package appenders

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/appveen/go-log/layout"
	"github.com/appveen/go-log/levels"
)

type rollingFileAppender struct {
	Appender
	layout         layout.Layout
	MaxFileSize    int64
	MaxBackupIndex int

	filename          string
	actualFileName    string
	currentDateInFile string
	logDirectory      string
	ReuseableFile     bool
	file              *os.File
	append            bool
	datewiseRotation  bool
	writeMutex        sync.Mutex

	bytesWritten int64

	backupFolder            string
	customFileNameGenerator func() string
	LogHookURL              string
	Client                  *http.Client
	CustomHeaders           map[string]string
}

// LogPayload - to shipped to url
type LogPayload struct {
	LogLevel  string    `json:"logLevel"`
	Timestamp time.Time `json:"timestamp"`
	Message   string    `json:"message"`
}

type LogDataEntry struct {
	Timestamp string `json:"timestamp"`
	LogLevel  string `json:"level"`
	Message   string `json:"msg"`
}

func RollingFile(filename string, directoryPath string, actualFileName string, append bool, dateRotation bool, reuseableFile bool, MaxBackupIndex int, customBackupFolder string, customFileNameGenerator func() string) *rollingFileAppender {
	a := &rollingFileAppender{
		layout:                  layout.Default(),
		MaxFileSize:             104857600,
		MaxBackupIndex:          MaxBackupIndex,
		append:                  append,
		datewiseRotation:        dateRotation,
		ReuseableFile:           reuseableFile,
		actualFileName:          actualFileName,
		logDirectory:            directoryPath,
		bytesWritten:            0,
		backupFolder:            customBackupFolder,
		customFileNameGenerator: customFileNameGenerator,
	}
	err := a.SetFilename(filename)
	if err != nil {
		fmt.Printf("Error opening file: %s\n", err)
		return nil
	}
	return a
}

func (a *rollingFileAppender) Close() {
	a.writeMutex.Lock()
	defer a.writeMutex.Unlock()
	if a.file != nil {
		a.file.Close()
		a.file = nil
	}
}

func (a *rollingFileAppender) Write(level levels.LogLevel, message string, args ...interface{}) {
	m := a.Layout().Format(level, message, args...)
	if !strings.HasSuffix(m, "\n") {
		m += "\n"
	}

	a.writeMutex.Lock()
	defer a.writeMutex.Unlock()

	// Ensure the file is open
	if a.file == nil {
		if err := a.openFile(); err != nil {
			fmt.Printf("Error opening file: %s\n", err)
			return
		}
	}

	if !a.datewiseRotation {
		if _, err := a.file.Write([]byte(m)); err != nil {
			fmt.Println("Error writing to file:", err)
			return
		}
		a.bytesWritten += int64(len(m))
		info, _ := a.file.Stat()
		if info.Size() >= a.MaxFileSize {
			a.bytesWritten = 0
			a.rotateFile()
		}
	} else {
		currentTime := time.Now()
		expectedDate := currentTime.Format("2006-01-02")
		if expectedDate != a.currentDateInFile {
			a.rotateFileDateWise(expectedDate)
			a.bytesWritten = 0
		}
		if _, err := a.file.Write([]byte(m)); err != nil {
			fmt.Println("Error writing to file:", err)
		}
		a.bytesWritten += int64(len(m))
	}
}

func (a *rollingFileAppender) Layout() layout.Layout {
	return a.layout
}

func (a *rollingFileAppender) SetLayout(layout layout.Layout) {
	a.layout = layout
}

func (a *rollingFileAppender) Filename() string {
	return a.filename
}

func (a *rollingFileAppender) SetFilename(filename string) error {
	a.writeMutex.Lock()
	defer a.writeMutex.Unlock()

	currentTime := time.Now()
	currentDate := currentTime.Format("2006-01-02")
	if a.filename != filename || a.file == nil {
		a.closeFile()
		a.filename = filename
		if a.datewiseRotation {
			if a.ReuseableFile {
				if _, err := os.Stat(filepath.Join(a.logDirectory, a.actualFileName[:len(a.actualFileName)-4]+"_"+currentDate+".log")); os.IsNotExist(err) {
					os.Remove(a.filename)
				}
			} else {
				a.deleteOutdatedFile()
			}
			a.currentDateInFile = currentDate
		}
		if err := a.openFile(); err != nil {
			return err
		}
	}
	return nil
}

func (a *rollingFileAppender) rotateFileDateWise(expectedDate string) {
	a.closeFile()
	if a.ReuseableFile {
		os.Remove(a.filename)
	} else {
		fileNameSplitter := strings.Split(a.actualFileName, a.currentDateInFile)
		a.actualFileName = fileNameSplitter[0] + expectedDate + fileNameSplitter[1]
		a.filename = filepath.Join(a.logDirectory, a.actualFileName)
		a.currentDateInFile = expectedDate
		a.deleteOutdatedFile()
	}
	if err := a.openFile(); err != nil {
		fmt.Println("Error opening file:", err)
	}
}

func (a *rollingFileAppender) deleteOutdatedFile() {
	listOfFiles := []string{}
	files, err := ioutil.ReadDir(a.logDirectory)
	if err == nil {
		for _, file := range files {
			re := regexp.MustCompile(`\d{4}-\d{2}-\d{2}`)
			if re.MatchString(file.Name()) {
				listOfFiles = append(listOfFiles, filepath.Join(a.logDirectory, file.Name()))
			}
		}
		sort.Strings(listOfFiles)
		if len(listOfFiles) > a.MaxBackupIndex {
			for i := 0; i < len(listOfFiles)-a.MaxBackupIndex; i++ {
				if err := os.Remove(listOfFiles[i]); err != nil {
					fmt.Println(err)
				}
			}
		}
	}
}

func (a *rollingFileAppender) rotateFile() {
	a.closeFile()
	filename := filepath.Base(a.filename)

	if a.backupFolder != "" {
		if a.customFileNameGenerator != nil {
			filename = a.customFileNameGenerator()
		}
		lastFile := filepath.Join(a.backupFolder, filename+"."+strconv.Itoa(a.MaxBackupIndex))
		if err := pushLogToURL(lastFile, a.LogHookURL, a.Client, a.CustomHeaders); err != nil {
			fmt.Println("Error pushing log to URL:", err)
		}
		if _, err := os.Stat(a.filename); err == nil {
			if err := os.Rename(a.filename, lastFile); err != nil {
				fmt.Println("Error renaming file:", err)
			}
		}
		for n := a.MaxBackupIndex; n > 0; n-- {
			f1 := filepath.Join(a.backupFolder, filename+"."+strconv.Itoa(n))
			f2 := filepath.Join(a.backupFolder, filename+"."+strconv.Itoa(n+1))
			for {
				if err := os.Rename(f1, f2); err != nil {
					if strings.Contains(fmt.Sprintf("%s", err), "The process cannot access the file because it is being used by another process") {
						time.Sleep(time.Second)
						continue // Retry renaming
					}
					fmt.Println("Error renaming file:", err)
					break // Exit the loop on error
				}
				break // Exit the retry loop on success
			}
			if err := pushLogToURL(f2, a.LogHookURL, a.Client, a.CustomHeaders); err != nil {
				fmt.Println("Error pushing log to URL:", err)
			}
		}
		for {
			if err := os.Rename(a.filename, filepath.Join(a.backupFolder, filename+".1")); err != nil {
				if strings.Contains(fmt.Sprintf("%s", err), "The process cannot access the file because it is being used by another process") {
					time.Sleep(time.Second)
					continue // Retry renaming
				}
				fmt.Println("Error renaming file:", err)
				break // Exit the loop on error
			}
			break // Exit the retry loop on success
		}
		if err := pushLogToURL(filepath.Join(a.backupFolder, filename+".1"), a.LogHookURL, a.Client, a.CustomHeaders); err != nil {
			fmt.Println("Error pushing log to URL:", err)
		}
	} else {
		lastFile := a.filename + "." + strconv.Itoa(a.MaxBackupIndex)
		if _, err := os.Stat(lastFile); err == nil {
			if err := os.Rename(a.filename, lastFile); err != nil {
				fmt.Println("Error renaming file:", err)
			}
		}
		for n := a.MaxBackupIndex; n > 0; n-- {
			f1 := a.filename + "." + strconv.Itoa(n)
			f2 := a.filename + "." + strconv.Itoa(n+1)
			for {
				if err := os.Rename(f1, f2); err != nil {
					if strings.Contains(fmt.Sprintf("%s", err), "The process cannot access the file because it is being used by another process") {
						time.Sleep(time.Second)
						continue // Retry renaming
					}
					fmt.Println("Error renaming file:", err)
					break // Exit the loop on error
				}
				break // Exit the retry loop on success
			}
		}
		for {
			if err := os.Rename(a.filename, a.filename+".1"); err != nil {
				if strings.Contains(fmt.Sprintf("%s", err), "The process cannot access the file because it is being used by another process") {
					time.Sleep(time.Second)
					continue // Retry renaming
				}
				fmt.Println("Error renaming file:", err)
				break // Exit the loop on error
			}
			break // Exit the retry loop on success
		}
	}

	if err := a.openFile(); err != nil {
		fmt.Println("Error opening file:", err)
	}
}

func (a *rollingFileAppender) closeFile() {
	if a.file != nil {
		if err := a.file.Close(); err != nil {
			fmt.Println("ERROR =", err)
		}
		a.file = nil
	}
}

func (a *rollingFileAppender) openFile() error {
	mode := os.O_WRONLY | os.O_APPEND | os.O_CREATE
	if !a.append {
		mode = os.O_WRONLY | os.O_CREATE
	}
	f, err := os.OpenFile(a.filename, mode, 0666)
	if err != nil {
		return err
	}
	a.file = f
	return nil
}

func pushLogToURL(file string, url string, client *http.Client, customHeaders map[string]string) error {
	if url == "" {
		return nil
	}
	f, err := os.OpenFile(file, os.O_RDONLY, 0666)
	if err != nil {
		return err
	}
	defer f.Close()

	var logPayloadEntries []LogPayload
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "Heartbeat") || strings.Contains(line, "EncryptedChunk") || strings.Contains(line, "Decoded") || strings.Contains(line, "CompressedChunk") || strings.Contains(line, "DataToWriteInFile") {
			continue
		}
		line = strings.Replace(line, "\\", "\\\\", -1)
		var logEntry LogDataEntry
		if err := json.Unmarshal([]byte(line), &logEntry); err != nil {
			fmt.Println(err)
			continue
		}
		parsedTimeStamp, err := time.Parse("2006-01-02 15:04:05.999999999 -0700 MST", logEntry.Timestamp)
		if err != nil {
			fmt.Println(err)
			continue
		}
		logPayloadEntries = append(logPayloadEntries, LogPayload{logEntry.LogLevel, parsedTimeStamp, logEntry.Message})
	}

	renamedFile := file + ".processed"
	if err := os.Rename(file, renamedFile); err != nil {
		return err
	}

	jsonData, err := json.Marshal(logPayloadEntries)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(jsonData))
	if err != nil {
		return err
	}
	customHeaders["filePath"] = renamedFile
	req.Header.Set("Content-Type", "application/json")
	for k, v := range customHeaders {
		req.Header.Set(k, v)
	}
	req.Close = true

	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return errors.New("Failed to upload logs = " + strconv.Itoa(res.StatusCode))
	}
	return nil
}

func readLinesFromFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
		break
	}
	return lines, scanner.Err()
}

func calculateMD5ChecksumForStream(body io.Reader) (string, error) {
	hash := md5.New()
	if _, err := io.Copy(hash, body); err != nil {
		return "", err
	}
	hashInBytes := hash.Sum(nil)[:16]
	return hex.EncodeToString(hashInBytes), nil
}
