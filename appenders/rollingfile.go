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

var CustomRHeaders map[string]string

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
	if !a.datewiseRotation {
		a.file.Write([]byte(m))
		info, _ := a.file.Stat()
		a.bytesWritten += int64(len(m))
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
		a.file.Write([]byte(m))
		a.bytesWritten += int64(len(m))
	}
	a.writeMutex.Unlock()
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
	currentTime := time.Now()
	currentDate := currentTime.Format("2006-01-02")
	if a.filename != filename || a.file == nil {
		a.closeFile()
		a.filename = filename
		if a.datewiseRotation {
			if a.ReuseableFile {
				if _, err := os.Stat(a.logDirectory + string(os.PathSeparator) + a.actualFileName[0:len(a.actualFileName)-4] + "_" + currentDate + ".log"); os.IsNotExist(err) {
					os.Remove(a.filename)
				}
			} else {
				a.deleteOutdatedFile()
			}
			a.currentDateInFile = currentDate
		}
		err := a.openFile()
		return err
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
		a.filename = a.logDirectory + string(os.PathSeparator) + a.actualFileName
		a.currentDateInFile = expectedDate
		a.deleteOutdatedFile()
	}
	a.openFile()
}

func (a *rollingFileAppender) deleteOutdatedFile() {
	listOfFiles := []string{}
	files, err := ioutil.ReadDir(a.logDirectory)
	if err == nil {
		for _, file := range files {
			re := regexp.MustCompile(`\d{4}-\d{2}-\d{2}`)
			if re.MatchString(file.Name()) {
				listOfFiles = append(listOfFiles, a.logDirectory+string(os.PathSeparator)+file.Name())
			}

		}
		sort.Strings(listOfFiles)
		if len(listOfFiles) > a.MaxBackupIndex {
			for i := 0; i < len(listOfFiles)-a.MaxBackupIndex; i++ {
				err := os.Remove(listOfFiles[i])
				if err != nil {
					fmt.Println(err)
				}

			}
		}
	}
}

func (a *rollingFileAppender) rotateFile() {
	a.closeFile()
	if a.backupFolder != "" {
		fmt.Println("Backup folder present")
		_, filename := filepath.Split(a.filename)
		if a.customFileNameGenerator != nil {
			filename = a.customFileNameGenerator()
		}
		lastFile := filepath.Join(a.backupFolder, filename+"."+strconv.Itoa(a.MaxBackupIndex))
		pushLogToURL(lastFile, a.LogHookURL, a.Client, a.CustomHeaders)
		if _, err := os.Stat(a.filename); err == nil {
			os.Rename(a.filename, lastFile)
		} else {
			fmt.Errorf("Error 1.1 - ", err.Error())
		}
		for n := a.MaxBackupIndex; n > 0; n-- {
			f1 := filepath.Join(a.backupFolder, filename+"."+strconv.Itoa(n))
			f2 := filepath.Join(a.backupFolder, filename+"."+strconv.Itoa(n+1))
			err := os.Rename(f1, f2)
			if err != nil {
				fmt.Errorf("Error 1.2 - ", err.Error())
			}
			for {
				if strings.Contains(fmt.Sprintf("%s", err), "The process cannot access the file because it is being used by another process") {
					err = os.Rename(f1, f2)
					continue
				}
				break
			}
			pushLogToURL(f2, a.LogHookURL, a.Client, a.CustomHeaders)
		}
		err := os.Rename(a.filename, filepath.Join(a.backupFolder, filename+".1"))
		if err != nil {
			fmt.Errorf("Error 1.3 - ", err.Error())
		}
		for {
			if strings.Contains(fmt.Sprintf("%s", err), "The process cannot access the file because it is being used by another process") {
				err = os.Rename(a.filename, filepath.Join(a.backupFolder, filename+".1"))
				continue
			}
			break
		}
		pushLogToURL(filepath.Join(a.backupFolder, filename+".1"), a.LogHookURL, a.Client, a.CustomHeaders)
	} else {
		fmt.Println("Backup folder not present")
		lastFile := a.filename + "." + strconv.Itoa(a.MaxBackupIndex)
		//pushLogToURL(lastFile, a.LogHookURL, a.Client, a.CustomHeaders)
		if _, err := os.Stat(lastFile); err == nil {
			os.Rename(a.filename, lastFile)
		} else {
			fmt.Errorf("Error 2.1 - ", err.Error())
		}
		for n := a.MaxBackupIndex; n > 0; n-- {
			f1 := a.filename + "." + strconv.Itoa(n)
			f2 := a.filename + "." + strconv.Itoa(n+1)
			err := os.Rename(f1, f2)
			if err != nil {
				fmt.Errorf("Error 2.2 - ", err.Error())
			}
			for {
				if strings.Contains(fmt.Sprintf("%s", err), "The process cannot access the file because it is being used by another process") {
					err = os.Rename(f1, f2)
					continue
				}
				break
			}
			//	pushLogToURL(f2, a.LogHookURL, a.Client, a.CustomHeaders)
		}
		err := os.Rename(a.filename, a.filename+".1")
		if err != nil {
			fmt.Errorf("Error 2.3 - ", err.Error())
		}
		for {
			if strings.Contains(fmt.Sprintf("%s", err), "The process cannot access the file because it is being used by another process") {
				err = os.Rename(a.filename, a.filename+".1")
				continue
			}
			break
		}
		//pushLogToURL(a.filename+".1", a.LogHookURL, a.Client, a.CustomHeaders)
	}
	a.openFile()
}
func (a *rollingFileAppender) closeFile() {
	if a.file != nil {
		err := a.file.Close()
		if err != nil {
			fmt.Println("ERROR = ", err)
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
	a.file = f
	return err
}

func pushLogToURL(file string, url string, client *http.Client, customHeaders map[string]string) error {
	if url == "" {
		return nil
	}
	f, err := os.OpenFile(file, os.O_RDONLY, 0666)
	if err != nil {
		fmt.Errorf("Error 3.1 - ", err.Error())
		return err
	}
	defer f.Close()

	logPayloadEntries := []LogPayload{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "Heartbeat") || strings.Contains(line, "EncryptedChunk") || strings.Contains(line, "Decoded") || strings.Contains(line, "CompressedChunk") || strings.Contains(line, "DataToWriteInFile") || strings.Contains(line, "Sentinel") {
			// fmt.Println("contains")
			continue
		}
		line = strings.Replace(line, "\\", "\\\\", -1)
		// fmt.Println(line)
		logEntry := LogDataEntry{}
		err = json.Unmarshal([]byte(line), &logEntry)
		if err != nil {
			fmt.Println(err)
		}
		// fmt.Println(logEntry)
		parsedTimeStamp, err := time.Parse("2006-01-02 15:04:05.999999999 -0700 MST", logEntry.Timestamp)
		if err != nil {
			fmt.Println(err)
			break
		}
		logPayloadEntries = append(logPayloadEntries, LogPayload{logEntry.LogLevel, parsedTimeStamp, logEntry.Message})
	}

	fCError := f.Close()
	if fCError != nil {
		fmt.Errorf("Error 3.2 - ", err.Error())
		return fCError
	}
	renamedFile := file + ".processed"
	err = os.Rename(file, renamedFile)
	if err != nil {
		fmt.Errorf("Error 3.3 - ", err.Error())
		return err
	}
	jsonData, err := json.Marshal(logPayloadEntries)
	if err != nil {
		fmt.Errorf("Error 3.4 - ", err.Error())
		return err
	}
	fmt.Println("Pushing Logs to URL - ", url)
	fmt.Println("Data to be pushed - ", jsonData)
	req, err := http.NewRequest("POST", url, bytes.NewReader(jsonData))
	if err != nil {
		fmt.Errorf("Error 3.5 - ", err.Error())
		return err
	}
	customHeaders["filePath"] = renamedFile
	req.Header.Set("Content-Type", "application/json")
	for k, v := range customHeaders {
		req.Header.Set(k, v)
	}
	if CustomRHeaders != nil {
		for k, v := range CustomRHeaders {
			req.Header.Set(k, v)
		}
	}
	fmt.Println("Headers - ", req.Header)
	req.Close = true
	res, err := client.Do(req)
	if err != nil {
		fmt.Errorf("Error 3.6 - ", err.Error())
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return errors.New("Failed to upload logs = " + string(res.StatusCode))
	}
	if res.Body != nil {
		fmt.Println("Response data - ", res.Body)
		fmt.Println("Response statusCode -", res.StatusCode)
		res.Body.Close()
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
	var returnMD5String string
	hash := md5.New()
	if _, err := io.Copy(hash, body); err != nil {
		return "", err
	}
	hashInBytes := hash.Sum(nil)[:16]
	returnMD5String = hex.EncodeToString(hashInBytes)
	return returnMD5String, nil
}

func UpdateRollingCustomHeaders(headers map[string]string) {
	fmt.Println("NewR Custom Headers - ", headers)
	CustomRHeaders = headers
}
