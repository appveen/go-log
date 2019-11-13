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

//LogPayload - to shipped to url
type LogPayload struct {
	Content        string    `json:"content"`
	Checksum       string    `json:"checksum"`
	Timestamp      time.Time `json:"startTimestamp"`
	StartTimestamp time.Time `json:"endTimestamp"`
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
		_, filename := filepath.Split(a.filename)
		if a.customFileNameGenerator != nil {
			filename = a.customFileNameGenerator()
		}
		lastFile := filepath.Join(a.backupFolder, filename+"."+strconv.Itoa(a.MaxBackupIndex))
		pushLogToURL(lastFile, a.LogHookURL, a.Client, a.CustomHeaders)
		if _, err := os.Stat(lastFile); err == nil {
			os.Remove(lastFile)
		}
		for n := a.MaxBackupIndex; n > 0; n-- {
			f1 := filepath.Join(a.backupFolder, filename+"."+strconv.Itoa(n))
			f2 := filepath.Join(a.backupFolder, filename+"."+strconv.Itoa(n+1))
			err := os.Rename(f1, f2)
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
		for {
			if strings.Contains(fmt.Sprintf("%s", err), "The process cannot access the file because it is being used by another process") {
				err = os.Rename(a.filename, filepath.Join(a.backupFolder, filename+".1"))
				continue
			}
			break
		}
		pushLogToURL(filepath.Join(a.backupFolder, filename+".1"), a.LogHookURL, a.Client, a.CustomHeaders)
	} else {
		lastFile := a.filename + "." + strconv.Itoa(a.MaxBackupIndex)
		pushLogToURL(lastFile, a.LogHookURL, a.Client, a.CustomHeaders)
		if _, err := os.Stat(lastFile); err == nil {
			os.Remove(lastFile)
		}
		for n := a.MaxBackupIndex; n > 0; n-- {
			f1 := a.filename + "." + strconv.Itoa(n)
			f2 := a.filename + "." + strconv.Itoa(n+1)
			err := os.Rename(f1, f2)
			for {
				if strings.Contains(fmt.Sprintf("%s", err), "The process cannot access the file because it is being used by another process") {
					err = os.Rename(f1, f2)
					continue
				}
				break
			}
			pushLogToURL(f2, a.LogHookURL, a.Client, a.CustomHeaders)
			os.Remove(f2)
		}
		err := os.Rename(a.filename, a.filename+".1")
		for {
			if strings.Contains(fmt.Sprintf("%s", err), "The process cannot access the file because it is being used by another process") {
				err = os.Rename(a.filename, a.filename+".1")
				continue
			}
			break
		}
		pushLogToURL(a.filename+".1", a.LogHookURL, a.Client, a.CustomHeaders)
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
		return err
	}
	data, err := ioutil.ReadAll(f)
	if err != nil {
		return err
	}
	f.Close()
	os.Remove(file)
	t := time.Now()
	payload := LogPayload{
		Content:        string(data),
		Checksum:       "",
		Timestamp:      t,
		StartTimestamp: t,
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", url, bytes.NewReader(jsonData))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if customHeaders != nil {
		for k, v := range customHeaders {
			req.Header.Set(k, v)
		}
	}
	req.Close = true
	res, err := client.Do(req)
	if err != nil {
		return errors.New(fmt.Sprintf("%s", err))
	}
	if res.StatusCode != 200 {
		return errors.New("request failed = " + string(res.StatusCode))
	}
	if res.Body != nil {
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
