package logger

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
)

type Entry struct {
	Timestamp string `json:"timestamp"`
	Source    string `json:"source"`
	Domain    string `json:"domain"`
	QueryType string `json:"query_type,omitempty"`
	//Proxy specific
	Method     string `json:"method,omitempty"`
	Path       string `json:"path,omitempty"`
	StatusCode string `json:"status_code,omitempty"`
	Type       string `json:"type"`
}

type TrivyResult struct {
	ArtifactName string `json:"ArtifactName"`
	Metadata     struct {
		OS struct {
			Family string `json:"Family"`
			Name   string `json:"Name"`
		} `json:"OS"`
	} `json:"Metadata"`
	Results []struct {
		Target          string          `json:"Target"`
		Vulnerabilities []Vulnerability `json:"Vulnerabilities"`
		Packages        []Package       `json:"Packages"`
	} `json:"Results"`
}

type Vulnerability struct {
	VulnerabilityID string `json:"VulnerabilityID"`
	PkgName         string `json:"PkgName"`
	Severity        string `json:"Severity"`
	Title           string `json:"Title"`
}

type Package struct {
	Name     string   `json:"Name"`
	Version  string   `json:"Version"`
	Licenses []string `json:"Licenses"`
}

type Logger struct {
	mu        sync.Mutex
	file      *os.File
	falcoFile *os.File
	trivyFile *os.File
}

func New() (*Logger, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(exe)

	f, err := os.OpenFile(filepath.Join(dir, "monitor.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	t, err := os.OpenFile(filepath.Join(dir, "trivy.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	fa, err := os.OpenFile(filepath.Join(dir, "falco.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	return &Logger{file: f, trivyFile: t, falcoFile: fa}, nil
}

func (l *Logger) StartFalco() {
	cmd := exec.Command("falco",
		"-o", "json_output=true",
		"-o", "file_output.enabled=true",
		"-o", "file_output.filename="+l.falcoFile.Name(),
	)
	if err := cmd.Start(); err != nil {
		log.Fatalf("falco start: %v", err)
	}
}

func (l *Logger) Write(e Entry) {
	line, _ := json.Marshal(e)
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Println(string(line))
	fmt.Fprintln(l.file, string(line))
}

func (l *Logger) TrivyWrite(e TrivyResult) {
	line, _ := json.Marshal(e)
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Println(string(line))
	fmt.Fprintln(l.trivyFile, string(line))
}

func (l *Logger) Close() {
	l.file.Close()
}

func ReadNDJSON[T any](filename string) ([]T, error){
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var result []T
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 10*1024*1024), 10*1024*1024)
	for scanner.Scan(){
		var e T
		if err := json.Unmarshal(scanner.Bytes(), &e); err == nil {
			result = append(result, e)
		}
	}
	return result, scanner.Err()
}

func (l *Logger) GetTrivyLogs() ([]TrivyResult, error) {
	return ReadNDJSON[TrivyResult](l.trivyFile.Name())
}

func (l *Logger) GetNetworkLogs() ([]Entry, error) {
	return ReadNDJSON[Entry](l.file.Name())
}

func (l *Logger) GetFalcoLogs() ([]map[string]any, error) {
	return ReadNDJSON[map[string]any](l.falcoFile.Name())
}

