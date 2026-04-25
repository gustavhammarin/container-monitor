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
		Vulnerabilities []Vulnerability `json:"Vulnerabilities"` // nil om inga CVEs
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
	f, err := os.OpenFile("monitor.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	t, err := os.OpenFile( "trivy.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	return &Logger{file: f, trivyFile: t}, nil
}

func (l *Logger) StartFalco() {
	exe, err := os.Executable()
	if err != nil {
		log.Fatalf("executable path: %v", err)
	}

	falcoLogPath := filepath.Join(filepath.Dir(exe), "falco.log")
	os.WriteFile(falcoLogPath, []byte{}, 0644)

	f, err := os.OpenFile(falcoLogPath, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("falco log file: %v", err)
	}

	l.falcoFile = f

	cmd := exec.Command("falco",
		"json_output=true",
		"-o", "file_output.enabled=true",
		"-o", "file_output.filename="+falcoLogPath,
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
	fmt.Fprintln(l.file, string(line))
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

