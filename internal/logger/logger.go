package logger

import (
	"encoding/json"
	"fmt"
	"os"
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
	Name    string   `json:"Name"`
	Version string   `json:"Version"`
	Licenses []string `json:"Licenses"`
}

type Logger struct {
	mu   sync.Mutex
	file *os.File
}

func New(path string) (*Logger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	return &Logger{file: f}, nil
}

func (l *Logger) Write(e Entry) {
	line, _ := json.Marshal(e)
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Println(string(line))
	fmt.Fprintln(l.file, string(line))
}

func (l *Logger) TrivyWrite(e TrivyResult){
	line, _ := json.Marshal(e)
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Println(string(line))
	fmt.Fprintln(l.file, string(line))
}

func (l *Logger) Close() {
	l.file.Close()
}
