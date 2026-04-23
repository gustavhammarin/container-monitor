package falco

import (
	"log"
	"os"
	"os/exec"
	"path/filepath"
)

func Run(){
	exe, err := os.Executable()
		if err != nil {
			log.Fatalf("executable path: %v", err)
		}

		falcoLogPath := filepath.Join(filepath.Dir(exe), "falco.log")
		os.WriteFile(falcoLogPath, []byte{}, 0644)

		cmd := exec.Command("falco",
			"json_output=true",
			"-o", "file_output.enabled=true",
			"-o", "file_output.filename="+falcoLogPath,
		)
		if err := cmd.Start(); err != nil {
			log.Fatalf("falco start: %v", err)
		}
}