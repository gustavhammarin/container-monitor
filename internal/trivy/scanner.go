package trivy

import (
	"container-monitor/internal/logger"
	"encoding/json"
	"log"
	"os/exec"
)

type Scanner struct {
	Logger *logger.Logger
}

func (s *Scanner) Scan(image string) {
	log.Printf("Trivy scanning: %v", image)

	cmd := exec.Command("trivy", "image", "--format", "json", "--quiet", image)

	out, err := cmd.Output()
	if err != nil {
		log.Printf("trivy error: %v", err)
		return
	}

	var result logger.TrivyResult
	
	if err := json.Unmarshal(out, &result); err != nil {
		log.Printf("trivy parse error: %v", err)
		return
	}

	s.Logger.TrivyWrite(result)
}
