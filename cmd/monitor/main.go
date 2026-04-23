package main

import (
	internaldns "container-monitor/internal/dns"
	"container-monitor/internal/falco"
	"container-monitor/internal/logger"
	"container-monitor/internal/proxy"
	"container-monitor/internal/trivy"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
)

func setDNS(nameserver string) {
	err := os.WriteFile("/etc/resolv.conf", []byte("nameserver "+nameserver+"\n"), 0644)
	if err != nil {
		log.Fatalf("setDNS: %v", err)
	}
}
func sanitizeName(image string) string {
	// alpine:latest → alpine-latest
	return strings.NewReplacer(":", "-", "/", "-").Replace(image)
}
func cleanup(dir string){
	logs := []string{
		filepath.Join(dir, "monitor.log"),
		filepath.Join(dir, "falco.log"),
		filepath.Join(dir, "trivy.log"),
	}
	for _, log := range logs{
		os.Remove(log)
	}
}

func main() {

	images := os.Args[1:]

	exe, _ := os.Executable()
	dir := filepath.Dir(exe)
	cleanup(dir)

	if len(images) == 0 {
		log.Fatal("Usage ./monitor <image> <image>")
	}
	log.Println("Setting real DNS")
	setDNS("8.8.8.8")
	falco.Run()

	for _, image := range images {
		log.Printf("Pulls image: %s", image)
		cmd := exec.Command("docker", "pull", image)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			log.Fatalf("docker pull %s: %v", image, err)
		}
	}

	log.Println("Pulling trivyDB...")
	cmd := exec.Command("trivy", "image", "--download-db-only")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("Failed to download DB... error: %v", err)
	}

	log.Println("Setting fake DNS")
	setDNS("127.0.0.1")

	l, err := logger.New("monitor.log")
	if err != nil {
		log.Fatalf("logger: %v", err)
	}
	defer l.Close()

	trivylog, err := logger.New("trivy.log")
	if err != nil {
		log.Fatalf("trivylogger: %v", err)
	}
	defer trivylog.Close()

	trivyscanner := trivy.Scanner{Logger: trivylog}

	for _, image := range images {
		log.Printf("Scanning %v with trivy", image)
		go trivyscanner.Scan(image)
	}

	for _, image := range images {
		name := sanitizeName(image)
		log.Printf("Startar container: %s", image)
		exec.Command("docker", "run", "-d",
			"--name", name,
			"--network", "sandlada",
			"--dns", "10.10.0.1",
			image,
		).Run()
	}

	go internaldns.Run(l)
	go proxy.Run(l)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Cleaning up...")
	for _, image := range images {
		exec.Command("docker", "stop", sanitizeName(image)).Run()
		exec.Command("docker", "rm", sanitizeName(image)).Run()
	}
	setDNS("8.8.8.8")
	log.Println("Finished.")

	log.Println("Turning off...")
}
