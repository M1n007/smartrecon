package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
)

func readFileToSlice(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return lines, nil
}

func checkIfToolsExist(toolsName string) bool {
	var commandName string
	commandName = toolsName

	cmd := exec.Command("which", commandName)
	_, err := cmd.Output()

	if err != nil {
		return false
	} else {
		return true
	}
}

func runReconTools(command string, wg *sync.WaitGroup) {
	if wg != nil {
		defer wg.Done()
	}

	cmdStr := command
	cmdParts := strings.Split(cmdStr, " ")

	cmd := exec.Command(cmdParts[0], cmdParts[1:]...)

	pipeReader, pipeWriter := io.Pipe()
	cmd.Stdout = pipeWriter

	err := cmd.Start()
	if err != nil {
		fmt.Printf("Error starting command %s: %v\n", cmdParts[0], err)
		return
	}

	go func() {
		scanner := bufio.NewScanner(pipeReader)
		for scanner.Scan() {
			output := scanner.Text()

			if cmdParts[0] == "nuclei" {
				if strings.Contains(string(output), "medium") ||
					strings.Contains(string(output), "critical") ||
					strings.Contains(string(output), "high") {
					fmt.Println(output)
				}
			}
		}
	}()

	err = cmd.Wait()
	if err != nil {
		fmt.Printf("Error running command %s: %v\n", cmdParts[0], err)
	}

	pipeWriter.Close()

}

func main() {

	var filename string
	var subdomainFileName string

	requiredTools := []string{"subfinder", "nuclei"}

	// checking tools
	fmt.Println("Checking tools...\n")
	for _, tools := range requiredTools {
		toolsExist := checkIfToolsExist(tools)
		if !toolsExist {
			fmt.Printf("%s tidak terpasang. \n", tools)
		}
	}

	fmt.Println("Semua tools terinstall, lanjut cari subdomain...\n")

	filename = "domain.txt"

	domainList, err := readFileToSlice(filename)
	if err != nil {
		fmt.Println("Error : ", err)
		return
	}

	// runing subfinder tools
	var wg sync.WaitGroup

	for _, domain := range domainList {
		wg.Add(1)

		fmt.Printf("Scanning subdomain %s....\n", domain)
		commandString := fmt.Sprintf("subfinder -d %s -o activesubdomain.txt", domain)
		go runReconTools(commandString, &wg)
	}

	wg.Wait()

	subdomainFileName = "activesubdomain.txt"

	subdomainList, _ := readFileToSlice(subdomainFileName)
	for _, domain := range domainList {
		var filteredSubDomain []string
		for _, subdomain := range subdomainList {
			if strings.Contains(string(subdomain), domain) {
				filteredSubDomain = append(filteredSubDomain, subdomain)
			}
		}

		subdomainTotalLength := len(filteredSubDomain)
		fmt.Printf("Total %v subdomain ditemukan pada domain %s\n", subdomainTotalLength, domain)
	}

	fmt.Println("\n")
	fmt.Println("Scanning subdomain dengan nuclei.... \n")

	commandString := "nuclei -l activesubdomain.txt --severity medium,high,critical"
	runReconTools(commandString, nil)

}
