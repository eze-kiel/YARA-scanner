package main

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/logrusorgru/aurora"
)

func (s *smtpServer) Address() string {
	return s.host + ":" + s.port
}

// ReportFormating returns a strings formatted to fit in the mail.
func ReportFormating(rules, files []string) string {
	var finalString string
	for i := range rules {
		finalString = finalString + rules[i] + ":" + files[i] + "\n\n"
	}

	return finalString
}

// GetRulesList check for files with the YARA extension in a given directory,
// and returns the list of the corresponding files
func GetRulesList(rulesPath string) ([]string, error) {
	out, err := exec.Command("ls", rulesPath).Output()
	if err != nil {
		return nil, err
	}

	filesList := strings.Split(string(out), "\n")

	// remove last item of list which is a blank space
	filesList = filesList[:len(filesList)-1]

	var rulesList []string
	for _, filename := range filesList {
		if strings.Contains(filename, ".yar") || strings.Contains(filename, ".yara") {
			fmt.Printf("%s rules file found: %s\n", aurora.Cyan("-"), filename)
			rulesList = append(rulesList, filename)
		}
	}

	return rulesList, nil
}
