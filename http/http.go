package http

import (
	. "fmt"
	"os/exec"
	"strings"
)

func GetHTTPDom(ip string) error {
	// execute wget command on the ip to see if the request
	// gets redirected
	command := exec.Command("wget", "--max-redirect=0", ip)
	output, _ := command.CombinedOutput()

	outputStr := string(output)

	// exctract domain name from the output
	if strings.Contains(outputStr, "Location:") {
		lines := strings.Split(outputStr, "\n")

		for _, line := range lines {
			if strings.HasPrefix(line, "Location:") {
				parts := strings.Fields(line)
				if len(parts) > 1 {
					domainURL := parts[1]

					domainParts := strings.Split(domainURL, "/")
					if len(domainParts) > 2 {
						domain := domainParts[2]
						Println("[*] Domain name found:", domain)
						return nil
					}
				}
			}
		}
	}

	return nil
}
