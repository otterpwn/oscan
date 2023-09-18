package main

import (
	"context"
	. "fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	nmap "github.com/Ullaakut/nmap/v3"

	"oscan/ftp"
	"oscan/smb"
)

// prints cute banner ʕ •ᴥ•ʔ
func printBanner() {
	otterBanner := "ʕ •ᴥ•ʔ oscan by ottersec"
	Println()
	Println(otterBanner)
	Println()
}

// prints help menu
func printHelp() {
	Println("Usage: oscan <ip_address> <port_range>")
	Println()
	Println("Options:")
	Println("  ip_address: IP address or hostname of the target")
	Println("  port_range: Port range to scan (e.g., '80', '20-100', 'all')")
	Println("  service: Show service names for open ports")
	Println("  dump: Dump available contents from services like FTP and SMB")
	Println("  help: Show this help message")
}

// checks if the specified option is the command line arguments
func checkIfOption(targetFlag string, arguments []string) bool {
	for _, argument := range arguments {
		if argument == targetFlag {
			return true
		}
	}

	return false
}

// checks if the specified port is in the openPorts array
func checkOpenPort(openPorts map[uint16]string, targetPort uint16) bool {
	for port, _ := range openPorts {
		if port == targetPort {
			return true
		}
	}

	return false
}

// parse the port argument from command line
func parsePort(portArg string) (firstPort, lastPort int) {
	// regex pattern for firtsport-lastport format
	rangePattern := `^\d+-\d+$`
	rangeRE := regexp.MustCompile(rangePattern)

	if portArg == "all" {
		return 1, 65535
		// check if format firstport-lastport is matched
	} else if rangeRE.MatchString(portArg) {
		firstPortString := strings.Split(portArg, "-")[0]
		lastPortString := strings.Split(portArg, "-")[1]
		firstPort, error := strconv.ParseInt(firstPortString, 10, 64)

		if error != nil {
			panic(error)
		}

		// parse port to int
		lastPort, error := strconv.ParseInt(lastPortString, 10, 64)

		if error != nil {
			panic(error)
		}

		return int(firstPort), int(lastPort)
	}

	Println("Something went wrong in the port argument parsing function")
	return 0, 0
}

// convert firstPort-lastPort format to firstPort,firstPort+1,firstPort+2...lastPort
func portRangeToString(firstPort, lastPort int) (string, error) {
	var ports []string
	for port := firstPort; port <= lastPort; port++ {
		ports = append(ports, strconv.Itoa(port))
	}

	portString := strings.Join(ports, ",")

	return portString, nil
}

// set up and run scanner on specified ports
// put results in open and filtered ports maps
func scanPorts(ip string, firstPort, lastPort int, openPortsMap, filteredPortsMap map[uint16]string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	portRangeString, _ := portRangeToString(firstPort, lastPort)

	scanner, error := nmap.NewScanner(
		ctx,
		nmap.WithTargets(ip),
		nmap.WithPorts(portRangeString),
	)

	if error != nil {
		Println("Error runnin scanner")
		return
	}

	result, _, error := scanner.Run()
	if error != nil {
		Println("Error runnin scanner")
		return
	}

	host := result.Hosts[0]

	for _, port := range host.Ports {
		portState := port.State.String()
		serviceName := port.Service.String()

		if portState == "open" {
			openPortsMap[port.ID] = serviceName
		} else if portState == "filtered" {
			filteredPortsMap[port.ID] = serviceName
		}
	}
}

// handle the open ports output and the service flag
func outOpenPorts(openPorts map[uint16]string, serviceFlag bool) {
	for port, serviceName := range openPorts {
		if serviceFlag {
			Println("[∮] open", port, "-", serviceName)
		} else {
			Println("[∮] open", port)
		}
	}
	Println()
}

// handle the filtered ports output and the service flag
func outFilteredPorts(filteredPorts map[uint16]string, serviceFlag bool) {
	for port, serviceName := range filteredPorts {
		if serviceFlag {
			Println("[~] filtered", port, "-", serviceName)
		} else {
			Println("[~] filtered", port)
		}
	}
	Println()
}

// checks for common services that can be enumerated automatically
func checkEnumServices(openPorts map[uint16]string, ip string) {
	for port, service := range openPorts {
		switch {
		case port == 21 && service == "ftp":
			enumFTP(ip)
		case port == 445 && service == "microsoft-ds":
			enumSMB(ip)
		}
	}
}

// enumerate FTP with the `oscan/ftp` module
func enumFTP(ip string) {
	ftpClient := ftp.ConnectFTP(ip)

	// check if anonymous authentication is enabled
	if ftp.CheckAnonAuth(ftpClient) {
		Println("FTP Anonymous login is enabled on port 21")

		// if the `dump` flag is specified and anon auth is enabled
		// on the FTP server, dump its contents
		if checkIfOption("dump", os.Args) {
			ftp.DumpFTP(ip)
		}
	}
}

// enumerate SMB with the `oscan/smb` module
func enumSMB(ip string) {
	smb.ListShares(ip, checkIfOption("dump", os.Args))
}

func main() {
	// initialize maps to store open/filtered ports and the respective service
	openPortsMap := make(map[uint16]string)
	filteredPortsMap := make(map[uint16]string)

	printBanner()

	// check if the binary is being ran with the right number of options
	// if not, print the help menu
	if len(os.Args) < 3 || checkIfOption("help", os.Args) {
		printHelp()
		return
	}

	ipAddress := os.Args[1]
	portArg := os.Args[2]

	firstPort, lastPort := parsePort(portArg)

	// check if the `service` flag is provided
	// if it is, pass it to the output functions
	serviceBit := checkIfOption("service", os.Args)

	scanPorts(ipAddress, firstPort, lastPort, openPortsMap, filteredPortsMap)

	// output section for open and filtered ports
	outOpenPorts(openPortsMap, serviceBit)
	outFilteredPorts(filteredPortsMap, serviceBit)

	checkEnumServices(openPortsMap, ipAddress)
}
