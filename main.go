package main

import (
	"context"
	. "fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"

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
func parsePort(portArg string) string {
	// regex pattern for firtsport-lastport format
	rangePattern := `^\d+-\d+$`
	singlePatter := `^\d{1,5}$`

	rangeRE := regexp.MustCompile(rangePattern)
	singleRE := regexp.MustCompile(singlePatter)

	if portArg == "all" {
		return "-"

		// check if a single port is specified
	} else if singleRE.MatchString(portArg) {
		return portArg

		// check if format firstport-lastport is matched
	} else if rangeRE.MatchString(portArg) {
		// extract ports from pattern
		firstPortString := strings.Split(portArg, "-")[0]
		lastPortString := strings.Split(portArg, "-")[1]

		// parse ports to int
		firstPort, error := strconv.ParseInt(firstPortString, 10, 64)
		if error != nil {
			panic(error)
		}
		lastPort, error := strconv.ParseInt(lastPortString, 10, 64)
		if error != nil {
			panic(error)
		}

		portRangeString, _ := portRangeToString(int(firstPort), int(lastPort))
		return portRangeString
	}

	Println("Something went wrong in the port argument parsing function")
	return "-"
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
func scanPorts(ip string, portRangeString string, openPortsMap, filteredPortsMap map[uint16]string) {
	scanner, err := nmap.NewScanner(
		context.Background(),
		nmap.WithTargets(ip),
		nmap.WithPorts(portRangeString),
	)

	if err != nil {
		Println("Error runnin scanner")
		return
	}

	done := make(chan error)
	result, _, err := scanner.Async(done).Run()
	if err != nil {
		Println("Error running scanner")
		return
	}

	if err := <-done; err != nil {
		Println(err)
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

// since a asynchronous scan is used, the ports need to be sorted before
// being passed to the output function
func sortPorts(openPorts map[uint16]string) []uint16 {
	var sortedPorts []uint16

	for port := range openPorts {
		sortedPorts = append(sortedPorts, port)
	}

	sort.Slice(sortedPorts, func(i, j int) bool {
		return sortedPorts[i] < sortedPorts[j]
	})

	return sortedPorts
}

// handle the open ports output and the service flag
func outOpenPorts(openPorts map[uint16]string, serviceFlag bool) {
	sortedPorts := sortPorts(openPorts)

	for _, port := range sortedPorts {
		if serviceFlag {
			Println("[∮] open", port, "-", openPorts[port])
		} else {
			Println("[∮] open", port)
		}
	}
	Println()
}

// handle the filtered ports output and the service flag
func outFilteredPorts(filteredPorts map[uint16]string, serviceFlag bool) {
	sortedPorts := sortPorts(filteredPorts)

	for _, port := range sortedPorts {
		if serviceFlag {
			Println("[~] filtered", port, "-", filteredPorts[port])
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

// check if oscan is being ran as root
func checkRoot() bool {
	euid := syscall.Geteuid()

	if euid == 0 {
		return true
	}

	return false
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

// start a separate scan to enumerate host's OS
func enumOS(ip string) (string, error) {
	if !checkRoot() {
		Println("[!] OS scan requires root permission")
		return "", nil
	}

	scanner, err := nmap.NewScanner(
		context.Background(),
		nmap.WithTargets(ip),
		nmap.WithOSDetection(),
	)

	if err != nil {
		return "", err
	}

	done := make(chan error)
	result, _, err := scanner.Async(done).Run()
	if err != nil {
		return "", err
	}

	if err := <-done; err != nil {
		return "", err
	}

	host := result.Hosts[0]
	return host.OS.Matches[0].Name, nil
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

	portRangeString := parsePort(portArg)

	// check if the `service` flag is provided
	// if it is, pass it to the output functions
	serviceBit := checkIfOption("service", os.Args)

	// check if the `service` flag is provided
	// if it is, pass it to the output functions
	osBit := checkIfOption("os", os.Args)

	scanPorts(ipAddress, portRangeString, openPortsMap, filteredPortsMap)

	// output section for open and filtered ports
	outOpenPorts(openPortsMap, serviceBit)
	outFilteredPorts(filteredPortsMap, serviceBit)

	if osBit {
		os, error := enumOS(ipAddress)
		if error != nil {
			Println("Something went wrong during OS enumeration:", error)
		} else if os != "" {
			Println("Running OS is", os)
		}
	}

	checkEnumServices(openPortsMap, ipAddress)
}
