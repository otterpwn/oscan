package main

import (
	"context"
	. "fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/semaphore"
)

var openPortsArray []int

// define `oscanner` type
// `ip` is the ip address to scan
// `threshold` is the threshold that will limit the number of go routines running at a given time
type oscanner struct {
	ip        string
	threshold *semaphore.Weighted
}

// function to print cute banner ʕ •ᴥ•ʔ
func printBanner() {
	otterBanner := "ʕ •ᴥ•ʔ oscan by ottersec"
	Println(otterBanner)
	Println()
}

// function to retrieve the maximum number of file descriptors that
// a process can handle using the linux command `ulimit`
func Ulimit() int64 {
	var hardcodedThreshold int64 = 1000

	// execute `ulimit` command
	output, error := exec.Command("sh", "-c", "ulimit", "-n").Output()

	if error != nil {
		panic(error)
	}

	// convert output of the command to variable
	s := strings.TrimSpace(string(output))
	if s == "unlimited" {
		return hardcodedThreshold
	}

	number, error := strconv.ParseInt(s, 10, 64)

	if error != nil {
		panic(error)
	}

	return number
}

// function that scans a port on a given host with a specified timeout
func scanPort(ip string, port int, timeout time.Duration) {
	target := Sprintf("%s:%d", ip, port)

	// connect to the given host and port
	connection, error := net.DialTimeout("tcp", target, timeout)

	if error != nil {
		// handle file descriptor error
		// wait for other routines to finish and scan the host and port again
		if strings.Contains(error.Error(), "Too many files open") {
			time.Sleep(timeout)
			scanPort(ip, port, timeout)
		}

		return
	}

	connection.Close()
	openPortsArray = append(openPortsArray, port)
}

func (scanner *oscanner) Start(firstPort, lastPort int, timeout time.Duration) {
	waitgroup := sync.WaitGroup{}
	defer waitgroup.Wait()

	for port := firstPort; port <= lastPort; port++ {
		waitgroup.Add(1)
		scanner.threshold.Acquire(context.TODO(), 1)

		go func(port int) {
			defer scanner.threshold.Release(1)
			defer waitgroup.Done()

			scanPort(scanner.ip, port, timeout)
		}(port)
	}
}

func checkIfPresent(targetFlag string, arguments []string) bool {
	for _, argument := range arguments {
		if argument == targetFlag {
			return true
		}
	}

	return false
}

func parsePort(portArg string) (firstPort, lastPort int) {
	rangePattern := `^\d+-\d+$`
	rangeRE := regexp.MustCompile(rangePattern)

	if portArg == "all" {
		return 1, 65535
	} else if rangeRE.MatchString(portArg) {
		Println("valid pattern")
		firstPortString := strings.Split(portArg, "-")[0]
		lastPortString := strings.Split(portArg, "-")[1]
		firstPort, error := strconv.ParseInt(firstPortString, 10, 64)

		if error != nil {
			panic(error)
		}

		lastPort, error := strconv.ParseInt(lastPortString, 10, 64)

		if error != nil {
			panic(error)
		}

		return int(firstPort), int(lastPort)
	}

	Println("Something went wrong in the port argument parsing function")
	return 0, 0
}

func getServices(port int) {
	Printf("getting service on port %d\n", port)
}

func outOpenPorts(openPorts []int, serviceFlag bool) {
	sort.Ints(openPorts)

	for _, port := range openPorts {
		Println(port)
		if serviceFlag {
			getServices(port)
		}
	}
}

func main() {
	printBanner()

	ipAddress := os.Args[1]
	portArg := os.Args[2]

	serviceBit := checkIfPresent("service", os.Args)

	firstPort, lastPort := parsePort(portArg)

	ps := &oscanner{
		ip:        ipAddress,
		threshold: semaphore.NewWeighted(Ulimit()),
	}

	ps.Start(firstPort, lastPort, 500*time.Millisecond)
	outOpenPorts(openPortsArray, serviceBit)
}
