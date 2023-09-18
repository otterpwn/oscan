package smb

import (
	. "fmt"
	"net"
	"os"
	"os/exec"
	"strings"

	SMB "github.com/hirochachacha/go-smb2"
)

// hardcoded default port for SMB
var smbPort int = 445

// list shares from SMB server using guest authentication
func ListShares(ip string, dumpFlag bool) error {
	server := Sprintf("%s:%d", ip, smbPort)
	connection, error := net.Dial("tcp", server)

	if error != nil {
		Println("Error while connecting to SMB on port 445")
		return error
	}
	defer connection.Close()

	dialer := &SMB.Dialer{
		Initiator: &SMB.NTLMInitiator{
			User:	        "otter",
			Password:	"",
		},
	}

	client, error := dialer.Dial(connection)
	if error != nil {
		Println("Error while connecting to SMB on port 445")
		return error
	}
	defer client.Logoff()

	shares, error := client.ListSharenames()
	if error != nil {
		Println("Error while listing SMB shares")
		return error
	}

	Println("Listing SMB Shares")	
	for _, share := range shares {
		Println("    ", share)
	}

	if dumpFlag {
		DumpShares(ip, shares, client)
	}

	return nil
}

// check if `smbclient` is installed to use it to dump the SMB shares
func CheckSMBClient() bool {
	command := exec.Command("smbclient", "--version")
	error := command.Run()

	if error != nil {
		return false
	}

	return true
}

// dumps recursively all the files from the readable SMB shares
// using guest authenticaton
func DumpShares(ip string, shares []string, client *SMB.Session) error {
	localPath := "./smb_dump"

	if !CheckSMBClient() {
		Println("`smbclient` is not installed or not in PATH")
	}

	error := os.MkdirAll(localPath, os.ModePerm)
	if error != nil {
		Println("Error creating smb_dump directory")
		return error
	}

	for _, share := range shares {
		shareUrl := Sprintf("//%s/%s", ip, share)

		command := exec.Command("smbclient", shareUrl, "-N", "-c" ,"recurse ON; prompt OFF; lcd ./smb_dump; mget *")

		command.Dir = localPath
		output, error := command.CombinedOutput()

		if error == nil {
			Println("Successfully dumped", share, "share")
		}

		if strings.Contains(string(output), "session setup failed") {
			Println("SMB session setup failed")
		}

	}
	
	return nil
}
