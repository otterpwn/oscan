package ftp

import (
	. "fmt"
	"os"
	"os/exec"

	FTP "github.com/jlaffaye/ftp"
)

// hardcoded default port for FTP
var ftpPort int = 21

// connect to FTP server and return client object
func ConnectFTP(ip string) *FTP.ServerConn {
	client, error := FTP.Dial(Sprintf("%s:%d", ip, ftpPort))

	if error != nil {
		Println("[!] Error connecting to FTP server on port", ftpPort)
		return nil
	}

	return client
}

// close the FTP connection
func CloseFTP(client *FTP.ServerConn) {
	client.Quit()
}

// checks if anonymous login is allowed on port 21
func CheckAnonAuth(client *FTP.ServerConn) bool {

	error := client.Login("anonymous", "anonymous")

	if error != nil {
		return false
	}

	client.Quit()
	return true
}

// check if wget is installed to use it to dump the FTP files
func CheckWget() bool {
	command := exec.Command("wget", "--version")
	error := command.Run()

	if error != nil {
		return false
	}

	return true
}

// dumps recursively all the files on the FTP server
// by default this uses anonymous:anonymous for anonymous login
func DumpFTP(ip string) error {
	localPath := "./ftp_dump"
	ftpServer := Sprintf("ftp://%s/", ip)

	error := os.MkdirAll(localPath, os.ModePerm)
	if error != nil {
		Println("[!] Error creating ftp_dump directory")
		return error
	}

	command := exec.Command("wget", "-r", "--no-parent", "--no-clobber", "--ftp-user=anonymous", "--ftp-password=anonymous", ftpServer)
	command.Dir = localPath

	_, error = command.CombinedOutput()
	if error != nil {
		Println("[!] There was an error while dumping the FTP files")
		return error
	}

	Println("[*] Successfully dumped files from FTP server")

	return nil
}
