package ntp

import (
	. "fmt"
	"os"
	"os/exec"
)

func SyncNTP(ip string) error {
	// commands to sync NTP service on the box
	timedatactlCommand := exec.Command("sudo", "timedatectl", "set-ntp", "0")
	ntpdateCommand := exec.Command("sudo", "ntpdate", "-u", ip)

	// combine the two commands
	timedatactlCommand.Stdin, _ = ntpdateCommand.StdoutPipe()
	ntpdateCommand.Stderr = timedatactlCommand.Stderr
	ntpdateCommand.Stdin, _ = os.Open("/dev/null")

	// start both commands
	if err := timedatactlCommand.Start(); err != nil {
		Println("[!] Error while syncing NTP")
		return err
	}
	if err := ntpdateCommand.Start(); err != nil {
		Println("[!] Error while syncing NTP")
		return err
	}

	// wait for both commands to finish
	if err := timedatactlCommand.Wait(); err != nil {
		Println("[!] Failed to run `timedatectl`")
		return err
	}
	if err := ntpdateCommand.Wait(); err != nil {
		Println("[!] Failed to run `ntpupdate`")
		return err
	}

	Println("[*] Synced time with NTP server on", ip)

	return nil
}
