## Required tools
1. `wget`
2. `smbclient`

## Go Environment setup
```
cd oscan
go env -w GO111MODULE=on
go mod init oscan
go get github.com/jlaffaye/ftp
go get github.com/hirochachacha/go-smb2
go get github.com/Ullaakut/nmap/v3
```
