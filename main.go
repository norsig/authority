package main

import (
	"fmt"

	"github.com/ovrclk/authority/command"
)

const (
	Version           = "0.2.3"
	VersionPrerelease = "dev"

	DEFAULT_VAULT_SERVER = "http://localhost:8200"
)

var (
	GitCommit string
)

func main() {
	version := fmt.Sprintf("authority v%s%s-%s", Version, VersionPrerelease, GitCommit)
	cli := command.New(version)
	err := cli.Execute()
	if err != nil {
		fmt.Println(err)
	}
}
