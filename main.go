package main

import (
	"fmt"

	"github.com/ovrclk/authority/command"
)

func main() {
	cli := command.New()
	err := cli.Execute()
	if err != nil {
		fmt.Println(err)
	}
}
