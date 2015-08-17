package main

import (
	"fmt"
	"log"
	"os"

	"github.com/docopt/docopt-go"

	"github.com/ovrclk/authority/authority"
)

const (
	Version           = "0.2.3"
	VersionPrerelease = "dev"

	DEFAULT_VAULT_SERVER = "https://localhost:8200"
)

var (
	GitCommit string
)

func main() {
	args, _ := docopt.Parse(helpText, nil, true, fmt.Sprintf("authority v%s%s-%s", Version, VersionPrerelease, GitCommit), false)

	env_server := os.Getenv("AUTHORITY_VAULT_SERVER")
	env_token := os.Getenv("AUTHORITY_VAULT_TOKEN")

	token := ""
	config := ""
	server := DEFAULT_VAULT_SERVER
	name := ""

	var client *authority.Client

	if args["--server"] != nil {
		server = args["--server"].(string)
	} else if env_server != "" {
		server = env_server
	}

	if args["--token"] != nil {
		token = args["--token"].(string)
	} else if env_token != "" {
		token = env_token
	}

	if args["<configfile>"] != nil {
		config = args["<configfile>"].(string)
	}

	if args["<name>"] != nil {
		name = args["<name>"].(string)
	}

	ca := args["ca"].(bool)
	cert := args["cert"].(bool)
	key := args["key"].(bool)
	crl := args["crl"].(bool)

	// skip failing config load if we're specifically running the config command
	ignoreConfig := args["config"].(bool)

	client = &authority.Client{Server: server, Token: token}

	if err := client.Init(ignoreConfig); err != nil {
		log.Fatal(err)
	} else {
		var err error
		if args["config"].(bool) {
			err = client.Config(config)
		} else if args["generate"].(bool) {
			err = client.Generate(name)
		} else if args["get"].(bool) {
			err = client.Get(name, ca, cert, key)
		} else if args["revoke"].(bool) {
			err = client.Revoke(name)
		} else if args["ca"].(bool) {
			err = client.CA(cert, key, crl)
		}
		if err != nil {
			log.Println("error:", err)
		}
	}

}

const helpText = `
Usage: authority config [<configfile>] [--server=SERVER --token=TOKEN]
       authority (generate|revoke) <name> [--server=SERVER --token=TOKEN]
       authority get [ca|cert|key]  <name> [--server=SERVER --token=TOKEN]
       authority ca [cert|key|crl] [--server=SERVER --token=TOKEN]

Authority is a server providing x509 certificate management

Commands:

    config     Display or set authority configuration
    generate   Generate a signed client certificate and access token
    get        Get a signed client certificate
    revoke     Revoke an existing signed client certificate
    ca         Get certificate authority files

Options:

  --server=SERVER   Address of authority server (AUTHORITY_VAULT_SERVER)
                    [default: https://localhost:8200]
  --token=TOKEN     Vault access token (AUTHORITY_VAULT_TOKEN)
  --help            Display this message
  --version         Show version and exit

`
