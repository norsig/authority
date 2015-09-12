package command

import (
	"fmt"
	"os"

	"github.com/ovrclk/cli"
	"github.com/spf13/cobra"

	"github.com/ovrclk/authority/client"
	"github.com/ovrclk/authority/version"
)

const (
	DEFAULT_VAULT_SERVER = "http://localhost:8200"
)

type CommandFactory struct {
	Cli      *cli.CLI
	Client   *client.Client
	Server   string
	Token    string
	CertName string
	RootName string
}

func New() *cli.CLI {
	root := &cobra.Command{
		Short: "Authority is a server providing x509 certificate management",
		Use:   "authority COMMAND [<args>..] [options]",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}

	cf := &CommandFactory{
		Cli: cli.New(root),
	}

	cf.globalFlags()
	cf.versionCommands()
	cf.caCommands()
	cf.certCommands()
	cf.configCommands()

	return cf.Cli
}

func (c *CommandFactory) versionCommands() {
	versionCommand := &cobra.Command{
		Use:   "version",
		Short: "Display version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(version.GetVersion())
		},
	}

	c.Cli.AddTopic("version", "display version", false).
		AddCommand(versionCommand)
}

func (c *CommandFactory) caCommands() {
	caCommand := &cobra.Command{
		Use: "ca",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}

	caCreateCommand := &cobra.Command{
		Use:   "ca:create",
		Short: "Create root certificate",
		Run: func(cmd *cobra.Command, args []string) {
			c.initClient()
			err := c.Client.GenerateCA()
			if err != nil {
				fmt.Printf("%v", err)
				os.Exit(1)
			} else {
				fmt.Printf("Root certificate created, or exists")
			}
		},
	}

	caKeyCommand := &cobra.Command{
		Use:   "ca:key",
		Short: "Get root certificate private key",
		Run: func(cmd *cobra.Command, args []string) {
			c.initClient()
			err := c.Client.GetKey("ca")
			if err != nil {
				fmt.Printf("%v", err)
				os.Exit(1)
			}
		},
	}

	caCertCommand := &cobra.Command{
		Use:   "ca:cert",
		Short: "Get root certificate",
		Run: func(cmd *cobra.Command, args []string) {
			c.initClient()
			err := c.Client.GetCert("ca")
			if err != nil {
				fmt.Printf("%v", err)
				os.Exit(1)
			}
		},
	}

	caCRLCommand := &cobra.Command{
		Use:   "ca:crl",
		Short: "Get root certificate revocation list",
		Run: func(cmd *cobra.Command, args []string) {
			c.initClient()
			err := c.Client.GetCRL("ca")
			if err != nil {
				fmt.Printf("%v", err)
				os.Exit(1)
			}
		},
	}

	c.Cli.AddTopic("ca", "manage root certificate", true).
		AddCommand(caCommand).
		AddCommand(caCreateCommand).
		AddCommand(caCertCommand).
		AddCommand(caKeyCommand).
		AddCommand(caCRLCommand)
}

func (c *CommandFactory) certCommands() {
	certCommand := &cobra.Command{
		Use: "cert",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}

	var rootName string
	var dnsNames string
	var ipAddresses string

	certCreateCommand := &cobra.Command{
		Use:   "cert:create <name>",
		Short: "Create certificate",
		Run: func(cmd *cobra.Command, args []string) {
			c.initClient()
			name := getCertificateName(args)
			err := c.Client.Generate(name, rootName, dnsNames, ipAddresses)
			if err != nil {
				fmt.Printf("%v", err)
				os.Exit(1)
			}
		},
	}

	certCreateCommand.Flags().StringVarP(&rootName, "root", "r", "ca", "name of root certificate")
	certCreateCommand.Flags().StringVarP(&dnsNames, "dnsnames", "d", "", "comma separated subject alt dns names")
	certCreateCommand.Flags().StringVarP(&ipAddresses, "ips", "i", "", "comma separated subject alt ip names")

	certKeyCommand := &cobra.Command{
		Use:   "cert:key <name>",
		Short: "Get certificate private key",
		Run: func(cmd *cobra.Command, args []string) {
			c.initClient()
			name := getCertificateName(args)
			err := c.Client.GetKey(name)
			if err != nil {
				fmt.Printf("%v", err)
				os.Exit(1)
			}
		},
	}

	certCertCommand := &cobra.Command{
		Use:   "cert:cert <name>",
		Short: "Get certificate",
		Run: func(cmd *cobra.Command, args []string) {
			c.initClient()
			name := getCertificateName(args)
			err := c.Client.GetCert(name)
			if err != nil {
				fmt.Printf("%v", err)
				os.Exit(1)
			}
		},
	}

	certRevokeCommand := &cobra.Command{
		Use:   "cert:revoke <name>",
		Short: "Revoke certificate",
		Run: func(cmd *cobra.Command, args []string) {
			c.initClient()
			name := getCertificateName(args)
			err := c.Client.Revoke(name)
			if err != nil {
				fmt.Printf("%v", err)
				os.Exit(1)
			}
		},
	}

	certCRLCommand := &cobra.Command{
		Use:   "cert:crl <name>",
		Short: "Get certificate revocation list",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Not implemented")
			os.Exit(1)
		},
	}

	c.Cli.AddTopic("cert", "manage client certificates", true).
		AddCommand(certCommand).
		AddCommand(certCreateCommand).
		AddCommand(certCertCommand).
		AddCommand(certKeyCommand).
		AddCommand(certRevokeCommand).
		AddCommand(certCRLCommand)
}

func (c *CommandFactory) configCommands() {
	var filePath string

	configCommand := &cobra.Command{
		Use: "config",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}

	configGetCommand := &cobra.Command{
		Use:   "config:get",
		Short: "Get authority configuration",
		Run: func(cmd *cobra.Command, args []string) {
			c.initClient()
			err := c.Client.GetConfig()
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		},
	}

	configSetCommand := &cobra.Command{
		Use:   "config:set [<key> <value> | -f <file>]",
		Short: "Set authority configuration, either a single value or a file with multiple values",
		Run: func(cmd *cobra.Command, args []string) {
			c.initClient()
			var err error
			if len(args) == 2 {
				key := args[0]
				val := args[1]
				err = c.Client.SetConfigItem(key, val)
			} else if len(args) == 0 {
				if filePath != "" {
					err = c.Client.SetConfig(filePath)
				} else {
					err = c.Client.SetAllConfig()
				}
			} else {
				fmt.Println("You must provide a key value pair or file name")
				os.Exit(1)
			}

			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		},
	}

	configSetCommand.Flags().StringVarP(&filePath, "file", "f", "", "configuration file")

	c.Cli.AddTopic("config", "edit certificate configuration settings", false).
		AddCommand(configCommand).
		AddCommand(configGetCommand).
		AddCommand(configSetCommand)
}

func (c *CommandFactory) initClient() {
	env_server := os.Getenv("AUTHORITY_VAULT_SERVER")
	env_token := os.Getenv("AUTHORITY_VAULT_TOKEN")

	if c.Server == "" {
		if env_server != "" {
			c.Server = env_server
		} else {
			c.Server = DEFAULT_VAULT_SERVER
		}
	}

	if c.Token == "" && env_token != "" {
		c.Token = env_token
	}

	c.Client = client.NewClient(c.Server, c.Token)
}

func (c *CommandFactory) globalFlags() {
	c.Cli.Flags().StringVarP(&c.Server, "server", "s", "", "address of vault server (AUTHORITY_VAULT_SERVER)")
	c.Cli.Flags().StringVarP(&c.Token, "token", "t", "", "vault access token (AUTHORITY_VAULT_TOKEN)")
}

func getCertificateName(args []string) string {
	if len(args) == 0 {
		fmt.Println("You must provide a certificate name")
		os.Exit(1)
		return ""
	}
	if len(args) > 1 {
		fmt.Println("Too many arguments specified")
		os.Exit(1)
		return ""
	}
	return args[0]
}
