package client

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"

	"github.com/ovrclk/authority/api"
	"github.com/ovrclk/authority/authority"
	"github.com/ovrclk/authority/config"
)

// Client provides an command line client for creating, storing and retrieving x509
// certificates.
type Client struct {
	api    *api.Client
	config *config.Config
}

// Create a new Client.
func NewClient(backend, server, token, path string) *Client {
	var err error

	c := &Client{}

	if backend == "file" {
		c.api, err = api.NewLocalClient(path)
	} else {
		c.api, err = api.NewClient(server, token)
	}

	if err != nil {
		log.Fatal(err)
	}

	c.loadConfig()

	return c
}

// Generate the root certificate if it does not exist already.
func (c *Client) GenerateCA() error {
	_, err := c.api.GetCA()
	return err
}

// SetConfig loads and stores the provided configuration file.
func (c *Client) SetConfig(configPath string) error {
	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("authority: error reading config file (%s): %v", configPath, err)
	}
	config, err := config.OpenConfig(string(data))
	if err != nil {
		return err
	}
	err = c.api.SetConfig(config)
	if err != nil {
		return fmt.Errorf("authority: cannot store configuration: %v", err)
	}
	fmt.Println("authority: configuration stored")
	return nil
}

func (c *Client) SetConfigItem(key, value string) error {
	if !config.KeyIsValid(key) {
		return fmt.Errorf("authority: \"%s\" is not a valid configuration key", key)
	}
	cfg, err := c.api.GetConfig()
	if err != nil && err != authority.ErrConfigMissing {
		return err
	}
	if cfg == nil {
		cfg = &config.Config{}
	}

	cfg.SetItem(key, value)

	err = c.api.SetConfig(cfg)
	if err != nil {
		return fmt.Errorf("authority: cannot store configuration: %v", err)
	}
	fmt.Println("authority: configuration stored")
	return nil
}

func (c *Client) SetAllConfig() error {
	cfg, err := c.api.GetConfig()
	if err != nil && err != authority.ErrConfigMissing {
		return err
	}
	if cfg == nil {
		cfg = &config.Config{}
	}

	r := bufio.NewReader(os.Stdin)
	for _, v := range cfg.GetConfigKeys() {
		fmt.Printf("%12s: ", v)
		input, err := r.ReadString('\n')
		if err != nil {
			return err
		}
		cfg.SetItem(v, strings.TrimSpace(input))
	}

	err = c.api.SetConfig(cfg)
	if err != nil {
		return fmt.Errorf("authority: cannot store configuration: %v", err)
	}
	fmt.Println("authority: configuration stored")
	return nil

}

// GetConfig displays the stored config, if it exists.
func (c *Client) GetConfig() error {
	cfg, err := c.api.GetConfig()
	if err != nil && err != authority.ErrConfigMissing {
		return err
	}
	if cfg == nil {
		cfg = &config.Config{}
	}
	configStr, err := cfg.ToString()
	if err != nil {
		return err
	}
	fmt.Println(configStr)
	return nil
}

// Generate creates and a certificate for the provided common name.
// It will also generate and display a backend access token with granular
// permissions to access the certificate.
func (c *Client) Generate(name string, parent string, dnsNames string, ipAddresses string) error {
	var altNames []string
	for _, name := range strings.Split(dnsNames, ",") {
		trimmedName := strings.TrimSpace(name)
		if trimmedName != "" {
			altNames = append(altNames, trimmedName)
		}
	}

	var altIPs []net.IP
	for _, ipString := range strings.Split(ipAddresses, ",") {
		ip := net.ParseIP(strings.TrimSpace(ipString))
		if ip != nil {
			altIPs = append(altIPs, ip)
		}
	}

	_, token, err := c.api.GenerateWithOptions(name, parent, altNames, altIPs)
	if err != nil {
		return err
	}

	fmt.Printf("access token for %s: %s", name, token)
	return nil
}

// GetCert displays the certificate for the provided common name, assuming that
// it exists already.
//
// The certificate will be displayed in a  PEM encoded format.
func (c *Client) GetCert(name string) error {
	cert, err := c.api.Get(name)
	if err != nil {
		return err
	}

	certCert := authority.CertificatePEM(cert.Certificate)
	fmt.Println(certCert)
	return nil
}

// GetKey displays the certificate for the provided common name, assuming that
// it exists already.
//
// The certificate will be displayed in a  PEM encoded format.
func (c *Client) GetKey(name string) error {
	cert, err := c.api.Get(name)
	if err != nil {
		return err
	}

	privateKey := authority.PrivateKeyPEM(cert.PrivateKey)
	fmt.Println(privateKey)
	return nil
}

// GetCRL outputs the certificate revocation list for the certificate
// with the provided common name.
//
// The certificate revocation list will be output as raw bytes.
func (c *Client) GetCRL(name string) error {
	if name != "ca" {
		return fmt.Errorf("authority: subcertificate revocation not implemented")
	}

	root, err := c.api.GetCA()
	if err != nil {
		return err
	}

	crlBytes := root.CRL.TBSCertList.Raw
	f := os.Stdout
	f.Write(crlBytes)
	f.Close()
	return nil
}

// Revoke adds the certificate with the provided common name to the root
// certificates certificate revocation list, assuming that the indicated
// certificate exists.
func (c *Client) Revoke(name string) error {
	err := c.api.Revoke(name)
	if err != nil {
		return err
	}
	fmt.Println("certificate", name, "revoked")
	return nil
}

func (c *Client) loadConfig() error {
	var err error
	c.config, err = c.api.GetConfig()
	if err != nil {
		return err
	}

	return nil
}
