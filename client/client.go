package client

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"github.com/ovrclk/authority/api"
	"github.com/ovrclk/authority/authority"
	"github.com/ovrclk/authority/config"
)

// Client provides an command line client for creating, storing and retrieving x509
// certificates.
type Client struct {
	api             *api.Client
	config          *config.Config
	baseDir         string
	certsDir        string
	keysDir         string
	restrictedNames []string
}

func NewClient(server, token string) *Client {
	var err error

	c := &Client{}

	homedir := os.Getenv("HOME")
	c.baseDir = filepath.Join(homedir, ".authority")
	c.certsDir = filepath.Join(c.baseDir, "certs")
	c.keysDir = filepath.Join(c.baseDir, "keys")

	for _, dir := range []string{c.certsDir, c.keysDir} {
		if _, err := os.Stat(dir); err != nil && os.IsNotExist(err) {
			if err := os.MkdirAll(dir, 0700); err != nil && !os.IsExist(err) {
				log.Fatal("authority: Could not create %s directory %v", dir, err)
			}
		}
	}

	c.api, err = api.NewClient(server, token, nil)
	if err != nil {
		log.Fatal(err)
	}

	c.loadConfig()

	return c
}

// loads the configuration from the backend
func (c *Client) loadConfig() error {
	var err error
	c.config, err = c.api.GetConfig()
	if err != nil {
		return err
	}

	return nil
}

// Config displays the stored config, or loads and stores the provided file.
func (c *Client) Config(configPath string) error {
	if configPath == "" {
		cfg, err := c.api.GetConfig()
		if err != nil {
			return err
		}
		configStr, err := cfg.ToString()
		if err != nil {
			return err
		}
		fmt.Println(configStr)
	} else {
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
		log.Println("authority: configuration stored")
	}
	return nil
}

// Generate creates and displays a certificate for the provided common name.
// It will also generate and display a backend access token with granular
// permissions to access the certificate.
func (c *Client) Generate(name string) error {
	_, token, err := c.api.Generate(name)
	if err != nil {
		return err
	}

	log.Printf("access token for %s: %s", name, token)
	return nil
}

// Get retrieves and either displays or stores on the filesystem the
// certificate, private key and root certificate for the provided common
// name, assuming that it exists already.
//
// If stored on the filesystem, the files will be stored in ~/.authority
// by default.
//
// The certificate, key and root certificate will be displayed or stored in a
// PEM encoded format.
func (c *Client) Get(name string, printCA bool, printCert bool, printKey bool) error {
	cert, err := c.api.Get(name)
	if err != nil {
		return err
	}

	root, err := c.api.GetCA()
	if err != nil {
		return err
	}

	caCert := authority.CertificatePEM(root.ClientCertificate.Certificate)
	if printCA {
		fmt.Println(caCert)
		return nil
	} else {
		err = c.writeFile(filepath.Join(c.certsDir, "ca.crt"), caCert)
		if err != nil {
			return err
		}
	}

	certCert := authority.CertificatePEM(cert.Certificate)
	if printCert {
		fmt.Println(certCert)
		return nil
	} else {
		err = c.writeFile(filepath.Join(c.certsDir, fmt.Sprintf("%s.crt", name)), certCert)
		if err != nil {
			return err
		}
	}

	privateKey := authority.PrivateKeyPEM(cert.PrivateKey)
	if printKey {
		fmt.Println(privateKey)
		return nil
	} else {
		err = c.writeFile(filepath.Join(c.keysDir, fmt.Sprintf("%s.key", name)), privateKey)
		if err != nil {
			return err
		}
	}

	if !(printCA || printCert || printKey) {
		log.Println("authority: stored certificate information")
	}

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
	log.Println("certificate", name, "revoked")
	return nil
}

// CA retrieves and either displays or stores on the filesystem the
// certificate, private key and certificate revocation list for the root
// certificate, assuming that it exists already.
//
// If stored on the filesystem, the files will be stored in ~/.authority
// by default.
//
// The certificate and key will be displayed or stored in a PEM encoded
// format, while the certificate revocation list will be displayed or stored
// as raw bytes.
func (c *Client) CA(printCert bool, printKey bool, printCRL bool) error {
	root, err := c.api.GetCA()
	if err != nil {
		return err
	}

	cert := authority.CertificatePEM(root.ClientCertificate.Certificate)
	if printCert {
		fmt.Println(cert)
		return nil
	} else {
		err = c.writeFile(filepath.Join(c.certsDir, "ca.crt"), cert)
		if err != nil {
			return err
		}
	}

	privateKey := authority.PrivateKeyPEM(root.ClientCertificate.PrivateKey)
	if printKey {
		fmt.Println(privateKey)
		return nil
	} else {
		err = c.writeFile(filepath.Join(c.keysDir, "ca.key"), privateKey)
		if err != nil {
			return err
		}
	}

	crlBytes := root.CRL.TBSCertList.Raw
	if printCRL {
		f := os.Stdout
		f.Write(crlBytes)
		f.Close()
		return nil
	} else {
		err = c.writeRawFile(filepath.Join(c.baseDir, "crl.crl"), crlBytes)
		if err != nil {
			return err
		}
	}

	log.Println("certificate authority information stored")
	return nil
}

func (c *Client) writeRawFile(path string, data []byte) error {
	fileOut, err := os.Create(path)
	if err != nil {
		return err
	}
	_, err = fileOut.Write(data)
	return err
}

func (c *Client) writeFile(path string, data string) error {
	fileOut, err := os.Create(path)
	if err != nil {
		return err
	}
	_, err = fileOut.WriteString(data)
	return err
}
