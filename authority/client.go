package authority

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/ovrclk/authority/backend"
)

// Client provides an interface for creating, storing and retrieving x509
// certificates.
type Client struct {
	Server  string
	Token   string
	Cfg     *Config
	Backend backend.Backend

	baseDir         string
	certsDir        string
	keysDir         string
	restrictedNames []string
}

// Init initializes the authority Client, loading configuration and
// connecting to the backend.
func (c *Client) Init(ignoreConfig bool) error {
	c.restrictedNames = []string{"ca", "cert", "config", "crl", "generate", "get", "key", "revoke"}

	homedir := os.Getenv("HOME")

	c.baseDir = filepath.Join(homedir, ".authority")
	c.certsDir = filepath.Join(c.baseDir, "certs")
	c.keysDir = filepath.Join(c.baseDir, "keys")

	for _, dir := range []string{c.certsDir, c.keysDir} {
		if _, err := os.Stat(dir); err != nil && os.IsNotExist(err) {
			if err := os.MkdirAll(dir, 0700); err != nil && !os.IsExist(err) {
				return fmt.Errorf("Could not create %s directory %s", dir, err)
			}
		}
	}

	c.Backend = backend.Backend(&backend.Vault{
		Server: c.Server,
		Token:  c.Token,
	})

	if err := c.Backend.Connect(); err != nil {
		log.Fatal("Can't connect to backend", err)
		return err
	}

	if !ignoreConfig {
		return c.loadConfig()
	}

	return nil
}

// loads the configuration from the backend
func (c *Client) loadConfig() error {
	var err error
	cfg, err := c.Backend.GetConfig()
	if err != nil {
		return err
	} else {
		c.Cfg, err = OpenConfig(cfg)
	}

	return nil
}

// Config displays the stored config, or loads and stores the provided file.
func (c *Client) Config(configPath string) error {
	if configPath == "" {
		cfg, err := c.Backend.GetConfig()
		if err != nil {
			log.Println(err)
		} else {
			log.Println(fmt.Sprintf("Current configuration:\n%s", cfg))
		}
	} else {
		data, err := ioutil.ReadFile(configPath)
		if err != nil {
			return fmt.Errorf("authority: error reading config file (%s): %v", configPath, err)
		}
		err = c.Backend.PutConfig(string(data))
		if err != nil {
			return fmt.Errorf("authority: cannot store configuration: %v", err)
		}
		log.Println("configuration stored")
	}
	return nil
}

// Generate creates and displays a certificate for the provided common name.
// It will also generate and display a backend access token with granular
// permissions to access the certificate.
func (c *Client) Generate(name string) error {
	if !c.nameIsValid(name) {
		return fmt.Errorf("%s is a restricted name", name)
	}

	cert := &Cert{
		CommonName: name,
		Backend:    c.Backend,
		Config:     c.Cfg,
	}

	if cert.Exists() {
		return fmt.Errorf("certificate %s already exists", name)
	}

	if _, err := c.Backend.GetConfig(); err != nil {
		return errors.New("unable to get configuration")
	}

	cert.Create()

	token, err := c.Backend.CreateTokenForCertificate(name)
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
	ca := GetCA(c.Backend, c.Cfg)

	cert := &Cert{
		CommonName: name,
		Backend:    c.Backend,
		Config:     c.Cfg,
	}

	if !cert.Exists() {
		return fmt.Errorf("certificate %s does not exist", name)
	}

	var err error

	caCert := CertificatePEM(ca.GetCertificate())
	if printCA {
		fmt.Println(caCert)
		return nil
	} else {
		err = c.writeFile(filepath.Join(c.certsDir, "ca.crt"), caCert)
		if err != nil {
			return err
		}
	}

	certCert := CertificatePEM(cert.GetCertificate())
	if printCert {
		fmt.Println(certCert)
		return nil
	} else {
		err = c.writeFile(filepath.Join(c.certsDir, fmt.Sprintf("%s.crt", name)), certCert)
		if err != nil {
			return err
		}
	}

	key := cert.GetPrivateKey()
	if key == nil {
		return fmt.Errorf("can't read private key!")
	}

	if printKey {
		fmt.Println(PrivateKeyPEM(key))
		return nil
	} else {
		err = c.writeFile(filepath.Join(c.keysDir, fmt.Sprintf("%s.key", name)), PrivateKeyPEM(key))
		if err != nil {
			return err
		}
	}

	log.Println("certificate", name, "stored")

	return nil
}

// Revoke adds the certificate with the provided common name to the root
// certificates certificate revocation list, assuming that the indicated
// certificate exists.
func (c *Client) Revoke(name string) error {
	ca := GetCA(c.Backend, c.Cfg)

	cert := &Cert{
		CommonName: name,
		Backend:    c.Backend,
		Config:     c.Cfg,
	}

	if !cert.Exists() {
		return fmt.Errorf("certificate %s does not exist", name)
	}

	err := ca.Revoke(cert.GetCertificate())
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
	ca := GetCA(c.Backend, c.Cfg)

	var err error

	cert := CertificatePEM(ca.GetCertificate())
	if printCert {
		fmt.Println(cert)
		return nil
	} else {
		err = c.writeFile(filepath.Join(c.certsDir, "ca.crt"), cert)
		if err != nil {
			return err
		}
	}

	key := ca.GetPrivateKey()
	if key == nil {
		return fmt.Errorf("can't read private key!")
	}

	if printKey {
		fmt.Println(PrivateKeyPEM(key))
		return nil
	} else {
		err = c.writeFile(filepath.Join(c.keysDir, "ca.key"), PrivateKeyPEM(key))
		if err != nil {
			return err
		}
	}

	crl := ca.GetCRLRaw()
	if printCRL {
		f := os.Stdout
		f.Write(crl)
		f.Close()
		return nil
	} else {
		err = c.writeRawFile(filepath.Join(c.baseDir, "crl.crl"), crl)
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

func (c *Client) nameIsValid(name string) bool {
	toCheck := strings.ToLower(name)
	for _, rn := range c.restrictedNames {
		if rn == toCheck {
			return false
		}
	}
	return true
}
