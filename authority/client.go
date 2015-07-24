package authority

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/ovrclk/authority/backend"
)

type Client struct {
	Server string
	Token  string

	Cfg             *Config
	Backend         backend.Backend
	user            *user.User
	baseDir         string
	certsDir        string
	keysDir         string
	restrictedNames []string
}

func (c *Client) Init(ignoreConfig bool) error {
	c.restrictedNames = []string{"ca", "cert", "config", "crl", "generate", "get", "key", "revoke"}

	c.user, _ = user.Current()

	c.baseDir = filepath.Join(c.user.HomeDir, ".authority")
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

func (c *Client) Config(config string) error {
	if config == "" {
		cfg, err := c.Backend.GetConfig()
		if err != nil {
			log.Println(err)
		} else {
			log.Println(fmt.Sprintf("Current configuration:\n%s", cfg))
		}
	} else {
		data, err := ioutil.ReadFile(config)
		if err != nil {
			return fmt.Errorf("can't load configuration file: %s", config)
		}
		err = c.Backend.PutConfig(string(data))
		if err != nil {
			return fmt.Errorf("can't store configuration")
		}
		log.Println("configuration stored")
	}
	return nil
}

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

	cert.Create()

	token, err := c.Backend.CreateTokenForCertificate(name)
	if err != nil {
		return err
	}
	log.Printf("access token for %s: %s", name, token)

	return nil
}

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
