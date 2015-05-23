package authority

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/user"
	"path/filepath"

	"github.com/ovrclk/authority/backend"
)

type Client struct {
	Server string
	Token  string

	config   *Config
	backend  backend.Backend
	user     *user.User
	baseDir  string
	certsDir string
	keysDir  string
}

func (c *Client) Init(ignoreConfig bool) error {
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

	c.backend = backend.Backend(&backend.Vault{
		Server: c.Server,
		Token:  c.Token,
	})

	if err := c.backend.Connect(); err != nil {
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
	cfg, err := c.backend.GetConfig()
	if err != nil {
		return err
	} else {
		c.config, err = OpenConfig(cfg)
	}

	return nil
}

func (c *Client) Config(config string) error {
	if config == "" {
		cfg, err := c.backend.GetConfig()
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
		err = c.backend.PutConfig(string(data))
		if err != nil {
			return fmt.Errorf("can't store configuration")
		}
		log.Println("configuration stored")
	}
	return nil
}

func (c *Client) Generate(name string) error {
	cert := &Cert{
		CommonName: name,
		Backend:    c.backend,
		Config:     c.config,
	}

	if cert.Exists() {
		return fmt.Errorf("certificate %s already exists", name)
	}

	cert.Create()

	token, err := c.backend.CreateTokenForCertificate(name)
	if err != nil {
		return err
	}
	log.Printf("access token for %s: %s", name, token)

	return nil
}

func (c *Client) Get(name string) error {
	ca := GetCA(c.backend, c.config)

	cert := &Cert{
		CommonName: name,
		Backend:    c.backend,
		Config:     c.config,
	}

	if !cert.Exists() {
		return fmt.Errorf("certificate %s does not exist", name)
	}

	var err error

	caCert := CertificatePEM(ca.GetCertificate())
	err = c.writeFile(filepath.Join(c.certsDir, "ca.crt"), caCert)
	if err != nil {
		return err
	}

	certCert := CertificatePEM(cert.GetCertificate())
	err = c.writeFile(filepath.Join(c.certsDir, fmt.Sprintf("%s.crt", name)), certCert)
	if err != nil {
		return err
	}

	key := cert.GetPrivateKey()
	if key == nil {
		return fmt.Errorf("can't read private key!")
	}
	err = c.writeFile(filepath.Join(c.keysDir, fmt.Sprintf("%s.key", name)), PrivateKeyPEM(key))
	if err != nil {
		return err
	}

	log.Println("certificate", name, "stored")

	return nil
}

func (c *Client) Revoke(name string) error {
	ca := GetCA(c.backend, c.config)

	cert := &Cert{
		CommonName: name,
		Backend:    c.backend,
		Config:     c.config,
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

func (c *Client) CA() error {
	ca := GetCA(c.backend, c.config)

	var err error

	cert := CertificatePEM(ca.GetCertificate())
	err = c.writeFile(filepath.Join(c.certsDir, "ca.crt"), cert)
	if err != nil {
		return err
	}

	key := ca.GetPrivateKey()
	if key == nil {
		return fmt.Errorf("can't read private key!")
	}
	err = c.writeFile(filepath.Join(c.keysDir, "ca.key"), PrivateKeyPEM(key))
	if err != nil {
		return err
	}

	crl := ca.GetCRLRaw()
	err = c.writeRawFile(filepath.Join(c.baseDir, "crl.crl"), crl)
	if err != nil {
		return err
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
