package api

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"github.com/ovrclk/authority/authority"
	"github.com/ovrclk/authority/config"
)

func getVaultInfo(t *testing.T) (string, string, *sync.Mutex, chan bool) {
	cmd := exec.Command("vault", "server", "-dev")
	mut := &sync.Mutex{}
	done := make(chan bool)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal("can't run vault", err)
	}

	token := make(chan string)

	runVault := func() {
		if err := cmd.Start(); err != nil {
			t.Fatal("can't run vault", err)
		}

		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			text := scanner.Text()
			fmt.Println(text)
			if strings.HasPrefix(text, "Root Token:") {
				token <- strings.TrimPrefix(text, "Root Token: ")
				mut.Lock()
				mut.Lock()
				fmt.Println("killing vault!!!!!!!")
				cmd.Process.Signal(os.Kill)
				done <- true
				return
			}
		}
	}
	go runVault()

	theToken := <-token
	fmt.Println("Using vault token:", theToken)

	return "http://localhost:8200", theToken, mut, done
}

func testConfig() *config.Config {
	return &config.Config{
		Defaults: config.DefaultsConfig{
			RootDomain: "ovrclk.com",
			Email:      "jeff@ovrclk.com",
			Org:        "Ovrclk",
			OrgUnit:    "Ovrclk",
			City:       "Missoula",
			Region:     "Montana",
			Country:    "USA",
			CrlDays:    "365",
			Digest:     "sha256",
			CertExpiry: "365",
		},
	}
}

func TestApiClientWithConfig(t *testing.T) {
	server, token, mutex, done := getVaultInfo(t)

	api, err := NewClient(server, token, nil)
	if err != nil {
		t.Fatal("error initializing client %v", err)
	}

	c, err := api.GetConfig()
	if c != nil || (err != authority.ErrConfigMissing) {
		t.Fatal("config shouldn't exist")
	}

	api, err = NewClient(server, token, testConfig())
	if err != nil {
		t.Fatalf("error initializing client %v", err)
	}

	c, err = api.GetConfig()
	if c == nil || (err != nil) {
		t.Fatal("config should exist")
	}

	root, err := api.GetCA()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if root.CommonName != "ca" {
		t.Fatal("root cert has wrong name")
	}

	if root.Certificate == nil {
		t.Fatal("don't have root certificate")
	}

	if root.PrivateKey == nil {
		t.Fatal("don't have root private key")
	}

	client, token, err := api.Generate("foobar", "")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if client.CommonName != "foobar" {
		t.Fatal("got an unexpected cert name")
	}

	if client.Certificate == nil {
		t.Fatal("don't have client certificate")
	}

	if client.PrivateKey == nil {
		t.Fatal("don't have client private key")
	}

	client2, err := api.Get("foobar")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if client2.CommonName != client.CommonName {
		t.Fatal("got an unexpected cert name")
	}

	if !bytes.Equal(client2.Certificate.Raw, client.Certificate.Raw) {
		t.Fatal("got unexpected certificate")
	}

	if client2.PrivateKey.D == client.PrivateKey.D {
		t.Fatal("got unexpected private key")
	}

	client3, token2, err := api.Generate("foobar", "")
	if token2 != "" {
		t.Fatal("expected empty token")
	}

	if err != authority.ErrCertAlreadyExists {
		t.Fatal("expected error for duplicate certificate")
	}

	if client2.CommonName != client3.CommonName {
		t.Fatal("got an unexpected cert name")
	}

	if !bytes.Equal(client2.Certificate.Raw, client3.Certificate.Raw) {
		t.Fatal("got unexpected certificate")
	}

	if client2.PrivateKey.D == client3.PrivateKey.D {
		t.Fatal("got unexpected private key")
	}

	mutex.Unlock()
	foo := <-done
	fmt.Println("done", foo)
}

func TestApiClientWithChildCert(t *testing.T) {
	server, token, mutex, done := getVaultInfo(t)

	api, err := NewClient(server, token, nil)
	if err != nil {
		t.Fatal("error initializing client %v", err)
	}

	c, err := api.GetConfig()
	if c != nil || (err != authority.ErrConfigMissing) {
		t.Fatal("config shouldn't exist")
	}

	api, err = NewClient(server, token, testConfig())
	if err != nil {
		t.Fatalf("error initializing client %v", err)
	}

	c, err = api.GetConfig()
	if c == nil || (err != nil) {
		t.Fatal("config should exist")
	}

	client, token, err := api.Generate("foo", "")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if client.CommonName != "foo" {
		t.Fatal("got an unexpected cert name")
	}

	client2, token, err := api.Generate("bar", "foo")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if client2.Certificate.Issuer.CommonName != client.CommonName {
		t.Fatalf("expected issuer name of %s but got %s instead", client.CommonName, client2.Certificate.Issuer.CommonName)
	}

	mutex.Unlock()
	foo := <-done
	fmt.Println("done", foo)
}
