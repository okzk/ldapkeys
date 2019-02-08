package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/BurntSushi/toml"
	"gopkg.in/ldap.v2"
	"io/ioutil"
	"log"
	"net/url"
	"os"
)

type Config struct {
	URL          string
	BaseDN       string
	Filter       string
	BindDN       string
	BindPassword string
}

func main() {
	log.SetFlags(0)
	if os.Getenv("LDAPKEYS_VERBOSE") != "1" {
		log.SetOutput(ioutil.Discard)
	}

	confFile := os.Getenv("LDAPKEYS_CONFIG_FILE")
	if confFile == "" {
		confFile = "/etc/ldapkeys/config.toml"
	}
	var conf Config
	if _, err := toml.DecodeFile(confFile, &conf); err != nil {
		log.Fatal(err)
	}

	if len(os.Args) <= 1 {
		log.Fatal("missing uid")
	}

	printPublicKeys(&conf, os.Args[1])
}

func printPublicKeys(conf *Config, uid string) {
	l, err := connectLDAP(conf.URL)
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	if conf.BindDN != "" {
		if err = l.Bind(conf.BindDN, conf.BindPassword); err != nil {
			log.Fatal(err)
		}
	}

	searchRequest := ldap.NewSearchRequest(
		conf.BaseDN, ldap.ScopeWholeSubtree, ldap.DerefAlways, 0, 0, false,
		fmt.Sprintf("(&(uid=%s)%s)", ldap.EscapeFilter(uid), conf.Filter),
		[]string{"sshPublicKey"}, nil)

	sr, err := l.Search(searchRequest)
	if err != nil {
		log.Fatal(err)
	}
	if len(sr.Entries) == 0 {
		log.Fatal("no entry")
	}
	if len(sr.Entries) > 1 {
		log.Fatal("too much entries")
	}

	for _, key := range sr.Entries[0].GetAttributeValues("sshPublicKey") {
		fmt.Println(key)
	}
}

func connectLDAP(urlStr string) (*ldap.Conn, error) {
	ldapUrl, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}

	if ldapUrl.Scheme == "ldap" {
		address := ldapUrl.Host
		if ldapUrl.Port() == "" {
			address += ":389"
		}
		return ldap.Dial("tcp", address)
	} else if ldapUrl.Scheme == "ldaps" {
		address := ldapUrl.Host
		if ldapUrl.Port() == "" {
			address = ldapUrl.Host + ":636"
		}
		return ldap.DialTLS("tcp", address, &tls.Config{ServerName: ldapUrl.Host})
	} else {
		return nil, errors.New("unsupported scheme: " + ldapUrl.Scheme)
	}
}
