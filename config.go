package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"time"
)

type Config struct {
	SecretKey    []byte
	ExpireLength time.Duration
	Port         int
	Principals   []Principal
}

type Principal struct {
	Name      string
	Hash      string
	Resources []string
}

func (c *Config) Read(path string) error {

	// Raw version coming straight from JSON
	type RawConfig struct {
		SecretKey    string
		ExpireLength int
		Port         int
		Principals   []Principal
	}

	byteValue, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	rawC := &RawConfig{}

	json.Unmarshal(byteValue, rawC)

	// Secure by default, although not persistent
	// if no secret key is provided, generate a 128 bit
	// random one (note this will mean tokens generated
	// across restarts will be incomparable)
	if c.SecretKey == nil && rawC.SecretKey == "" {

		r := make([]byte, 16)
		_, err := rand.Read(r)

		if err != nil {
			return err
		}

		c.SecretKey = r
	}
	if rawC.SecretKey != "" {
		c.SecretKey = []byte(rawC.SecretKey)
	}

	// If no expire length set in config.json,
	// assume 1 hour by default
	if rawC.ExpireLength <= 0 {
		rawC.ExpireLength = 1
	}
	c.ExpireLength = time.Hour * time.Duration(rawC.ExpireLength)

	// If no Port, assume 8080
	c.Port = rawC.Port
	if rawC.Port == 0 {
		c.Port = 8080
	}

	// Move principals over to real configuration
	c.Principals = make([]Principal, len(rawC.Principals))
	for i, p := range rawC.Principals {
		if p.Name == "" {
			fmt.Printf("principal at index `%d` has no name, can't be loaded\n", i)
			continue
		}
		if p.Name == "CSRFTOKEN" {
			fmt.Printf("principal name `%s` is not permitted, skipped.", p.Name)
			continue
		}
		c.Principals[i] = p
	}

	return nil
}

func (c *Config) GetPrincipal(name string) *Principal {

	for _, p := range c.Principals {
		if p.Name == name {
			return &p
		}
	}

	return nil
}

func (c *Config) AuthenticatePrincipal(name string, hash string) (bool, error) {

	p := c.GetPrincipal(name)
	if p == nil {
		return false, fmt.Errorf("requested principal `%s` does not exist", name)
	}

	valid := []byte(p.Hash)
	test := []byte(hash)

	diff := 0
	for i := 0; i < len(valid); i++ {
		var t byte
		if i < len(test) {
			t = test[i]
		} else {
			t = valid[i] ^ 0x01
		}
		diff = diff + int((valid[i] ^ t))
	}

	return diff == 0, nil

}

func (c *Config) PrincipalIsAuthorized(name string, requestpath string) bool {

	p := c.GetPrincipal(name)
	if p == nil {
		return false
	}

	res, err := p.IsAuthorized(requestpath)
	if err != nil {
		return false
	}

	return res
}

func (p *Principal) IsAuthorized(requestpath string) (bool, error) {

	val := false

	for _, path := range p.Resources {
		// Iteration over allowed resource prefixes

		if path == "ALL" {
			// Special ALL case grants access to any location
			return true, nil
		}

		matched := 0

		for i, char := range path {
			// Substring prefix matching
			if i < len(requestpath) && rune(requestpath[i]) == char {
				matched = matched + 1
			}
		}

		if matched == len(path) {
			val = true
		}
	}

	return val, nil
}
