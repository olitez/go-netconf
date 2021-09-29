package netconf

import (
	"fmt"

	"golang.org/x/crypto/ssh"
)

//Credential things to login on some host
type Credential interface {
	Config() *ssh.ClientConfig
	String() string
}

//PlainPassword user-password login credential
type PlainPassword struct {
	User     string
	Password string
}

func (p PlainPassword) String() string { return fmt.Sprintf("%s plain password", p.User) }

//Config build an ssh.ClientConfig from credential
func (p PlainPassword) Config() *ssh.ClientConfig {
	return SSHConfigPassword(p.User, p.Password)
}

//PublicKey privat-public key login credential
type PublicKey struct {
	User string
	File string
}

func (p PublicKey) String() string { return fmt.Sprintf("%s public key", p.User) }

//Config build an ssh.ClientConfig from credential
func (p PublicKey) Config() *ssh.ClientConfig {
	cfg, err := SSHConfigPubKeyFile(p.User, p.File)
	if err != nil {
		panic(err)
	}
	return cfg
}
