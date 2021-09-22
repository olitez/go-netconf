package netconf

import "golang.org/x/crypto/ssh"

//Credential things to login on some host
type Credential interface {
	Config() *ssh.ClientConfig
}

//PlainPassword user-password login credential
type PlainPassword struct {
	User     string
	Password string
}

//Config build an ssh.ClientConfig from credential
func (p PlainPassword) Config() *ssh.ClientConfig {
	return SSHConfigPassword(p.User, p.Password)
}

//PublicKey privat-public key login credential
type PublicKey struct {
	User string
	Key  string
}

//Config build an ssh.ClientConfig from credential
func (p PublicKey) Config() *ssh.ClientConfig {
	cfg, err := SSHConfigPubKeyFile(p.User, p.Key, "\n")
	if err != nil {
		panic(err)
	}
	return cfg
}
