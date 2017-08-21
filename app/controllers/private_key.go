package controllers

import (
	"github.com/revel/revel"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
)

type PrivateKey struct {
	App
}

type mnemonicKeyRes struct {
	Key      []byte `json:"key"`
	Mnemonic string `json:"mnemonic"`
}

type errorRes struct {
	Message string                            `json:"message"`
	Errors  map[string]*revel.ValidationError `json:"errors"`
}

func (c PrivateKey) Create(id, password string) revel.Result {

	c.Validation.Required(id).Message("Id is required.")
	c.Validation.Required(password).Message("Password is required.")
	c.Validation.MinSize(password, 8).Message("Password must be at least 8 characters.")
	c.Validation.MaxSize(password, 64).Message("Password must be at most 64 characters.")

	if c.Validation.HasErrors() {
		c.Response.Status = 422
		return c.RenderJSON(errorRes{Message: "Request not valid!", Errors: c.Validation.ErrorMap()})
	}

	masterKey, mnemonic := generateMasterKeyPair(password)
	return c.RenderJSON(mnemonicKeyRes{Key: masterKey.Key, Mnemonic: mnemonic})
}

func generateMasterKeyPair(password string) (*bip32.Key, string) {
	entropy, _ := bip39.NewEntropy(256)
	mnemonic, _ := bip39.NewMnemonic(entropy)
	seed := bip39.NewSeed(mnemonic, password)
	masterKey, _ := bip32.NewMasterKey(seed)
	return masterKey, mnemonic
}
