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
	Key      string `json:"key"`
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

	mnemonic, error := getMnemonic()
	firstDerivedKey, error := getPrivateKey(mnemonic, password)

  if error != nil {
    c.Response.Status = 500
		return c.RenderJSON(errorRes{Message: "Internal Server Error!"})
	}
	return c.RenderJSON(mnemonicKeyRes{Key: firstDerivedKey, Mnemonic: mnemonic})
}

func getMnemonic() (string, error){
  // Mnemonic Geneation
  entropy, error := bip39.NewEntropy(256)
  mnemonic, error := bip39.NewMnemonic(entropy)
	return mnemonic, error
}

func getPrivateKey(mnemonic string, password string) (string, error) {
  // Seed for the Private key generation
  seed := bip39.NewSeed(mnemonic, password)
  masterKey, error := bip32.NewMasterKey(seed)

  //Private Key m/0
  bip32PrivateKey, error := masterKey.NewChildKey(0)

  // Private key for m/0/0
  firstDerivedKey, error := bip32PrivateKey.NewChildKey(0)

  return firstDerivedKey.String(), error
}
