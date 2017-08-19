package controllers

import (
	"github.com/revel/revel"
    "github.com/tyler-smith/go-bip32"
    "github.com/tyler-smith/go-bip39"
)

type PrivateKey struct {
	*revel.Controller
}

type MnemonicKeyRes struct {
    Key []byte `json:"key"`
    Mnemonic string `json:"mnemonic"`
}

func (c PrivateKey) Create() revel.Result {
	var jsonData map[string]string
	c.Params.BindJSON(&jsonData)

	masterKey, mnemonic := GenerateMasterKeyPair(jsonData["password"])

	responseData := MnemonicKeyRes{Key: masterKey.Key, Mnemonic: mnemonic}

	return c.RenderJSON(responseData)
}

func GenerateMasterKeyPair(password string) (*bip32.Key, string) {
  // Generate a mnemonic for memorization or user-friendly seeds
  entropy, _ := bip39.NewEntropy(256)
  mnemonic, _ := bip39.NewMnemonic(entropy)

  seed := bip39.NewSeed(mnemonic, password)

  masterKey, _ := bip32.NewMasterKey(seed)

  return masterKey, mnemonic
}