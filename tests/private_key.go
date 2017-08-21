package tests

import (
	"github.com/revel/revel/testing"
	"net/url"
	"encoding/json"
	"strings"
)

type PrivateKeyTest struct {
	testing.TestSuite
}

type MnemonicKeyTest struct {
	Key      string `json:"key"`
	Mnemonic string `json:"mnemonic"`
}

func (t *PrivateKeyTest) TestValidationWorksProperly() {
	t.PostForm("/private_key", nil)
	t.AssertStatus(422)
	t.AssertContains("Id is required.")
	t.AssertContains("Password is required.")
	t.PostForm("/private_key", url.Values{
		"id": {""}, "password": {""},
	})
	t.AssertStatus(422)
	t.AssertContains("Id is required.")
	t.AssertContains("Password is required.")

	t.PostForm("/private_key", url.Values{
		"id": {""}, "password": {"abcd"},
	})
	t.AssertStatus(422)
	t.AssertContains("Id is required.")
	t.AssertContains("Password must be at least 8 characters.")


	t.PostForm("/private_key", url.Values{
		"id": {"test"}, "password": {"abcd"},
	})
	t.AssertStatus(422)
	t.AssertNotContains("Id is required.")
	t.AssertContains("Password must be at least 8 characters.")

	t.PostForm("/private_key", url.Values{
		"id": {"test"}, "password": {"abcdefgh"},
	})
	t.AssertStatus(200)
	t.AssertNotContains("Id is required.")
	t.AssertNotContains("Password must be at least 8 characters.")

	t.PostForm("/private_key", url.Values{
		"id": {"test"}, "password": {"abcdefghasodijfasdlifjadsoifjaodsifjdsaifjadosifjasdoifjsdfaidsfjasiodjfasiodfjasdoifj"},
	})
	t.AssertStatus(422)
	t.AssertNotContains("Id is required.")
	t.AssertContains("Password must be at most 64 characters.")
}

func (t *PrivateKeyTest) TestItGereratesKeyAndMneonics() {
	t.PostForm("/private_key", url.Values{
		"id": {"12345"}, "password": {"abcdefgh"},
	})
	t.AssertOk()
	t.AssertContentType("application/json; charset=utf-8")

	// Parsing the response from server.
	var response MnemonicKeyTest
	err := json.Unmarshal(t.ResponseBody, &response)
	t.Assert(err == nil)

	key := response.Key
	t.Assert(key != "")
	t.Assert(len(key) == 44)

	mnemonic := response.Mnemonic
	t.Assert(mnemonic != "")
	words := strings.Fields(mnemonic)
	t.Assert(len(words) == 24)
}