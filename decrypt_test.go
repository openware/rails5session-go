package rails5session

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	validCookieSalt       = []byte("encrypted cookie")
	validSignedCookieSalt = []byte("signed encrypted cookie")
	validSecretKeyBase    = []byte("62363a59925a0331f946bf3271c6652384c8c211b05a82075e402cc2a514b62414df188585313ecd911b1f3cd0c9847fa2e1bf8ff0fb35a042d0d9c8a21988c9")
)

const validCookie = "anFGNGZRT2N0WFIvVThoa292VlgrdjdFUkJDamZRRmhKS0NTZk0xdEErMmM5enM2UVlsdjdUa2xDQmM0V3A4UElYWXdNUmFLdnNYcWdYWFcvKytmT2MwQ3NNY0xOVGZLbVh5eVlMNEJ6aGhJeTY1bUV3RXpLWlFlVG1pS0RnMUV3b1Fra0tVZUpmbllranRMZTNxK2l2aXRYUEZQYmRoWEV2Q3IwMXBHemM1RzZ6ejR2eFQrS21DMU1ETTRLRFNqNkxXS2R0bVZCSXQwVFdwQ3M3VzQzWTRnTVpJQVhxWkJlV3JUQ1ZpZjEwZ2w5SHNWNHNWQVdBQVh2RU8zbGowRytHM0hXZyt3OTlQWXRpdHJ0VjNsM0E9PS0tUU02NkExRmZ4VnpnVHFZSzZhS2prdz09--8e4c7b7e46f9ec5d4dfeb324df8d12805a86b875"

func TestVerifyAndDecryptCookieSession_Garbage_ReturnsError(t *testing.T) {
	test := assert.New(t)

	encryption := NewEncryption([]byte("q"), []byte("w"), []byte("e"))

	data, err := VerifyAndDecryptCookieSession(encryption, "garbage")
	test.Nil(data)
	test.Error(err)
}

func TestVerifyAndDecryptCookieSession_InvalidDigest_ReturnsErrorInvalidDigest(t *testing.T) {
	test := assert.New(t)

	encryption := NewEncryption([]byte("q"), []byte("w"), []byte("e"))

	data, err := VerifyAndDecryptCookieSession(encryption, "garbage--garbage")
	test.Nil(data)
	test.Error(err)
	test.Equal(err, ErrorInvalidDigest)
}

func TestVerifyAndDecryptCookieSession_ValidSessionIncorrectSecret_ReturnsErrorInvalidDigest(t *testing.T) {
	test := assert.New(t)

	encryption := NewEncryption(
		[]byte("q"),
		validCookieSalt,
		validSignedCookieSalt,
	)

	data, err := VerifyAndDecryptCookieSession(encryption, validCookie)
	test.Nil(data)
	test.Error(err)
	test.Equal(err, ErrorInvalidDigest)
}

func TestVerifyAndDecryptCookieSession_ValidSessionValidSecret_ReturnsData(t *testing.T) {
	test := assert.New(t)

	encryption := NewEncryption(
		validSecretKeyBase,
		validCookieSalt,
		validSignedCookieSalt,
	)

	data, err := VerifyAndDecryptCookieSession(encryption, validCookie)
	test.NotNil(data)
	test.NoError(err)

	unmarshalled := map[string]interface{}{}
	err = json.Unmarshal(data, &unmarshalled)
	test.Nil(err)
	test.NotNil(data)
}
