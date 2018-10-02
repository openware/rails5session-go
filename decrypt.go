package rails5session

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/reconquest/karma-go"
	"golang.org/x/crypto/pbkdf2"
)

var (
	// Rails.application.encryption.action_dispatch.encrypted_cookie_salt
	DefaultEncryptedCookieSalt = []byte("encrypted cookie")

	// Rails.application.encryption.action_dispatch.encrypted_signed_cookie_salt
	DefaultEncryptedSignedCookieSalt = []byte("signed encrypted cookie")
)

var (
	ErrorInvalidDigest = errors.New("invalid session digest")
)

const (
	sessionKeySize       = 64
	sessionKeyIterations = 1000
)

type Encryption struct {
	keyBase                   []byte
	encryptedCookieSalt       []byte
	encryptedSignedCookieSalt []byte
	secret                    []byte
	signedSecret              []byte
}

func NewEncryption(
	keyBase []byte,
	encryptedCookieSalt []byte,
	encryptedSignedCookieSalt []byte,
) *Encryption {
	encryption := &Encryption{
		keyBase:                   keyBase,
		encryptedCookieSalt:       encryptedCookieSalt,
		encryptedSignedCookieSalt: encryptedSignedCookieSalt,
	}

	if len(encryption.encryptedCookieSalt) == 0 {
		encryption.encryptedCookieSalt = DefaultEncryptedCookieSalt
	}

	if len(encryption.encryptedSignedCookieSalt) == 0 {
		encryption.encryptedCookieSalt = DefaultEncryptedSignedCookieSalt
	}

	encryption.initSecret()
	encryption.initSignSecret()

	return encryption
}

func (encryption *Encryption) initSecret() {
	const aes256cbcSize = 32

	encryption.secret = pbkdf2.Key(
		[]byte(encryption.keyBase),
		[]byte(encryption.encryptedCookieSalt),
		sessionKeyIterations,
		sessionKeySize,
		sha1.New,
	)[0:aes256cbcSize]
}

func (encryption *Encryption) initSignSecret() {
	encryption.signedSecret = pbkdf2.Key(
		[]byte(encryption.keyBase),
		[]byte(encryption.encryptedSignedCookieSalt),
		1000,
		sessionKeySize,
		sha1.New,
	)
}

// VerifyAndDecryptCookieSession verifies given cookie session value digest,
// returns error ErrorInvalidDigest if it's invalid, otherwise tries to decrypt
// the message and returns decrypted message.
func VerifyAndDecryptCookieSession(
	encryption *Encryption,
	cookie string,
) ([]byte, error) {
	// Rails 5 session cookie contains of two parts delimited by --
	// encodedBase64Message--Digest
	//
	// First of all, we need to verify that digest is correct, otherwise after
	// AES decryption we will get garbage instead expected data if the message
	// is not valid.
	parts := strings.SplitN(cookie, "--", 2)

	if len(parts) != 2 {
		return nil, errors.New("missing '--' delimiter in session")
	}

	encodedMessage, messageDigest := parts[0], parts[1]

	// calculate correct digest based on signed secret and given message
	digest := getDigest(encryption.signedSecret, []byte(encodedMessage))

	if digest != messageDigest {
		return nil, ErrorInvalidDigest
	}

	// Here we verified that message and digest is valid, the message is
	// encoded using base64, we need to decode it.

	message, err := base64.StdEncoding.DecodeString(encodedMessage)
	if err != nil {
		return nil, karma.Format(
			err,
			"unable to decode message using base64",
		)
	}

	// The message itself contains of two parts delimtied by --
	// First part is encrypted and base64-encoded data.
	// Second part is initialization vector (nonce) that base64-encoded too.

	messageParts := strings.SplitN(string(message), "--", 2)

	if len(messageParts) != 2 {
		return nil, errors.New(
			"missing '--' delimiter in encrypted session message",
		)
	}

	encodedData, encodedIV := messageParts[0], messageParts[1]

	encryptedData, err := base64.StdEncoding.DecodeString(encodedData)
	if err != nil {
		return nil, karma.Format(
			err,
			"unable to decode encrypted message data part",
		)
	}

	iv, err := base64.StdEncoding.DecodeString(encodedIV)
	if err != nil {
		return nil, karma.Format(
			err,
			"unable to decode encrypted iv data part",
		)
	}

	block, err := aes.NewCipher(encryption.secret)
	if err != nil {
		return nil, karma.Format(
			err,
			"unable to init cipher block",
		)
	}

	if len(encryptedData) < aes.BlockSize {
		return nil, fmt.Errorf(
			"encrypted message is too short: %d (block_size: %d)",
			len(encryptedData), aes.BlockSize,
		)
	}

	// CBC mode always works in whole blocks.
	if len(encryptedData)%aes.BlockSize != 0 {
		return nil, fmt.Errorf(
			"encrypted message is not a multiple of the "+
				"block size: %d (block_size: %d)",
			len(encryptedData), aes.BlockSize,
		)
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	// CryptBlocks can work in-place if the two arguments are the same.
	// So, can omit allocating new memory.
	mode.CryptBlocks(encryptedData, encryptedData)

	// There is always a message padding, we need to remvoe it.
	// Read about padding here:
	// https://tools.ietf.org/html/rfc5246#section-6.2.3.2
	padding := int(encryptedData[len(encryptedData)-1])

	return encryptedData[0 : len(encryptedData)-padding], nil
}

func getDigest(signedSecret []byte, message []byte) string {
	hash := hmac.New(sha1.New, signedSecret)
	hash.Write(message)
	return hex.EncodeToString(hash.Sum(nil))
}
