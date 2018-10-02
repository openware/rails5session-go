# rails5session-go

[![GoDoc](https://godoc.org/github.com/openware/rails5session-go?status.svg)](https://godoc.org/github.com/openware/rails5session-go)

Go decrypter of Rails 5 sessions.

## Installation

```
go get github.com/openware/rails5session-go
```

## Usage

Create Encryption instance with your rails session secret key base (specified
in config/secrets.yml)

```go
encryption := rails5session.NewEncryption(
    secretKeyBase,
    cookieSalt,
    signedCookieSalt,
)
```

* You can obtain your cookieSalt by running following ruby code:

    ```ruby
    Rails.application.encryption.action_dispatch.encrypted_cookie_salt
    ```

* You can obtain your signedCookieSalt by running following ruby code:

    ```ruby
    Rails.application.encryption.action_dispatch.encrypted_signed_cookie_salt
    ```


Then verify and decrypt user's cookie, it will return decrypted slice of bytes
and error if any.

```go
	data, err := rails5session.VerifyAndDecryptCookieSession(encryption, cookie)
    if err != nil {
        panic(err)
    }
```

Also, take a look at [tests](decrypt_test.go).
