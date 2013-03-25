##GOTP

One-Time Password for Google Authenticator

##Example
```go
package main

import (
	"github.com/xgdapg/gotp"
	"log"
)

func main() {
	otp := gotp.NewGoogleAuth("YOUR_SECRET_KEY")
	log.Println("TOTP", otp.GenerateByTime())
	log.Println("HOTP", otp.GenerateByCount(3))
}
```