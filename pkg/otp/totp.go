package otp

import (
	"time"

	"github.com/pquerna/otp/totp"
)

func GetTotpPasscode(secret string) string {
	passcode, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		panic(err)
	}

	return passcode
}
