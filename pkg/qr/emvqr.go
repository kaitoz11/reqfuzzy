package qr

import (
	"fmt"
	"log"

	"go.mercari.io/go-emv-code/mpm"
)

func EncodeEMVString(tag, value string) string {
	length := fmt.Sprintf("%02d", len(value))
	return tag + length + value
}

func PrintEMVQR(qr string) {
	dst, err := mpm.Decode([]byte(qr))
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Printf("%+v\n", dst)
}
