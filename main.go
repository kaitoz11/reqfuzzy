package main

import (
	"fmt"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker"
)

func main() {
	rawRequest := "GET /df?df=dfdsa&ggg=zzz#sdf HTTP/1.1\r\nHost: example.com\r\n\r\n"

	client := attacker.NewHClient()
	// client.UseProxy("http://127.0.0.1:8080", "./burp.pem")
	client.UseColor(attacker.Red)
	client.UseBaseURL("https://example.com")

	request, err := client.ParseRawRequest(rawRequest)
	if err != nil {
		fmt.Println("Error parsing request:", err)
		return
	}
	fmt.Println("Parsed Request:", request)

	response, err := client.SendRequest(request)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}

	fmt.Println("Response Status Code:", response.StatusCode)
	fmt.Println("Response Body:", response.String())
}
