package main

import (
	"fmt"
	"time"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker"
)

func main() {
	rawRequest := []byte("GET /df?df=dfdsa&ggg=zzz#sdf HTTP/1.1\r\nHost: example.com\r\n\r\n")

	client := attacker.NewHClient()
	client.UseProxy("http://127.0.0.1:8080", "/home/k4it0z11/security-toolbox/burp/cert.pem")
	client.UseColor(attacker.Red)
	client.UseBaseURL("https://example.com")

	request, err := client.ParseRawRequest(rawRequest)
	if err != nil {
		fmt.Println("Error parsing request:", err)
		return
	}
	// fmt.Println("Parsed Request:", string(request))

	// response, err := client.SendRequest(request)
	// if err != nil {
	// 	fmt.Println("Error sending request:", err)
	// 	return
	// }
	//
	// fmt.Println("Response Status Code:", response.StatusCode)
	// fmt.Println("Response Body:", response.String())

	fuzzer := attacker.NewFuzzerBuilder(client, request)
	fuzzer.AddInjector(func(request attacker.Request) error {
		request.SetQueryParam("df", "123456")
		return nil
	})
	for i := range 100 {
		fuzzer.AddInjector(func(request attacker.Request) error {
			request.SetQueryParam("df", fmt.Sprintf("123453-%d", i))
			return nil
		})
	}
	fuzzy, err := fuzzer.Build()
	if err != nil {
		panic(err)
	}

	fuzzy.Fuzz()
	//
	// go func() {
	// 	time.Sleep(time.Second * 20)
	// 	fuzzy.PauseFuzzing()
	// 	fmt.Println("Fuzzing Paused")
	// 	time.Sleep(time.Second * 10)
	// 	fuzzy.Fuzz(func(config *attacker.FuzzingConfig) {
	// 		config.RateLimiter = time.Millisecond * 100
	// 	})
	// }()
	//
	// for {
	// 	time.Sleep(time.Second * 1)
	// 	fuzzy.PrintFuzzingResult()
	// }
}
