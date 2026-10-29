//go:build go1.26

package attacker

// net/http began using Request.Host for jar lookup/storage in Go 1.26.
const cookieJarUsesRequestHost = true
