package tester_test

import (
	"fmt"

	"github.com/larryf1/jwtoken-tester/v2/pkg/tester"
)

// cleanupT is the two-method subset of testing.T that NewServer needs. In a
// real test the *testing.T value itself is passed.
type cleanupT struct{}

func (cleanupT) Helper()        {}
func (cleanupT) Cleanup(func()) {}

// ExampleNewServer starts an issuer for a test, mints a token, and lets the
// test cleanup close the server.
func ExampleNewServer() {
	var t cleanupT
	srv := tester.NewServer(t)
	defer srv.Close()

	token, err := srv.Mint(tester.MintRequest{
		Claims: map[string]any{"sub": "user-123"},
	})
	if err != nil {
		panic(err)
	}

	fmt.Println(token.TokenType, token.ExpiresIn)
	// Output: Bearer 1h0m0s
}
