// Command tokgen prints a valid OOB token for manual smoke testing.
package main

import (
	"flag"
	"fmt"

	"ssrf-platform/internal/token"
	"ssrf-platform/internal/types"
)

func main() {
	secret := flag.String("secret", "dev-only-change-me", "HMAC secret")
	variant := flag.String("variant", "oob-http", "variant id")
	flag.Parse()
	c := types.JobContext{Version: 1, TaskID: 1, Nonce: 1, RunID: "smoke", ServiceID: "s", EndpointID: "e", Param: "p", VariantID: *variant}
	fmt.Println(token.Encode(c, []byte(*secret)))
}
