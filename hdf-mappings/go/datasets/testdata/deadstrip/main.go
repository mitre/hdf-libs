// Command deadstrip is the smallest real consumer of one mapping package: it
// exists so a test can build it and inspect which datasets the linker kept.
package main

import (
	"fmt"

	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/owasp"
)

func main() {
	fmt.Println(owasp.NISTControl("A01:2021"))
}
