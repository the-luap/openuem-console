// openuem-apple-vendor runs only in an authorized MDM vendor's infrastructure.
// It never contacts a customer instance or Apple's portal.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/open-uem/openuem-console/internal/mdm/apple"
)

func main() {
	csr := flag.String("csr", "", "Absolute path to the customer's public PEM CSR")
	chain := flag.String("vendor-chain", "", "Absolute path to the authorized vendor certificate, intermediates and Apple root in PEM order")
	key := flag.String("vendor-key", "", "Absolute path to the vendor's protected PKCS#8 RSA key, kept only in vendor infrastructure")
	pin := flag.String("vendor-sha256", "", "Approved vendor certificate SHA-256 fingerprint (64 lowercase hex characters), verified out of band")
	output := flag.String("output", "", "Absolute new output path under trusted parents; an existing entry is never overwritten")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "unexpected positional arguments")
		os.Exit(1)
	}
	trust, err := apple.NewVendorTrust([]string{*pin})
	if err == nil {
		err = trust.SignVendorFiles(*csr, *chain, *key, *output)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stdout, "Vendor-signed portal request created. Return this public file to the customer. Apple issuance has not been performed.")
}
