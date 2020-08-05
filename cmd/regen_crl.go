package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/square/certstrap/depot"
	"github.com/square/certstrap/pkix"
	"github.com/urfave/cli"
)

// NewInitCommand sets up an "init" command to initialize a new CA
func RegenCRLCommand() cli.Command {
	return cli.Command{
		Name:        "regen-crl",
		Usage:       "Regenerate Certificate Authority CRL",
		Description: "Regenerate Certificate Authority CRL.",
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "passphrase",
				Usage: "Passphrase to decrypt private-key PEM block of CA",
			},
			cli.StringFlag{
				Name:  "CA",
				Usage: "Name of CA to re-generation CRL from",
			},
		},
		Action: RegenCRLAction,
	}
}

func RegenCRLAction(c *cli.Context) {
	if !c.IsSet("CA") {
		fmt.Println("Must supply CA")
		os.Exit(1)
	}

	formattedCAName := strings.Replace(c.String("CA"), " ", "_", -1)

	key, err := depot.GetPrivateKey(d, formattedCAName)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Read CA key error:", err)
		os.Exit(1)
	}

	crt, err := depot.GetCertificate(d, formattedCAName)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Read CA crt error:", err)
		os.Exit(1)
	}

	expiresTime, err := crt.GetNotAfter()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Read CA NotAfter error:", err)
		os.Exit(1)
	}

	// Create an empty CRL, this is useful for Java apps which mandate a CRL.
	crl, err := pkix.CreateCertificateRevocationList(key, crt, expiresTime)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Create CRL error:", err)
		os.Exit(1)
	}
	if err = depot.PutCertificateRevocationList(d, formattedCAName, crl); err != nil {
		fmt.Fprintln(os.Stderr, "Save CRL error:", err)
		os.Exit(1)
	}
	fmt.Printf("Created %s/%s.crl\n", depotDir, formattedCAName)
}
