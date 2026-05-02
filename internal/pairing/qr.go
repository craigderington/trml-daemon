package pairing

import (
	"fmt"
	"net/url"

	qrcode "github.com/skip2/go-qrcode"
)

// PairURI builds the trml://pair? URI for QR display.
func PairURI(pubKeyB64, deviceID, relayHost string) string {
	u := url.URL{
		Scheme: "trml",
		Host:   "pair",
	}
	q := url.Values{}
	q.Set("pub", pubKeyB64)
	q.Set("id", deviceID)
	q.Set("relay", relayHost)
	u.RawQuery = q.Encode()
	return u.String()
}

// PrintQR prints the pairing URI as a terminal QR code.
func PrintQR(pubKeyB64, deviceID, relayHost string) error {
	uri := PairURI(pubKeyB64, deviceID, relayHost)

	fmt.Println("\n╔══════════════════════════════════════╗")
	fmt.Println("║         trml pairing code            ║")
	fmt.Println("╚══════════════════════════════════════╝")
	fmt.Println()

	q, err := qrcode.New(uri, qrcode.Medium)
	if err != nil {
		return fmt.Errorf("generate QR: %w", err)
	}
	fmt.Println(q.ToSmallString(false))
	fmt.Printf("URI: %s\n\n", uri)
	fmt.Println("Scan with the trml iOS app to pair this device.")
	fmt.Println()
	return nil
}
