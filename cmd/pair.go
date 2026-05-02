package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"

	"github.com/craigderington/trml-daemon/internal/crypto"
	"github.com/craigderington/trml-daemon/internal/pairing"
)

var pairCmd = &cobra.Command{
	Use:   "pair",
	Short: "Print the pairing QR code",
	RunE: func(cmd *cobra.Command, args []string) error {
		pubKeyB64, err := crypto.PublicKeyFromPrivateB64(cfg.PrivateKey)
		if err != nil {
			return fmt.Errorf("derive public key: %w", err)
		}

		relayHost := cfg.RelayURL
		if u, err := url.Parse(cfg.RelayURL); err == nil && u.Host != "" {
			relayHost = u.Host
		}

		return pairing.PrintQR(pubKeyB64, cfg.DeviceID, relayHost)
	},
}
