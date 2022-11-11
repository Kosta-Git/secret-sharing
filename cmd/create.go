package cmd

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"github.com/Kosta-Git/secret-sharing/cryptography"
	aesHelper "github.com/Kosta-Git/secret-sharing/cryptography/aes"
	rsaHelper "github.com/Kosta-Git/secret-sharing/cryptography/rsa"
	"github.com/Kosta-Git/secret-sharing/cryptography/shamir"
	"github.com/spf13/cobra"
)

var (
	secret    string
	keySize   int
	nonceSize int
	rsaSize   int
)

// createCmd represents the create command
var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Creates a new secret",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		// Create RSA Key
		rng := rand.Reader
		key, err := rsa.GenerateKey(rng, rsaSize)
		HandleError(err)

		rsaEncryptedSecret, err := rsaHelper.Encrypt(secret, &key.PublicKey)
		HandleError(err)

		aesSecret, err := aesHelper.GenerateSecret(keySize, nonceSize)
		HandleError(err)

		finalPayload, err := aesHelper.Encrypt(rsaEncryptedSecret, aesSecret)
		HandleError(err)

		aesKeyShares, err := shamir.Split(aesSecret.FormatBytes(), 2, 2)
		HandleError(err)

		packedSecret, err := cryptography.PackRsaAndKeyShare(key, aesKeyShares[0])
		HandleError(err)

		fmt.Printf("Data: \n%v\n", finalPayload)
		fmt.Printf("Secret: \n%v\n", packedSecret)
		fmt.Printf("Trusted party authorization code: \n%v\n", base64.RawStdEncoding.EncodeToString(aesKeyShares[1]))
	},
}

func init() {
	rootCmd.AddCommand(createCmd)

	createCmd.Flags().StringVarP(&secret, "secret", "s", "", "The secret you want to share")
	if err := createCmd.MarkFlagRequired("secret"); err != nil {
		fmt.Println(err)
	}

	createCmd.Flags().IntVarP(&keySize, "keySize", "k", 32, "The aes key size, defaults to 32bytes (aes256)")
	createCmd.Flags().IntVarP(&nonceSize, "nonceSize", "n", 12, "The aes nonce size, defaults to 12bytes")
	createCmd.Flags().IntVarP(&rsaSize, "rsaSize", "r", 4096, "The rsa key size, defaults to 4096bytes")
}
