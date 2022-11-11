package cmd

import (
	"encoding/base64"
	"fmt"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"os"
	"secret-sharing/cryptography"
	aesHelper "secret-sharing/cryptography/aes"
	rsaHelper "secret-sharing/cryptography/rsa"
	"secret-sharing/cryptography/shamir"
	"strings"
)

// readCmd represents the read command
var readCmd = &cobra.Command{
	Use:   "read",
	Short: "Reads a secret",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		isDefined(cmd, "data", "secret", "trustedPartyToken")

		// Unpack secret
		packedSecret := viper.GetString("secret")
		rsa, keyShare, err := cryptography.UnpackRsaAndKeyShare(packedSecret)
		HandleError(err)

		// Get trusted party key share
		encodedShare := viper.GetString("trustedPartyToken")
		trustedPartyShare, err := base64.RawStdEncoding.DecodeString(encodedShare)
		HandleError(err)

		// Reassemble key shares
		assembledKeyBytes, err := shamir.Combine([][]byte{keyShare, trustedPartyShare})
		HandleError(err)
		key, err := aesHelper.NewKey(string(assembledKeyBytes))
		HandleError(err)

		// Decrypt payload
		encryptedData := viper.GetString("data")
		rsaEncryptedData, err := aesHelper.Decrypt(encryptedData, key)
		HandleError(err)
		plaintext, err := rsaHelper.Decrypt(rsaEncryptedData, rsa)
		HandleError(err)

		fmt.Printf("The decryption was succesful:\n%v\n", plaintext)
	},
}

func init() {
	rootCmd.AddCommand(readCmd)

	readCmd.Flags().StringP("data", "d", "", "The data value, can be set in config")
	readCmd.Flags().StringP("secret", "s", "", "The secret value, can be set in config")
	readCmd.Flags().StringP("trustedPartyToken", "t", "", "The trusted party token, can be set in config")
}

func isDefined(cmd *cobra.Command, requiredFlags ...string) {
	var missingFlags []string

	for _, flag := range requiredFlags {
		val, err := cmd.Flags().GetString(flag)
		if err != nil || val == "" {
			if viper.GetViper().IsSet(fmt.Sprintf("read.%v", flag)) == false {
				missingFlags = append(missingFlags, flag)
			} else {
				viper.GetViper().Set(flag, viper.GetString(fmt.Sprintf("read.%v", flag)))
			}
		} else {
			viper.GetViper().Set(flag, val)
		}
	}

	if len(missingFlags) > 0 {
		cmd.PrintErrf("Error: missing required flags \"%v\"\n", strings.Join(missingFlags, "\" \""))
		cmd.Help()
		os.Exit(1)
	}
}
