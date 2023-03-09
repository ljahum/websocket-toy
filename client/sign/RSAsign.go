package sign

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
)

func RsaSign(privateKey *rsa.PrivateKey, msg []byte) []byte {
	//签名
	Shash := sha256.New()
	Shash.Write([]byte(msg))

	signature, _ := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, Shash.Sum(nil))
	return signature
}
func RsaVerify(publicKey *rsa.PublicKey, signature []byte, msg []byte) bool {
	Vhash := sha256.New()
	//Vhash.Write([]byte("123321"))
	Vhash.Write(msg)
	//err := rsa.VerifyPKCS1v15(&privateKey.PublicKey, crypto.SHA256, Vhash.Sum(nil), signature)
	err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, Vhash.Sum(nil), signature)
	if err != nil {
		fmt.Println("error")
		return false

	} else {
		fmt.Println("success")
		return true
	}
}
