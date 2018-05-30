package main

import (
"crypto/ecdsa"
"crypto/elliptic"
"crypto/rand"
"fmt"
"encoding/pem"
"encoding/asn1"
"errors"
"io/ioutil"
"crypto/x509"
"crypto/rsa"
)

type pkcs8Info struct {
	Version             int
	PrivateKeyAlgorithm []asn1.ObjectIdentifier
	PrivateKey          []byte
}

type ecPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

func main() {

	//privateKeyTest()


	file, err := ioutil.ReadFile("ssss.pem")
	//file, err := ioutil.ReadFile("private.pem")
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	privateKey, err := pemtoPrivateKey(file, nil)

	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println("========")
	//
	//pemEncoded, err := toPem(privateKey)
	//if err != nil {
	//	fmt.Println(err.Error())
	//	return
	//}
	//fmt.Println("")
	//fmt.Println(string(pemEncoded))
	//fmt.Println("")

	x509Encoded, _ := x509.MarshalECPrivateKey(privateKey)
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})

	fmt.Println("")
	fmt.Println(string(pemEncoded))
	fmt.Println("")

	//x509EncodedPub, _ := x509.MarshalPKIXPublicKey(publicKey)
	//pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})
	//
	//return string(pemEncoded), string(pemEncodedPub)

	//puk := prk.PublicKey
	//
	//pem.EncodeToMemory(
	//	&pem.Block{
	//		Type:  "PRIVATE KEY",
	//		Bytes: prk.,
	//	},
}

func privateKeyTest() {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	pemEncoded, err := toPem(privateKey)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println("")
	fmt.Println(string(pemEncoded))
	fmt.Println("")
}

func toPem(k *ecdsa.PrivateKey) ([]byte, error) {
	if k == nil {
		return nil, errors.New("Invalid ecdsa private key. It must be different from nil.")
	}

	// get the oid for the curve
	oidNamedCurve := asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidPublicKeyECDSA := asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}

	// based on https://golang.org/src/crypto/x509/sec1.go
	privateKeyBytes := k.D.Bytes()
	paddedPrivateKey := make([]byte, (k.Curve.Params().N.BitLen() + 7) / 8)
	copy(paddedPrivateKey[len(paddedPrivateKey) - len(privateKeyBytes):], privateKeyBytes)
	// omit NamedCurveOID for compatibility as it's optional
	asn1Bytes, err := asn1.Marshal(ecPrivateKey{
		Version:    1,
		PrivateKey: paddedPrivateKey,
		PublicKey:  asn1.BitString{Bytes: elliptic.Marshal(k.Curve, k.X, k.Y)},
	})

	if err != nil {
		return nil, fmt.Errorf("error marshaling EC key to asn1 [%s]", err)
	}

	var pkcs8Key pkcs8Info
	pkcs8Key.Version = 0
	pkcs8Key.PrivateKeyAlgorithm = make([]asn1.ObjectIdentifier, 2)
	pkcs8Key.PrivateKeyAlgorithm[0] = oidPublicKeyECDSA
	pkcs8Key.PrivateKeyAlgorithm[1] = oidNamedCurve
	pkcs8Key.PrivateKey = asn1Bytes

	pkcs8Bytes, err := asn1.Marshal(pkcs8Key)
	if err != nil {
		return nil, fmt.Errorf("error marshaling EC key to asn1 [%s]", err)
	}
	return pem.EncodeToMemory(
		&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: pkcs8Bytes,
		},
	), nil
}

// PEMtoPrivateKey unmarshals a pem to private key
func pemtoPrivateKey(raw []byte, pwd []byte) (*ecdsa.PrivateKey, error) {
	if len(raw) == 0 {
		return nil, errors.New("Invalid PEM. It must be different from nil.")
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("Failed decoding PEM. Block must be different from nil. [% x]", raw)
	}

	// TODO: derive from header the type of the key

	if x509.IsEncryptedPEMBlock(block) {
		if len(pwd) == 0 {
			return nil, errors.New("Encrypted Key. Need a password")
		}

		decrypted, err := x509.DecryptPEMBlock(block, pwd)
		if err != nil {
			return nil, fmt.Errorf("Failed PEM decryption [%s]", err)
		}

		fmt.Println("11111")
		key, err := DERToPrivateKey(decrypted)
		if err != nil {
			return nil, err
		}
		return key, err
	}

	fmt.Println("22222222")
	cert, err := DERToPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, err
}

// DERToPrivateKey unmarshals a der to private key
func DERToPrivateKey(der []byte) (key *ecdsa.PrivateKey, err error) {

	if _, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return nil, errors.New("not ecdsa.PrivateKey rsa privatekey 1")
	}

	prk, err := x509.ParsePKCS8PrivateKey(der);
	if err == nil {
		switch prk.(type) {
		case *rsa.PrivateKey:
			return nil, errors.New("not ecdsa.PrivateKey rsa privatekey 2")
		case *ecdsa.PrivateKey:
			fmt.Println("3333")
			return prk.(*ecdsa.PrivateKey), nil
		default:
			return nil, errors.New("Found unknown private key type in PKCS#8 wrapping")
		}
	}

	if key, err = x509.ParseECPrivateKey(der); err == nil {
		fmt.Println("4444444")
		return
	}

	return nil, errors.New("Invalid key type. The DER must contain an rsa.PrivareKey or ecdsa.PrivateKey")
}

