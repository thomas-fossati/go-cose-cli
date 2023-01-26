package main

import (
	"bufio"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/veraison/go-cose"
)

func nameToAlg(name string) (error, cose.Algorithm) {
	switch name {
	case "ES256":
		return nil, cose.AlgorithmES256
	case "ES384":
		return nil, cose.AlgorithmES384
	default:
		return fmt.Errorf("algorithm %s not supported", name), 0
	}
}

func MustLoadSignerFromFile(sAlg, sKeyFile string) cose.Signer {
	rawSKey, err := ioutil.ReadFile(sKeyFile)
	if err != nil {
		log.Fatalf("unable to read private key file: %v", err)
	}

	var skey crypto.PrivateKey

	err = jwk.ParseRawKey(rawSKey, &skey)
	if err != nil {
		log.Fatalf("parsing JWK file: %v", err)
	}

	ecKey, ok := skey.(*ecdsa.PrivateKey)
	if !ok {
		log.Fatalf("want EC key, got %T", skey)
	}

	err, alg := nameToAlg(sAlg)
	if err != nil {
		log.Fatalf("%v", err)
	}

	signer, err := cose.NewSigner(alg, ecKey)
	if err != nil {
		log.Fatalf("creating signer: %v", err)
	}

	return signer
}

func MustLoadTBSPayload() []byte {
	r := bufio.NewReader(os.Stdin)

	tbsPayload, err := ioutil.ReadAll(r)
	if err != nil {
		log.Fatalf("reading from stdin: %s", err)
	}

	return tbsPayload
}

func main() {
	var sAlg, sKeyFile string

	flag.StringVar(&sAlg, "a", "", "signature algorithm (ES256, ES384)")
	flag.StringVar(&sKeyFile, "k", "", "file containing a private key in JWK format")

	flag.Parse()

	signer := MustLoadSignerFromFile(sAlg, sKeyFile)

	tbsPayload := MustLoadTBSPayload()

	headers := cose.Headers{}

	sig, err := cose.Sign1(rand.Reader, signer, headers, tbsPayload, nil)
	if err != nil {
		log.Fatalf("sign1 failed: %v", err)
	}

	fmt.Printf("%x\n", sig)
}
