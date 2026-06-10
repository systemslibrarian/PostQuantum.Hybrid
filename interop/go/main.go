// Cross-implementation interop driver: exercises ML-KEM-768 via Go's
// standard library (crypto/mlkem, FIPS 203) and ML-DSA-65 via
// cloudflare/circl (FIPS 204) so CI can prove the .NET backends agree
// with independent implementations. See interop/README.md and
// .github/workflows/interop.yml.
package main

import (
	"crypto/mlkem"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

func main() {
	if len(os.Args) < 2 {
		die("usage: interop <subcommand> args... (mlkem-pubkey|mlkem-encap|mlkem-decap|mldsa-pubkey|mldsa-sign|mldsa-verify)")
	}
	switch os.Args[1] {
	case "mlkem-pubkey":
		// mlkem-pubkey <seed-hex(64B d||z)> -> ek hex
		dk := decapKey(arg(2))
		fmt.Println(hex.EncodeToString(dk.EncapsulationKey().Bytes()))
	case "mlkem-encap":
		// mlkem-encap <ek-hex> -> line1: ct hex, line2: ss hex
		ekBytes, err := hex.DecodeString(arg(2))
		check(err)
		ek, err := mlkem.NewEncapsulationKey768(ekBytes)
		check(err)
		ss, ct := ek.Encapsulate()
		fmt.Println(hex.EncodeToString(ct))
		fmt.Println(hex.EncodeToString(ss))
	case "mlkem-decap":
		// mlkem-decap <seed-hex> <ct-hex> -> ss hex
		dk := decapKey(arg(2))
		ct, err := hex.DecodeString(arg(3))
		check(err)
		ss, err := dk.Decapsulate(ct)
		check(err)
		fmt.Println(hex.EncodeToString(ss))
	case "mldsa-pubkey":
		// mldsa-pubkey <seed-hex(32B ξ)> -> vk hex
		pub, _ := mldsaKeys(arg(2))
		fmt.Println(hex.EncodeToString(pub.Bytes()))
	case "mldsa-sign":
		// mldsa-sign <seed-hex(32B)> <msg-hex> -> sig hex (deterministic, empty ctx)
		_, priv := mldsaKeys(arg(2))
		msg, err := hex.DecodeString(arg(3))
		check(err)
		sig := make([]byte, mldsa65.SignatureSize)
		check(mldsa65.SignTo(priv, msg, nil, false, sig))
		fmt.Println(hex.EncodeToString(sig))
	case "mldsa-verify":
		// mldsa-verify <vk-hex> <msg-hex> <sig-hex> -> "ok" or exit 1
		pub := mldsaPub(arg(2))
		msg, err := hex.DecodeString(arg(3))
		check(err)
		sig, err := hex.DecodeString(arg(4))
		check(err)
		if !mldsa65.Verify(pub, msg, nil, sig) {
			die("verify failed")
		}
		fmt.Println("ok")
	default:
		die("unknown subcommand: " + os.Args[1])
	}
}

func decapKey(seedHex string) *mlkem.DecapsulationKey768 {
	seed, err := hex.DecodeString(seedHex)
	check(err)
	dk, err := mlkem.NewDecapsulationKey768(seed)
	check(err)
	return dk
}

func mldsaKeys(seedHex string) (*mldsa65.PublicKey, *mldsa65.PrivateKey) {
	seedBytes, err := hex.DecodeString(seedHex)
	check(err)
	if len(seedBytes) != mldsa65.SeedSize {
		die(fmt.Sprintf("mldsa seed must be %d bytes (got %d)", mldsa65.SeedSize, len(seedBytes)))
	}
	var seed [mldsa65.SeedSize]byte
	copy(seed[:], seedBytes)
	return mldsa65.NewKeyFromSeed(&seed)
}

func mldsaPub(pubHex string) *mldsa65.PublicKey {
	pubBytes, err := hex.DecodeString(pubHex)
	check(err)
	pub := new(mldsa65.PublicKey)
	check(pub.UnmarshalBinary(pubBytes))
	return pub
}

func arg(i int) string {
	if len(os.Args) <= i {
		die("missing argument")
	}
	return os.Args[i]
}

func check(err error) {
	if err != nil {
		die(err.Error())
	}
}

func die(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(1)
}
