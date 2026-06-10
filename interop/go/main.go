// Cross-implementation interop driver: exercises ML-KEM-768 via Go's
// standard library (crypto/mlkem, FIPS 203) so CI can prove the .NET
// backends (BouncyCastle and native) agree with an independent
// implementation. See interop/README.md and .github/workflows/interop.yml.
package main

import (
	"crypto/mlkem"
	"encoding/hex"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		die("usage: interop <mlkem-pubkey|mlkem-encap|mlkem-decap> args...")
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
