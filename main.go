package main

import (
	"fmt"

	"github.com/slipe-fun/skid/pkg/identity"
	"github.com/slipe-fun/skid/pkg/protocol"
)

func main() {
	alicePrivateKeys, alicePublicKeys, err := identity.NewUser()
	if err != nil {
		panic(err)
	}

	bobPrivateKeys, bobPublicKeys, err := identity.NewUser()
	if err != nil {
		panic(err)
	}

	encrypted, err := protocol.Encrypt(
		"Hello",
		alicePublicKeys,
		alicePrivateKeys,
		bobPublicKeys,
		identity.LongTermIdentityHash(bobPublicKeys),
	)
	if err != nil {
		panic(err)
	}

	decrypted, err := protocol.Decrypt(
		encrypted,
		bobPublicKeys,
		bobPrivateKeys,
		alicePublicKeys,
		false,
		identity.LongTermIdentityHash(alicePublicKeys),
	)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Decrypted message: %s\n", string(decrypted))
}
