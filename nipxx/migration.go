package nipxx

import (
	"crypto/sha256"
	"fmt"
	"encoding/json"
	"encoding/hex"

	"github.com/nbd-wtf/go-nostr"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

func EventSignExternal(
	evt *nostr.Event,
	privateKey string,
	signOpts ...schnorr.SignOption) (string, error) {

	s, err := hex.DecodeString(privateKey)
	if err != nil {
		return "", fmt.Errorf("invalid private key")
	}

	if len(evt.PubKey) == 0 {
		return "", fmt.Errorf("event missing public key")
	}

	if evt.Tags == nil {
		evt.Tags = make(nostr.Tags, 0)
	}

	sk, _ := btcec.PrivKeyFromBytes(s)

	h := sha256.Sum256(evt.Serialize())
	sig, err := schnorr.Sign(sk, h[:], signOpts...)
	if err != nil {
		return "", err
	}

	hex := hex.EncodeToString(sig.Serialize())

	return hex, nil
}

func EventVerifySignatureExternal(evt *nostr.Event, pubkey string, sig string) (bool, error) {
	evtDuplicate, err := duplicateEventWithoutTag(evt, []string{"sigs"})
	if err != nil {
		return false, err
	}

	// Read and check pubkey.
	pk, err := hex.DecodeString(pubkey)
	if err != nil {
		return false, fmt.Errorf("invalid pubkey hex")
	}

	schnorrPubKey, err := schnorr.ParsePubKey(pk)
	if err != nil {
		return false, fmt.Errorf("invalid pubkey")
	}

	// Read signature.
	s, err := hex.DecodeString(sig)
	if err != nil {
		return false, fmt.Errorf("invalid signature")
	}
	schnorrSig, err := schnorr.ParseSignature(s)
	if err != nil {
		return false, fmt.Errorf("invalid signature")
	}

	// Check signature.
	hash := sha256.Sum256(evtDuplicate.Serialize())
	return schnorrSig.Verify(hash[:], schnorrPubKey), nil
}

func EventAddMigrationSignatures(evt *nostr.Event, sigs []string) *nostr.Event {
	tag := nostr.Tag{"sigs"}

	for _, sig := range sigs {
		tag = append(tag, sig)
	}

	evt.Tags = evt.Tags.AppendUnique(tag)

	return evt
}

func duplicateEventWithoutTag(evt *nostr.Event, prefix []string) (*nostr.Event, error) {
	tmp, err := json.Marshal(evt)
	if err != nil {
		return nil, err
	}

	var duplicate nostr.Event
	err = json.Unmarshal(tmp, &duplicate)
	if err != nil {
		return nil, err
	}

	duplicate.Tags = duplicate.Tags.FilterOut([]string{"sigs"})

	return &duplicate, nil
}
