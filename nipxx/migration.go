package nipxx

import (
	"crypto/sha256"
	"fmt"
	"strconv"
	"encoding/json"
	"encoding/hex"

	"github.com/nbd-wtf/go-nostr"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

type MigrationKeys struct {
	Threshold int
	PubKeys []string
}

func (k *MigrationKeys) MarshalJSON() ([]byte, error) {
	arr := make([]string, 0, 1 + len(k.PubKeys))
	arr = append(arr, strconv.Itoa(k.Threshold))

	for _, key := range k.PubKeys {
		arr = append(arr, key)
	}

	return json.Marshal(arr)
}

func (k *MigrationKeys) UnmarshalJSON(input []byte) error {
	arr := []interface{}{}
	json.Unmarshal(input, &arr)

	if len(arr) <= 1 {
		return fmt.Errorf("not enough values")
	}

	switch val := arr[0].(type) {
	case float64:
		k.Threshold = int(val)
	case string:
		t, err := strconv.ParseInt(val, 10, 64)
		if err != nil {
			return err
		}
		k.Threshold = int(t)
	default:
		fmt.Errorf("must include threshold number")
	}

	for _, key := range arr[1:] {
		switch val := key.(type) {
		case string:
			if len(val) != 64 {
				return fmt.Errorf("pubkey must be 32-bytes")
			}
			k.PubKeys = append(k.PubKeys, val)
		default:
			fmt.Errorf("pubkey must be a string")
		}
	}

	return nil
}

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
