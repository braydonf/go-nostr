package nipxx

import (
	"crypto/sha256"
	"fmt"
	"strconv"
	"encoding/json"
	"encoding/hex"
	"encoding/base64"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip44"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

const (
	// Regular events.
	KindKeyMigrationAndRevocation int = 50
	KindRecoveryKeysSetup int = 51

	// Parameterized replaceable events (pubkey:kind:d-tag).
	KindKeyMigrationAttestation int = 30050
	KindRecoveryKeysAttestation int = 30051
)

const (
	SafeguardKeyMigration string = "key-migration"
	SafeguardKeyRevocation string = "key-revocation"
	SafeguardKeyMigrationAttestation string = "key-migration-attestation"
	SafeguardRecoveryKeysSetup string = "recovery-keys-setup"
	SafeguardRecoveryKeysAttestation string = "recovery-keys-attestation"
)

type KeyMigrationAndRevocation struct {
	PubKey string
	NewPubKey string
	RecoveryKeysSetupID string
	Comment string
}

type KeyMigrationAttestation struct {
	EncryptKey []byte
	EncryptSalt []byte
	ForPubKey string
	NewPubKey string
	KeyMigrationAndRevocationId string
}

type RecoveryKeysSetup struct {
	RecoveryPubKeys []string
	Threshold int
	Comment string
}

type RecoveryKeysAttestation struct {
	EncryptKey []byte
	EncryptSalt []byte
	ForPubKey string
	SetupID string
	SetupEvent string
}

func MakeKeyMigrationAndRevocation(
	pubKey string,
	newPubKey string,
	recoveryKeysSetupID string,
	comment string) *KeyMigrationAndRevocation {

	migration := &KeyMigrationAndRevocation{
		PubKey: pubKey,
		NewPubKey: newPubKey,
		RecoveryKeysSetupID: recoveryKeysSetupID,
		Comment: comment,
	}

	return migration
}

func MakeKeyMigrationAndRevocationEvent(
	migration *KeyMigrationAndRevocation,
	createdAt nostr.Timestamp) *nostr.Event {

	evt := nostr.Event{}
	evt.CreatedAt = createdAt
	evt.Kind = KindKeyMigrationAndRevocation
	evt.PubKey = migration.PubKey
	evt.Content = migration.Comment

	if len(migration.NewPubKey) > 0 {
		evt.Tags = make([]nostr.Tag, 0, 3)
		evt.Tags = evt.Tags.AppendUnique(nostr.Tag{"new-key", migration.NewPubKey})
		evt.Tags = evt.Tags.AppendUnique(nostr.Tag{"e", migration.RecoveryKeysSetupID})
		evt.Tags = evt.Tags.AppendUnique(nostr.Tag{SafeguardKeyMigration})
	} else {
		evt.Tags = evt.Tags.AppendUnique(nostr.Tag{SafeguardKeyRevocation})
	}

	return &evt
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

func ValidateKeyMigrationAndRevocationEvent(evt *nostr.Event) error {
	// Check the kind.
	if evt.Kind != KindKeyMigrationAndRevocation {
		return fmt.Errorf("invalid kind")
	}

	newKey := evt.Tags.GetAll([]string{"new-key"})

	// There are two paths, one with a new-key and another without.
	// If there is a new-key then this is a migration and revocation, if there
	// isn't then this is only a revocation.
	if len(newKey) > 0 {
		if len(newKey) > 1 {
			return fmt.Errorf("must only include one new key")
		}

		// Check the safeguard for a key migration as a new key is
		// included with the event.
		safeguardLength := len(evt.Tags.GetAll([]string{"key-migration"}))
		if safeguardLength < 1 || safeguardLength > 1 {
			return fmt.Errorf("must include migration safeguard tag")
		}
	} else {
		safeguardLength := len(evt.Tags.GetAll([]string{"key-revocation"}))
		if safeguardLength < 1 || safeguardLength > 1 {
			return fmt.Errorf("must include revocation safeguard tag")
		}
	}

	return nil
}

func MakeRecoveryKeysAttestation(
	encryptKey []byte,
	encryptSalt []byte,
	forPubKey string,
	setupID string,
	setupEvent string,
) *RecoveryKeysAttestation {
	attestation := &RecoveryKeysAttestation{
		EncryptKey: encryptKey,
		EncryptSalt: encryptSalt,
		ForPubKey: forPubKey,
		SetupID: setupID,
		SetupEvent: setupEvent,
	}

	return attestation
}

func MakeRecoveryKeysAttestationEvent(
	attestation *RecoveryKeysAttestation,
	createdAt nostr.Timestamp) (*nostr.Event, error) {

	evt := nostr.Event{}
	evt.CreatedAt = createdAt
	evt.Kind = KindRecoveryKeysAttestation

	if len(attestation.EncryptKey) > 0 {
		// Public safeguard tag.
		evt.Tags = make([]nostr.Tag, 0, 2)

		// Deterministic private d-tag.
		cypherpub, err := nip44.Encrypt(
			attestation.ForPubKey,
			attestation.EncryptKey,
			nip44.WithCustomSalt(attestation.EncryptSalt))

		if err != nil {
			return nil, err
		}

		cypherbytes, err := base64.StdEncoding.DecodeString(cypherpub)

		if err != nil {
			return nil, err
		}

		cyphersum := fmt.Sprintf("%x", sha256.Sum256(cypherbytes))

		evt.Tags = evt.Tags.AppendUnique(nostr.Tag{"d", cyphersum})

		// Private tags.
		ptags := nostr.Tags(make([]nostr.Tag, 0, 3))
		ptags = ptags.AppendUnique(nostr.Tag{"p", attestation.ForPubKey})
		ptags = ptags.AppendUnique(nostr.Tag{"e", attestation.SetupID})
		ptags = ptags.AppendUnique(nostr.Tag{"setup", attestation.SetupEvent})

		tagsJSON, err := json.Marshal(ptags)
		if err != nil {
			return nil, err
		}

		cyphertext, err := nip44.Encrypt(
			string(tagsJSON),
			attestation.EncryptKey,
			nip44.WithCustomSalt(attestation.EncryptSalt))

		if err != nil {
			return nil, err
		}

		evt.Content = cyphertext
	} else {
		// Public tags for all.
		evt.Tags = make([]nostr.Tag, 0, 5)
		evt.Tags = evt.Tags.AppendUnique(nostr.Tag{"d", attestation.ForPubKey})
		evt.Tags = evt.Tags.AppendUnique(nostr.Tag{"p", attestation.ForPubKey})
		evt.Tags = evt.Tags.AppendUnique(nostr.Tag{"e", attestation.SetupID})
		evt.Tags = evt.Tags.AppendUnique(nostr.Tag{"setup", attestation.SetupEvent})
	}

	evt.Tags = evt.Tags.AppendUnique(nostr.Tag{SafeguardRecoveryKeysAttestation})

	return &evt, nil
}

func ValidateRecoveryKeysAttestationEvent(evt *nostr.Event) error {
	// Check the kind.
	if evt.Kind != KindRecoveryKeysAttestation {
		return fmt.Errorf("invalid kind")
	}

	// Check the safeguard tag to verify that it has
	// been included correctly.
	safeguard := evt.Tags.GetAll([]string{SafeguardRecoveryKeysAttestation})

	if len(safeguard) != 1 {
		return fmt.Errorf("must include one safeguard tag")
	}

	if len(safeguard[0]) != 1 {
		return fmt.Errorf("safeguard must not include a value")
	}

	// Must include one d tag.
	lenDtags := len(evt.Tags.GetAll([]string{"d"}))
	if lenDtags == 0 || lenDtags > 1 {
		return fmt.Errorf("must include one d tag")
	}

	if len(evt.Content) > 0 {
		// If content is non-empty (private), public tags must not be included.
		if len(evt.Tags.GetAll([]string{"p"})) > 0 ||
			len(evt.Tags.GetAll([]string{"e"})) > 0 ||
			len(evt.Tags.GetAll([]string{"setup"})) > 0 {
			return fmt.Errorf("private attestation must not include public tags")
		}

		// Content, if available, must be base64 encoded.
		_, err := base64.StdEncoding.DecodeString(evt.Content)
		if err != nil {
			return fmt.Errorf("private content must be base64")
		}
	} else {
		if len(evt.Tags.GetAll([]string{"p"})) == 0 ||
			len(evt.Tags.GetAll([]string{"e"})) == 0 ||
			len(evt.Tags.GetAll([]string{"setup"})) == 0 {
			return fmt.Errorf("public attestation must include public tags")
		}
	}

	return nil
}

func MakeRecoveryKeysSetupEvent(
	setup *RecoveryKeysSetup,
	createdAt nostr.Timestamp) *nostr.Event {

	evt := nostr.Event{}
	evt.CreatedAt = createdAt
	evt.Kind = KindRecoveryKeysSetup

	evt.Tags = make([]nostr.Tag, 0, len(setup.RecoveryPubKeys) + 2)

	for _, pubkey := range setup.RecoveryPubKeys {
		evt.Tags = evt.Tags.AppendUnique(nostr.Tag{"p", pubkey})
	}

	evt.Tags = evt.Tags.AppendUnique(nostr.Tag{"threshold", fmt.Sprintf("%d", setup.Threshold)})
	evt.Tags = evt.Tags.AppendUnique(nostr.Tag{SafeguardRecoveryKeysSetup})

	evt.Content = setup.Comment

	return &evt
}

func MakeRecoveryKeysSetup(
	pubkeys [] string,
	threshold int,
	comment string,
) *RecoveryKeysSetup {
	setup := &RecoveryKeysSetup{
		RecoveryPubKeys: pubkeys,
		Threshold: threshold,
		Comment: comment,
	}

	return setup
}

// ValidateRecoveryKeysEvent validates that the event
// has all of the required and necessary properties
// to be considered valid. It does not include pubkey, sig
// or created_at validation.
func ValidateRecoveryKeysEvent(evt *nostr.Event) error {
	// Check the kind.
	if evt.Kind != KindRecoveryKeysSetup {
		return fmt.Errorf("invalid kind")
	}

	// Check the safeguard tag to verify that it has
	// been included correctly.
	safeguard := evt.Tags.GetAll([]string{SafeguardRecoveryKeysSetup})

	if len(safeguard) != 1 {
		return fmt.Errorf("must include one safeguard tag")
	}

	if len(safeguard[0]) != 1 {
		return fmt.Errorf("safeguard must not include a value")
	}

	// Check that the threshold tag has been included
	// and has a valid value.
	thresholds := evt.Tags.GetAll([]string{"threshold"})

	if len(thresholds) != 1 {
		return fmt.Errorf("must include one threshold tag")
	}

	if len(thresholds[0]) != 2 {
		return fmt.Errorf("threshold tag must include only one value")
	}

	threshold, err := strconv.Atoi(thresholds[0][1])

	if err != nil {
		return fmt.Errorf("threshold tag value must be an integer")
	}

	if threshold <= 0 {
		return fmt.Errorf("threshold tag value must be a non-zero positive integer")
	}

	// Check that, at a minimum, one recovery pubkey has been included
	// and that it has a valid value.
	pubkeys := evt.Tags.GetAll([]string{"p"})

	if len(pubkeys) < 1 {
		return fmt.Errorf("must include one or more recovery pubkeys")
	}

	return nil
}
