package nipxx

import (
	"errors"
	"fmt"
	"strconv"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip44"
)

const (
	// Regular events.
	KindKeyMigration int = 50
	KindKeyMigrationAttestation int = 30050

	// Parameterized replaceable events (pubkey:kind:d-tag).
	KindRecoveryKeysSetup int = 51
	KindRecoveryKeysAttestation int = 30051
)

const (
	SafeguardKeyMigration string = "key-migration"
	SafeguardKeyRevocation string = "key-revocation"
	SafeguardKeyMigrationAttestation string = "key-migration-attestation"
	SafeguardRecoveryKeysSetup string = "recovery-keys-setup"
	SafeguardRecoveryKeysAttestation string = "recovery-keys-attestation"
)

type KeyMigration struct {
	ID string
	OldPubKey string
	NewPubKey string
	RecoveryKeysSetupId string
	RecoveryKeysSetupEvent string
	RecoveryKeysSignatures string
}

type KeyMigrationAttestation struct {
	OldPubKey string
	NewPubKey string
	KeyMigrationId string
	KeyMigration string
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
		evt.Tags = make([]nostr.Tag, 0, 1)
	} else {
		evt.Tags = make([]nostr.Tag, 0, 3)
		evt.Tags = evt.Tags.AppendUnique(nostr.Tag{"p", attestation.ForPubKey})
		evt.Tags = evt.Tags.AppendUnique(nostr.Tag{"e", attestation.SetupID})
	}

	evt.Tags = evt.Tags.AppendUnique(nostr.Tag{SafeguardRecoveryKeysAttestation})

	if len(attestation.EncryptKey) > 0 {
		cyphertext, err := nip44.Encrypt(
			attestation.SetupEvent,
			attestation.EncryptKey,
			nip44.WithCustomSalt(attestation.EncryptSalt))

		if err != nil {
			return nil, err
		}
		evt.Content = cyphertext
	} else {
		evt.Content = attestation.SetupEvent
	}

	return &evt, nil
}

func ValidateRecoveryKeysAttestationEvent(evt *nostr.Event) error {
	// Check the kind.
	if evt.Kind != KindRecoveryKeysAttestation {
		return errors.New("Invalid kind.")
	}

	// Check the safeguard tag to verify that it has
	// been included correctly.
	safeguard := evt.Tags.GetAll([]string{SafeguardRecoveryKeysAttestation})

	if len(safeguard) != 1 {
		return errors.New("Must include one safeguard tag.")
	}

	if len(safeguard[0]) != 1 {
		return errors.New("Safeguard must not include a value.")
	}

	// Content should not be empty.
	if len(evt.Content) == 0 {
		return errors.New("Content should not be empty.")
	}

	// Content should be encrypted (base64) if missing the `p` tag (private).

	// Content should be plaintext if the `p`tag is included (public).

	return nil
}

func MakeRecoveryKeysSetupEvent(setup *RecoveryKeysSetup, createdAt nostr.Timestamp) *nostr.Event {
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
		return errors.New("Invalid kind.")
	}

	// Check the safeguard tag to verify that it has
	// been included correctly.
	safeguard := evt.Tags.GetAll([]string{SafeguardRecoveryKeysSetup})

	if len(safeguard) != 1 {
		return errors.New("Must include one safeguard tag.")
	}

	if len(safeguard[0]) != 1 {
		return errors.New("Safeguard must not include a value.")
	}

	// Check that the threshold tag has been included
	// and has a valid value.
	thresholds := evt.Tags.GetAll([]string{"threshold"})

	if len(thresholds) != 1 {
		return errors.New("Must include one threshold tag.")
	}

	if len(thresholds[0]) != 2 {
		return errors.New("Threshold tag must include only one value.")
	}

	threshold, err := strconv.Atoi(thresholds[0][1])

	if err != nil {
		return errors.New("Threshold tag value must be an integer.")
	}

	if threshold <= 0 {
		return errors.New("Threshold tag value must be a non-zero positive integer.")
	}

	// Check that, at a minimum, one recovery pubkey has been included
	// and that it has a valid value.
	pubkeys := evt.Tags.GetAll([]string{"p"})

	if len(pubkeys) < 1 {
		return errors.New("Must include one or more recovery pubkeys.")
	}

	return nil
}
