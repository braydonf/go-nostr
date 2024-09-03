package nipxx

import (
	"errors"
)

const (
	// Regular events (last numbers match corresponding attestations).
	KindKeyMigration int = 50
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
	ForPubKey string
	RecoveryKeysSetupId string
	RecoveryKeysSetup string
}

func MakeRecoveryKeysSetup(
	pubkeys [] string,
	threshold int,
	comment string,
) (error, *RecoveryKeysSetup) {
	 if threshold == 0 {
		 return errors.New("Threshold must not be zero."), nil
	 }

	setup := &RecoveryKeysSetup{
		RecoveryPubKeys: pubkeys,
		Threshold: threshold,
		Comment: comment,
	}

	return nil, setup
}
