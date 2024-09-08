package nipxx

import (
	"testing"
	"encoding/json"
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"github.com/nbd-wtf/go-nostr"
	"github.com/btcsuite/btcd/btcec/v2"
)

func TestMakeKeyMigrationAndRevocation(t *testing.T) {
	for _, vector := range []struct {
		PubKey string
		NewPubKey string
		RecoveryKeysSetupID string
		Comment string
	}{
		{
			"0000000000000000000000000000000000000000000000000000000000000000",
			"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			"1111111111111111111111111111111111111111111111111111111111111111",
			"This is an optional comment.",
		},
		{
			"0000000000000000000000000000000000000000000000000000000000000000",
			"",
			"1111111111111111111111111111111111111111111111111111111111111111",
			"There is no migration here, just a revocation.",
		},
	} {
		migration := MakeKeyMigrationAndRevocation(
			vector.PubKey,
			vector.NewPubKey,
			vector.RecoveryKeysSetupID,
			vector.Comment)

		assert.Equal(t, vector.PubKey, migration.PubKey)
		assert.Equal(t, vector.NewPubKey, migration.NewPubKey)
		assert.Equal(t, vector.RecoveryKeysSetupID, migration.RecoveryKeysSetupID)
		assert.Equal(t, vector.Comment, migration.Comment)
	}
}

func TestMakeKeyMigrationAndRevocationEvent(t *testing.T) {
	for _, vector := range []struct {
		PrivateKey string
		NewPubKey string
		Timestamp int64
		Comment string
		RecoveryKeysSetupID string
		RecoveryPrivateKeys []string
		ExpectedJSON string
	}{
		{
			"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
			int64(1725402774),
			"This is an optional comment.",
			"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
			[]string{
				"4fe17162aa42c96d7757f98cabc8a0b38ceb61a9160195b5d16bce6f6d8064ca",
				"8b57adf363f3abed31ea6e0b664884af07e2a92611154599345f6a63f9c70f02",
				"741a0fb3d23db2c87f82a9a979084893c3f094c47776c1283dd313331fc4b308",
			},
			"{\"kind\":50,\"id\":\"65d607fc433a642d3afd1ef945fa8d8b7738b5cc4a4ed46e416c1662e78f8ce0\",\"pubkey\":\"9166c289b9f905e55f9e3df9f69d7f356b4a22095f894f4715714aa4b56606af\",\"created_at\":1725402774,\"tags\":[[\"new-key\",\"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\"],[\"e\",\"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\"],[\"key-migration\"],[\"sigs\",\"439960df010db03e6147665ca589954b34ab38d16e5d74dfa1b98d4c5b3b54186ef327e1a0dcd910bc76119dc4bdbe51d235672c28ec652b35a42e363ceae565\",\"ca7b4a94be3f19161cc61dc896ab4210315abe982c52fa5ee1b53fae8ce8ea0b0c19afea5090aef4f96668bdf821ddd7deb50ecaa12ec44f563c34e4b7d6990c\",\"5751e438fb4d922dbba239868aa9248001a1209a6d9a17689bda40086540d41a831e230e3d7b27ef4b35380ebd4080337bbf41d2b98a1a02e66f8d6b13795198\"]],\"content\":\"This is an optional comment.\",\"sig\":\"b16baac3250c83aa02ebe51c08580c7f37a98ac36d40b1d2750b760fe45be34e5fce007e0675e72f92bb98205f8ea409a27ac44ee7b4578877723fe12c55fb65\"}",
		},
	} {
		s, err := hex.DecodeString(vector.PrivateKey)
		assert.Nil(t, err)
		_, pubkey := btcec.PrivKeyFromBytes(s)

		// Make the migration event.
		migration := MakeKeyMigrationAndRevocation(
			hex.EncodeToString(pubkey.SerializeCompressed()),
			vector.NewPubKey,
			vector.RecoveryKeysSetupID,
			vector.Comment)

		evt := MakeKeyMigrationAndRevocationEvent(migration, nostr.Timestamp(vector.Timestamp))
		assert.NotNil(t, evt)

		// Sign the event with all of the recovery keys.
		lenSigs := len(vector.RecoveryPrivateKeys)
		sigs := make([]string, lenSigs, lenSigs)
		for i, privateKey := range vector.RecoveryPrivateKeys {
			sig, err := EventSignExternal(evt, privateKey)
			assert.Nil(t, err)
			assert.NotEqual(t, sig, "")
			sigs[i] = sig
		}

		// Add the sigs tag with all of the recovery signatures.
		EventAddMigrationSignatures(evt, sigs)

		// Sign the event.
		err = evt.Sign(vector.PrivateKey)
		assert.Nil(t, err)

		// Verify the event is correctly constructed.
		evtjson, err := json.Marshal(evt)

		assert.Nil(t, err)
		assert.Equal(t, vector.ExpectedJSON, string(evtjson))
	}
}

func TestValidateKeyMigrationAndRevocationEvent(t *testing.T) {
	for _, vector := range []struct {
		JSON string
		ExpectedError string
	}{
		{
			"{\"kind\":50,\"pubkey\":\"9166c289b9f905e55f9e3df9f69d7f356b4a22095f894f4715714aa4b56606af\",\"created_at\":1725402774,\"tags\":[[\"new-key\",\"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\"],[\"e\",\"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\"],[\"key-migration\"],[\"sigs\",\"439960df010db03e6147665ca589954b34ab38d16e5d74dfa1b98d4c5b3b54186ef327e1a0dcd910bc76119dc4bdbe51d235672c28ec652b35a42e363ceae565\",\"ca7b4a94be3f19161cc61dc896ab4210315abe982c52fa5ee1b53fae8ce8ea0b0c19afea5090aef4f96668bdf821ddd7deb50ecaa12ec44f563c34e4b7d6990c\",\"5751e438fb4d922dbba239868aa9248001a1209a6d9a17689bda40086540d41a831e230e3d7b27ef4b35380ebd4080337bbf41d2b98a1a02e66f8d6b13795198\"]],\"content\":\"This is an optional comment.\"}",
			"",
		},
		{
			"{\"kind\":49,\"pubkey\":\"9166c289b9f905e55f9e3df9f69d7f356b4a22095f894f4715714aa4b56606af\",\"created_at\":1725402774,\"tags\":[[\"new-key\",\"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\"],[\"e\",\"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\"],[\"key-migration\"],[\"sigs\",\"439960df010db03e6147665ca589954b34ab38d16e5d74dfa1b98d4c5b3b54186ef327e1a0dcd910bc76119dc4bdbe51d235672c28ec652b35a42e363ceae565\",\"ca7b4a94be3f19161cc61dc896ab4210315abe982c52fa5ee1b53fae8ce8ea0b0c19afea5090aef4f96668bdf821ddd7deb50ecaa12ec44f563c34e4b7d6990c\",\"5751e438fb4d922dbba239868aa9248001a1209a6d9a17689bda40086540d41a831e230e3d7b27ef4b35380ebd4080337bbf41d2b98a1a02e66f8d6b13795198\"]],\"content\":\"This is an optional comment.\"}",
			"Invalid kind.",
		},
		{
			"{\"kind\":50,\"pubkey\":\"9166c289b9f905e55f9e3df9f69d7f356b4a22095f894f4715714aa4b56606af\",\"created_at\":1725402774,\"tags\":[[\"new-key\",\"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\"],[\"e\",\"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\"],[\"sigs\",\"439960df010db03e6147665ca589954b34ab38d16e5d74dfa1b98d4c5b3b54186ef327e1a0dcd910bc76119dc4bdbe51d235672c28ec652b35a42e363ceae565\",\"ca7b4a94be3f19161cc61dc896ab4210315abe982c52fa5ee1b53fae8ce8ea0b0c19afea5090aef4f96668bdf821ddd7deb50ecaa12ec44f563c34e4b7d6990c\",\"5751e438fb4d922dbba239868aa9248001a1209a6d9a17689bda40086540d41a831e230e3d7b27ef4b35380ebd4080337bbf41d2b98a1a02e66f8d6b13795198\"]],\"content\":\"This is an optional comment.\"}",
			"Must include migration safeguard tag.",
		},
		{
			"{\"kind\":50,\"pubkey\":\"9166c289b9f905e55f9e3df9f69d7f356b4a22095f894f4715714aa4b56606af\",\"created_at\":1725402774,\"tags\":[[\"key-migration\"]],\"content\":\"This is an optional comment.\"}",
			"Must include revocation safeguard tag.",
		},
		{
			"{\"kind\":50,\"pubkey\":\"9166c289b9f905e55f9e3df9f69d7f356b4a22095f894f4715714aa4b56606af\",\"created_at\":1725402774,\"tags\":[[\"key-revocation\"]],\"content\":\"This is an optional comment.\"}",
			"",
		},
	} {
		var evt nostr.Event
		err := json.Unmarshal([]byte(vector.JSON), &evt)
		assert.Nil(t, err)

		err = ValidateKeyMigrationAndRevocationEvent(&evt)

		if vector.ExpectedError == "" {
			// Valid
			assert.Nil(t, err)
		} else {
			// Invalid
			assert.NotNil(t, err)
			assert.EqualErrorf(t, err, vector.ExpectedError, "Error message: %s", err)
		}
	}
}

func TestMakeRecoveryKeysSetup(t *testing.T) {
	for _, vector := range []struct {
		PubKeys []string
		Threshold  int
		Comment string
	} {
		{[]string{"4fe17162aa42c96d7757f98cabc8a0b38ceb61a9160195b5d16bce6f6d8064ca", "8b57adf363f3abed31ea6e0b664884af07e2a92611154599345f6a63f9c70f02", "741a0fb3d23db2c87f82a9a979084893c3f094c47776c1283dd313331fc4b308"}, 2, "Setting up my first set of recovery keys! Yay!"},
		{[]string{"4fe17162aa42c96d7757f98cabc8a0b38ceb61a9160195b5d16bce6f6d8064ca", "8b57adf363f3abed31ea6e0b664884af07e2a92611154599345f6a63f9c70f02", "741a0fb3d23db2c87f82a9a979084893c3f094c47776c1283dd313331fc4b308"}, 0, "Doing something illogical!"},
	} {
		setup := MakeRecoveryKeysSetup(vector.PubKeys, vector.Threshold, vector.Comment)

		assert.Equal(t, setup.Comment, vector.Comment)
		assert.Equal(t, setup.RecoveryPubKeys, vector.PubKeys)
		assert.Equal(t, setup.Threshold, vector.Threshold)
	}
}

func TestMakeRecoveryKeysSetupEvent(t *testing.T) {
	for _, vector := range []struct {
		PrivateKey string
		Timestamp int64
		PubKeys []string
		Threshold  int
		Comment string
		ExpectedJSON string
	}{
		{
			"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			int64(1725402764),
			[]string{
				"4fe17162aa42c96d7757f98cabc8a0b38ceb61a9160195b5d16bce6f6d8064ca",
				"8b57adf363f3abed31ea6e0b664884af07e2a92611154599345f6a63f9c70f02",
				"741a0fb3d23db2c87f82a9a979084893c3f094c47776c1283dd313331fc4b308",
			},
			2,
			"Setting up my first set of recovery keys! Yay!",
			"{\"kind\":51,\"id\":\"40808ce2685b0aeaa756d05fc99853db0c79043210a3a949fdbc905ea2984c05\",\"pubkey\":\"9166c289b9f905e55f9e3df9f69d7f356b4a22095f894f4715714aa4b56606af\",\"created_at\":1725402764,\"tags\":[[\"p\",\"4fe17162aa42c96d7757f98cabc8a0b38ceb61a9160195b5d16bce6f6d8064ca\"],[\"p\",\"8b57adf363f3abed31ea6e0b664884af07e2a92611154599345f6a63f9c70f02\"],[\"p\",\"741a0fb3d23db2c87f82a9a979084893c3f094c47776c1283dd313331fc4b308\"],[\"threshold\",\"2\"],[\"recovery-keys-setup\"]],\"content\":\"Setting up my first set of recovery keys! Yay!\",\"sig\":\"8e73482ffae5261edb5181960a8d50974de468f20ea9f505cb57812e348ee920468dbb390ab39b497e33ac9aa2e6f784305bea831b232585171ab0878c04c4b3\"}",
		},
	} {
		setup := MakeRecoveryKeysSetup(vector.PubKeys, vector.Threshold, vector.Comment)
		evt := MakeRecoveryKeysSetupEvent(setup, nostr.Timestamp(vector.Timestamp))

		evt.Sign(vector.PrivateKey)

		evtjson, err := json.Marshal(evt)

		assert.Nil(t, err)
		assert.Equal(t, vector.ExpectedJSON, string(evtjson))
	}
}

func TestValidateRecoveryKeysEvent(t *testing.T) {
	for _, vector := range []struct {
		JSON string
		ExpectedError string
	}{
		{
			"{\"kind\":49,\"created_at\":1725402764,\"tags\":[[\"p\",\"4fe17162aa42c96d7757f98cabc8a0b38ceb61a9160195b5d16bce6f6d8064ca\"],[\"p\",\"8b57adf363f3abed31ea6e0b664884af07e2a92611154599345f6a63f9c70f02\"],[\"p\",\"741a0fb3d23db2c87f82a9a979084893c3f094c47776c1283dd313331fc4b308\"],[\"threshold\",\"2\"],[\"recovery-keys-setup\"]],\"content\":\"\"}",
			"Invalid kind.",
		},
		{
			"{\"kind\":51,\"created_at\":1725402764,\"tags\":[[\"p\",\"4fe17162aa42c96d7757f98cabc8a0b38ceb61a9160195b5d16bce6f6d8064ca\"],[\"p\",\"8b57adf363f3abed31ea6e0b664884af07e2a92611154599345f6a63f9c70f02\"],[\"p\",\"741a0fb3d23db2c87f82a9a979084893c3f094c47776c1283dd313331fc4b308\"],[\"threshold\",\"2\"],[\"recovery-keys-setup\", \"recovery-keys-setup\"]],\"content\":\"\"}",
			"Safeguard must not include a value.",
		},
		{
			"{\"kind\":51,\"created_at\":1725402764,\"tags\":[[\"p\",\"4fe17162aa42c96d7757f98cabc8a0b38ceb61a9160195b5d16bce6f6d8064ca\"],[\"p\",\"8b57adf363f3abed31ea6e0b664884af07e2a92611154599345f6a63f9c70f02\"],[\"p\",\"741a0fb3d23db2c87f82a9a979084893c3f094c47776c1283dd313331fc4b308\"],[\"threshold\",\"2\"],[\"recovery-keys-setup\"], [\"recovery-keys-setup\"]],\"content\":\"\"}",
			"Must include one safeguard tag.",
		},
		{
			"{\"kind\":51,\"created_at\":1725402764,\"tags\":[[\"p\",\"4fe17162aa42c96d7757f98cabc8a0b38ceb61a9160195b5d16bce6f6d8064ca\"],[\"p\",\"8b57adf363f3abed31ea6e0b664884af07e2a92611154599345f6a63f9c70f02\"],[\"p\",\"741a0fb3d23db2c87f82a9a979084893c3f094c47776c1283dd313331fc4b308\"],[\"threshold\",\"2\"]],\"content\":\"\"}",
			"Must include one safeguard tag.",
		},
		{
			"{\"kind\":51,\"created_at\":1725402764,\"tags\":[[\"p\",\"4fe17162aa42c96d7757f98cabc8a0b38ceb61a9160195b5d16bce6f6d8064ca\"],[\"p\",\"8b57adf363f3abed31ea6e0b664884af07e2a92611154599345f6a63f9c70f02\"],[\"p\",\"741a0fb3d23db2c87f82a9a979084893c3f094c47776c1283dd313331fc4b308\"],[\"threshold\",\"0\"],[\"recovery-keys-setup\"]],\"content\":\"\"}",
			"Threshold tag value must be a non-zero positive integer.",
		},
		{
			"{\"kind\":51,\"created_at\":1725402764,\"tags\":[[\"p\",\"4fe17162aa42c96d7757f98cabc8a0b38ceb61a9160195b5d16bce6f6d8064ca\"],[\"p\",\"8b57adf363f3abed31ea6e0b664884af07e2a92611154599345f6a63f9c70f02\"],[\"p\",\"741a0fb3d23db2c87f82a9a979084893c3f094c47776c1283dd313331fc4b308\"],[\"threshold\",\"-1\"],[\"recovery-keys-setup\"]],\"content\":\"\"}",
			"Threshold tag value must be a non-zero positive integer.",
		},
		{
			"{\"kind\":51,\"created_at\":1725402764,\"tags\":[[\"p\",\"4fe17162aa42c96d7757f98cabc8a0b38ceb61a9160195b5d16bce6f6d8064ca\"],[\"p\",\"8b57adf363f3abed31ea6e0b664884af07e2a92611154599345f6a63f9c70f02\"],[\"p\",\"741a0fb3d23db2c87f82a9a979084893c3f094c47776c1283dd313331fc4b308\"],[\"threshold\",\"wild string\"],[\"recovery-keys-setup\"]],\"content\":\"\"}",
			"Threshold tag value must be an integer.",
		},
		{
			"{\"kind\":51,\"created_at\":1725402764,\"tags\":[[\"p\",\"4fe17162aa42c96d7757f98cabc8a0b38ceb61a9160195b5d16bce6f6d8064ca\"],[\"p\",\"8b57adf363f3abed31ea6e0b664884af07e2a92611154599345f6a63f9c70f02\"],[\"p\",\"741a0fb3d23db2c87f82a9a979084893c3f094c47776c1283dd313331fc4b308\"],[\"recovery-keys-setup\"]],\"content\":\"\"}",
			"Must include one threshold tag.",
		},
		{
			"{\"kind\":51,\"created_at\":1725402764,\"tags\":[[\"p\",\"4fe17162aa42c96d7757f98cabc8a0b38ceb61a9160195b5d16bce6f6d8064ca\"],[\"p\",\"8b57adf363f3abed31ea6e0b664884af07e2a92611154599345f6a63f9c70f02\"],[\"p\",\"741a0fb3d23db2c87f82a9a979084893c3f094c47776c1283dd313331fc4b308\"],[\"threshold\", \"1\", \"1\"],[\"recovery-keys-setup\"]],\"content\":\"\"}",
			"Threshold tag must include only one value.",
		},
		{
			"{\"kind\":51,\"created_at\":1725402764,\"tags\":[[\"p\",\"4fe17162aa42c96d7757f98cabc8a0b38ceb61a9160195b5d16bce6f6d8064ca\"],[\"p\",\"8b57adf363f3abed31ea6e0b664884af07e2a92611154599345f6a63f9c70f02\"],[\"p\",\"741a0fb3d23db2c87f82a9a979084893c3f094c47776c1283dd313331fc4b308\"],[\"threshold\", \"00 00 1 -3\"],[\"recovery-keys-setup\"]],\"content\":\"\"}",
			"Threshold tag value must be an integer.",
		},
		{
			"{\"kind\":51,\"created_at\":1725402764,\"tags\":[[\"threshold\", \"1\"],[\"recovery-keys-setup\"]],\"content\":\"\"}",
			"Must include one or more recovery pubkeys.",
		},
		{
			"{\"kind\":51,\"created_at\":1725402764,\"tags\":[[\"p\",\"4fe17162aa42c96d7757f98cabc8a0b38ceb61a9160195b5d16bce6f6d8064ca\"],[\"threshold\", \"1\"],[\"recovery-keys-setup\"]],\"content\":\"\"}",
			"",
		},
		{
			"{\"kind\":51,\"created_at\":1725402764,\"tags\":[[\"p\",\"4fe17162aa42c96d7757f98cabc8a0b38ceb61a9160195b5d16bce6f6d8064ca\"],[\"p\",\"8b57adf363f3abed31ea6e0b664884af07e2a92611154599345f6a63f9c70f02\"],[\"p\",\"741a0fb3d23db2c87f82a9a979084893c3f094c47776c1283dd313331fc4b308\"],[\"threshold\", \"1\"],[\"recovery-keys-setup\"]],\"content\":\"\"}",
			"",
		},
		{
			"{\"kind\":51,\"created_at\":1725402764,\"tags\":[[\"p\",\"4fe17162aa42c96d7757f98cabc8a0b38ceb61a9160195b5d16bce6f6d8064ca\"],[\"p\",\"8b57adf363f3abed31ea6e0b664884af07e2a92611154599345f6a63f9c70f02\"],[\"p\",\"741a0fb3d23db2c87f82a9a979084893c3f094c47776c1283dd313331fc4b308\"],[\"threshold\", \"5\"],[\"recovery-keys-setup\"]],\"content\":\"\"}",
			"",
		},
	} {
		var evt nostr.Event
		err := json.Unmarshal([]byte(vector.JSON), &evt)
		assert.Nil(t, err)

		err = ValidateRecoveryKeysEvent(&evt)

		if vector.ExpectedError == "" {
			// Valid
			assert.Nil(t, err)
		} else {
			// Invalid
			assert.NotNil(t, err)
			assert.EqualErrorf(t, err, vector.ExpectedError, "Error message: %s", err)
		}
	}
}

func TestMakeRecoveryKeysAttestation(t *testing.T) {
	for _, vector := range []struct {
		EncryptKey string
		EncryptSalt string
		ForPubKey  string
		SetupID string
		SetupEvent string
	}{
		{
			"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			"0000000000000000000000000000000000000000000000000000000000000000",
			"9166c289b9f905e55f9e3df9f69d7f356b4a22095f894f4715714aa4b56606af",
			"40808ce2685b0aeaa756d05fc99853db0c79043210a3a949fdbc905ea2984c05",
			"{\"kind\":52,\"id\":\"2e9857c30aa364c83d769e7fa6e18bd7975fe58f2bcdb487f8e5289e60b216f2\",\"pubkey\":\"9166c289b9f905e55f9e3df9f69d7f356b4a22095f894f4715714aa4b56606af\",\"created_at\":1725402764,\"tags\":[[\"p\",\"4fe17162aa42c96d7757f98cabc8a0b38ceb61a9160195b5d16bce6f6d8064ca\"],[\"p\",\"8b57adf363f3abed31ea6e0b664884af07e2a92611154599345f6a63f9c70f02\"],[\"p\",\"741a0fb3d23db2c87f82a9a979084893c3f094c47776c1283dd313331fc4b308\"],[\"threshold\",\"2\"],[\"recovery-keys-setup\"]],\"content\":\"Setting up my first set of recovery keys! Yay!\",\"sig\":\"fe17c1ec586fbbf68f0588125d4476c28a4d5bfd9948832036fe00559794f2941161aa82605e59632877edbabe62e35c19d28faf1b676ffdb78a977043af663e\"}",
		},
		{
			"",
			"",
			"9166c289b9f905e55f9e3df9f69d7f356b4a22095f894f4715714aa4b56606af",
			"40808ce2685b0aeaa756d05fc99853db0c79043210a3a949fdbc905ea2984c05",
			"{\"kind\":52,\"id\":\"2e9857c30aa364c83d769e7fa6e18bd7975fe58f2bcdb487f8e5289e60b216f2\",\"pubkey\":\"9166c289b9f905e55f9e3df9f69d7f356b4a22095f894f4715714aa4b56606af\",\"created_at\":1725402764,\"tags\":[[\"p\",\"4fe17162aa42c96d7757f98cabc8a0b38ceb61a9160195b5d16bce6f6d8064ca\"],[\"p\",\"8b57adf363f3abed31ea6e0b664884af07e2a92611154599345f6a63f9c70f02\"],[\"p\",\"741a0fb3d23db2c87f82a9a979084893c3f094c47776c1283dd313331fc4b308\"],[\"threshold\",\"2\"],[\"recovery-keys-setup\"]],\"content\":\"Setting up my first set of recovery keys! Yay!\",\"sig\":\"fe17c1ec586fbbf68f0588125d4476c28a4d5bfd9948832036fe00559794f2941161aa82605e59632877edbabe62e35c19d28faf1b676ffdb78a977043af663e\"}",
		},
	} {
		encryptKey, err := hex.DecodeString(vector.EncryptKey)
		assert.Nil(t, err)

		encryptSalt, err := hex.DecodeString(vector.EncryptSalt)
		assert.Nil(t, err)

		attestation := MakeRecoveryKeysAttestation(
			encryptKey,
			encryptSalt,
			vector.ForPubKey,
			vector.SetupID,
			vector.SetupEvent)

		assert.Equal(t, encryptKey, attestation.EncryptKey)
		assert.Equal(t, vector.ForPubKey, attestation.ForPubKey)
		assert.Equal(t, vector.SetupID, attestation.SetupID)
		assert.Equal(t, vector.SetupEvent, attestation.SetupEvent)
	}
}

func TestMakeRecoveryKeyAttestationEvent(t *testing.T) {
	for _, vector := range []struct {
		PrivateKey string
		EncryptKey string
		EncryptSalt string
		ForPubKey string
		SetupID string
		SetupEvent string
		Timestamp int64
		ExpectedJSON string
	}{
		{
			"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
			"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			"0000000000000000000000000000000000000000000000000000000000000000",
			"9166c289b9f905e55f9e3df9f69d7f356b4a22095f894f4715714aa4b56606af",
			"40808ce2685b0aeaa756d05fc99853db0c79043210a3a949fdbc905ea2984c05",
			"{\"kind\":51,\"id\":\"40808ce2685b0aeaa756d05fc99853db0c79043210a3a949fdbc905ea2984c05\",\"pubkey\":\"9166c289b9f905e55f9e3df9f69d7f356b4a22095f894f4715714aa4b56606af\",\"created_at\":1725402764,\"tags\":[[\"p\",\"4fe17162aa42c96d7757f98cabc8a0b38ceb61a9160195b5d16bce6f6d8064ca\"],[\"p\",\"8b57adf363f3abed31ea6e0b664884af07e2a92611154599345f6a63f9c70f02\"],[\"p\",\"741a0fb3d23db2c87f82a9a979084893c3f094c47776c1283dd313331fc4b308\"],[\"threshold\",\"2\"],[\"recovery-keys-setup\"]],\"content\":\"Setting up my first set of recovery keys! Yay!\",\"sig\":\"8e73482ffae5261edb5181960a8d50974de468f20ea9f505cb57812e348ee920468dbb390ab39b497e33ac9aa2e6f784305bea831b232585171ab0878c04c4b3\"}",
			int64(1725402765),
			"{\"kind\":30051,\"id\":\"0aa62d8cff27cc19843c775817ceefacb57c897939aff2439786baeaa31d9826\",\"pubkey\":\"a706ad8f73115f90500266f273f7571df9429a4cfb4bbfbcd825227202dabad1\",\"created_at\":1725402765,\"tags\":[[\"d\",\"442427cc2ef69f8b15b823327b3cd2e94daac101a8ff89c7d3bdbd35bb64e939\"],[\"recovery-keys-attestation\"]],\"content\":\"Av//////////////////////////////////////////ZKqMK1a+YsQxv2pOJvaqQJYCS/nd89hQ+HsMDc0ltpAw8bnHKnl5TiHH9qm3coDsyQTVybJkDch+tl+FlbELRcPkIGqxICUDp5lPzj/u23/+VseJaziv+HU0S6/bS5IAbewdzekaN8H4NNAx/nCWzps0s5cm+PetZkdydJv875Aoh71gWF7u5BFZ1Kr1j8XXnBIzzvBA4kGGzusD0CTyUzZqlXV9OTBzi+1cU0qXR3pRroLCDP3EZ4gemFtK26wqxpg2lIjomkYTcuw8JqX4G2AjcsL9knlqUYKZwBrSe87QgWD3Q0Cy1dBGPmU9OZL6FPpYS7hZMzFWTfvalaoCeCAW1kdFeqIQ2ddX81ksD2QsUFNpLLwQxFKHSpqwgkWq9bpPGxdG8ECV9u218dLuJXFSKFGVVJG2iX8qjIXaBHjkOfmPzuJuho5r1UP7gAopffY7TrZxV1yRaHIXHyGZJDQgbHbi1ssfkq1k9jEbsZlxDM5zwLx1nDYhmob21nR/DhdA8U3OFHvJvzCA5bHBX3nMiY2pYGyNT46WP0anvRpCjezaP/0AD9hkrBqV1eXFeDYkcKKcmAWmvl/AkY+0C7qKxj+L5vAPH6VXBFeZpvTHuovl1ZXS4jHW4su/qV94DaleK55Ddn7zwNsAXCEstCm0TkZmePfkspW8UFe68LQRvbGOheHGpgpUyAxojSB9eMa4F8uQwAYYrf489h+VNy3jQGHRX2z6QXARGo/uHAR7843KCScymyrbWbTCOLXiFhuSI+HS7ag0TXqOw22h+6j7A1KH01E/4ln/EN7v1cOiYv94m5aAiXKVBZVakzwhbZTEsvkc3657h9VZi7Qw0mbwDoSQIyGKX7ZmMKkoRZOaSjbUWbXEZPbh6wnflmnzeP/+qAGhNbB/kzP2G5Nz7YV9kA+f1upnyOG6KXGKJntgn6DIItjU6MuNw2VM3OYdh5DS5xlezQMzx3TJRTo08TAvfEMM/SjoND1TE5PcyhBKXYaBG+eRsEbutc5t4+gqt69W8erzmFRJL3klGJ2kft5RXFD5enrF2om1OXrkaU7o/DKzPy8/38begooZGhXjR0Ruj+ahNHsca6PL0/UQ84AaxpDzZ3lDN0vNSkmEJGrLzxjhqKGYljPMYa6VUgRg2/xvyqB7YUx+m4dUgpSz0bbGdXqHTYab8zLjupPHvxx2FvOdCRYOAygwq0qO/vUWaE/vn78COwPe78BUA8HNOGTA\",\"sig\":\"dd531aa2d853b4a242167d6b8b731b1b7af56ecccb47b7488ebf276ade4dc6fe02e09e3b0fb8545310fe7a89dc0f9c8debbf6897e0d31986e67535ec603e0449\"}",
		},
		{
			"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
			"",
			"",
			"9166c289b9f905e55f9e3df9f69d7f356b4a22095f894f4715714aa4b56606af",
			"40808ce2685b0aeaa756d05fc99853db0c79043210a3a949fdbc905ea2984c05",
			"{\"kind\":51,\"id\":\"40808ce2685b0aeaa756d05fc99853db0c79043210a3a949fdbc905ea2984c05\",\"pubkey\":\"9166c289b9f905e55f9e3df9f69d7f356b4a22095f894f4715714aa4b56606af\",\"created_at\":1725402764,\"tags\":[[\"p\",\"4fe17162aa42c96d7757f98cabc8a0b38ceb61a9160195b5d16bce6f6d8064ca\"],[\"p\",\"8b57adf363f3abed31ea6e0b664884af07e2a92611154599345f6a63f9c70f02\"],[\"p\",\"741a0fb3d23db2c87f82a9a979084893c3f094c47776c1283dd313331fc4b308\"],[\"threshold\",\"2\"],[\"recovery-keys-setup\"]],\"content\":\"Setting up my first set of recovery keys! Yay!\",\"sig\":\"8e73482ffae5261edb5181960a8d50974de468f20ea9f505cb57812e348ee920468dbb390ab39b497e33ac9aa2e6f784305bea831b232585171ab0878c04c4b3\"}",
			int64(1725402765),
			"{\"kind\":30051,\"id\":\"52a0c2eddee6afd6762636f787165f3484985443b5bb94b1f40988e7b9ab3f4c\",\"pubkey\":\"a706ad8f73115f90500266f273f7571df9429a4cfb4bbfbcd825227202dabad1\",\"created_at\":1725402765,\"tags\":[[\"d\",\"9166c289b9f905e55f9e3df9f69d7f356b4a22095f894f4715714aa4b56606af\"],[\"p\",\"9166c289b9f905e55f9e3df9f69d7f356b4a22095f894f4715714aa4b56606af\"],[\"e\",\"40808ce2685b0aeaa756d05fc99853db0c79043210a3a949fdbc905ea2984c05\"],[\"setup\",\"{\\\"kind\\\":51,\\\"id\\\":\\\"40808ce2685b0aeaa756d05fc99853db0c79043210a3a949fdbc905ea2984c05\\\",\\\"pubkey\\\":\\\"9166c289b9f905e55f9e3df9f69d7f356b4a22095f894f4715714aa4b56606af\\\",\\\"created_at\\\":1725402764,\\\"tags\\\":[[\\\"p\\\",\\\"4fe17162aa42c96d7757f98cabc8a0b38ceb61a9160195b5d16bce6f6d8064ca\\\"],[\\\"p\\\",\\\"8b57adf363f3abed31ea6e0b664884af07e2a92611154599345f6a63f9c70f02\\\"],[\\\"p\\\",\\\"741a0fb3d23db2c87f82a9a979084893c3f094c47776c1283dd313331fc4b308\\\"],[\\\"threshold\\\",\\\"2\\\"],[\\\"recovery-keys-setup\\\"]],\\\"content\\\":\\\"Setting up my first set of recovery keys! Yay!\\\",\\\"sig\\\":\\\"8e73482ffae5261edb5181960a8d50974de468f20ea9f505cb57812e348ee920468dbb390ab39b497e33ac9aa2e6f784305bea831b232585171ab0878c04c4b3\\\"}\"],[\"recovery-keys-attestation\"]],\"content\":\"\",\"sig\":\"76fea74ae727fe0038b6da4b2d61f6436c4bd9fd57c262b912879d036f7e63919247ae73dfafc8187c76523a9f78050eec8a55eac650aa8fb3fa73b35f46eace\"}",
		},
	} {

		encryptKey, err := hex.DecodeString(vector.EncryptKey)
		assert.Nil(t, err)
		encryptSalt, err := hex.DecodeString(vector.EncryptKey)
		assert.Nil(t, err)

		attestation := MakeRecoveryKeysAttestation(
			encryptKey,
			encryptSalt,
			vector.ForPubKey,
			vector.SetupID,
			vector.SetupEvent)

		evt, err := MakeRecoveryKeysAttestationEvent(
			attestation,
			nostr.Timestamp(vector.Timestamp))

		assert.Nil(t, err)

		evt.Sign(vector.PrivateKey)

		evtjson, err := json.Marshal(evt)
		assert.Nil(t, err)
		assert.Equal(t, vector.ExpectedJSON, string(evtjson))
	}
}

func TestValidateRecoveryKeysAttestationEvent(t *testing.T) {
	for _, vector := range []struct {
		JSON string
		ExpectedError string
	}{
		{
			"{\"kind\":30051,\"pubkey\":\"a706ad8f73115f90500266f273f7571df9429a4cfb4bbfbcd825227202dabad1\",\"created_at\":1725402765,\"tags\":[[\"d\",\"9166c289b9f905e55f9e3df9f69d7f356b4a22095f894f4715714aa4b56606af\"],[\"p\",\"9166c289b9f905e55f9e3df9f69d7f356b4a22095f894f4715714aa4b56606af\"],[\"e\",\"40808ce2685b0aeaa756d05fc99853db0c79043210a3a949fdbc905ea2984c05\"],[\"setup\",\"{\\\"kind\\\":51,\\\"id\\\":\\\"40808ce2685b0aeaa756d05fc99853db0c79043210a3a949fdbc905ea2984c05\\\",\\\"pubkey\\\":\\\"9166c289b9f905e55f9e3df9f69d7f356b4a22095f894f4715714aa4b56606af\\\",\\\"created_at\\\":1725402764,\\\"tags\\\":[[\\\"p\\\",\\\"4fe17162aa42c96d7757f98cabc8a0b38ceb61a9160195b5d16bce6f6d8064ca\\\"],[\\\"p\\\",\\\"8b57adf363f3abed31ea6e0b664884af07e2a92611154599345f6a63f9c70f02\\\"],[\\\"p\\\",\\\"741a0fb3d23db2c87f82a9a979084893c3f094c47776c1283dd313331fc4b308\\\"],[\\\"threshold\\\",\\\"2\\\"],[\\\"recovery-keys-setup\\\"]],\\\"content\\\":\\\"Setting up my first set of recovery keys! Yay!\\\",\\\"sig\\\":\\\"8e73482ffae5261edb5181960a8d50974de468f20ea9f505cb57812e348ee920468dbb390ab39b497e33ac9aa2e6f784305bea831b232585171ab0878c04c4b3\\\"}\"],[\"recovery-keys-attestation\"]],\"content\":\"\"}",
			"",
		},
		{
			"{\"kind\":30051,\"pubkey\":\"a706ad8f73115f90500266f273f7571df9429a4cfb4bbfbcd825227202dabad1\",\"created_at\":1725402765,\"tags\":[[\"p\",\"9166c289b9f905e55f9e3df9f69d7f356b4a22095f894f4715714aa4b56606af\"],[\"e\",\"40808ce2685b0aeaa756d05fc99853db0c79043210a3a949fdbc905ea2984c05\"],[\"setup\",\"{\\\"kind\\\":51,\\\"id\\\":\\\"40808ce2685b0aeaa756d05fc99853db0c79043210a3a949fdbc905ea2984c05\\\",\\\"pubkey\\\":\\\"9166c289b9f905e55f9e3df9f69d7f356b4a22095f894f4715714aa4b56606af\\\",\\\"created_at\\\":1725402764,\\\"tags\\\":[[\\\"p\\\",\\\"4fe17162aa42c96d7757f98cabc8a0b38ceb61a9160195b5d16bce6f6d8064ca\\\"],[\\\"p\\\",\\\"8b57adf363f3abed31ea6e0b664884af07e2a92611154599345f6a63f9c70f02\\\"],[\\\"p\\\",\\\"741a0fb3d23db2c87f82a9a979084893c3f094c47776c1283dd313331fc4b308\\\"],[\\\"threshold\\\",\\\"2\\\"],[\\\"recovery-keys-setup\\\"]],\\\"content\\\":\\\"Setting up my first set of recovery keys! Yay!\\\",\\\"sig\\\":\\\"8e73482ffae5261edb5181960a8d50974de468f20ea9f505cb57812e348ee920468dbb390ab39b497e33ac9aa2e6f784305bea831b232585171ab0878c04c4b3\\\"}\"],[\"recovery-keys-attestation\"]],\"content\":\"\"}",
			"Must include one d tag.",
		},
		{
			"{\"kind\":30051,\"pubkey\":\"a706ad8f73115f90500266f273f7571df9429a4cfb4bbfbcd825227202dabad1\",\"created_at\":1725402765,\"tags\":[[\"d\",\"9166c289b9f905e55f9e3df9f69d7f356b4a22095f894f4715714aa4b56606af\"],[\"d\",\"9166c289b9f905e55f9e3df9f69d7f356b4a22095f894f4715714aa4b56606ae\"],[\"p\",\"9166c289b9f905e55f9e3df9f69d7f356b4a22095f894f4715714aa4b56606af\"],[\"e\",\"40808ce2685b0aeaa756d05fc99853db0c79043210a3a949fdbc905ea2984c05\"],[\"setup\",\"{\\\"kind\\\":51,\\\"id\\\":\\\"40808ce2685b0aeaa756d05fc99853db0c79043210a3a949fdbc905ea2984c05\\\",\\\"pubkey\\\":\\\"9166c289b9f905e55f9e3df9f69d7f356b4a22095f894f4715714aa4b56606af\\\",\\\"created_at\\\":1725402764,\\\"tags\\\":[[\\\"p\\\",\\\"4fe17162aa42c96d7757f98cabc8a0b38ceb61a9160195b5d16bce6f6d8064ca\\\"],[\\\"p\\\",\\\"8b57adf363f3abed31ea6e0b664884af07e2a92611154599345f6a63f9c70f02\\\"],[\\\"p\\\",\\\"741a0fb3d23db2c87f82a9a979084893c3f094c47776c1283dd313331fc4b308\\\"],[\\\"threshold\\\",\\\"2\\\"],[\\\"recovery-keys-setup\\\"]],\\\"content\\\":\\\"Setting up my first set of recovery keys! Yay!\\\",\\\"sig\\\":\\\"8e73482ffae5261edb5181960a8d50974de468f20ea9f505cb57812e348ee920468dbb390ab39b497e33ac9aa2e6f784305bea831b232585171ab0878c04c4b3\\\"}\"],[\"recovery-keys-attestation\"]],\"content\":\"\"}",
			"Must include one d tag.",
		},
		{
			"{\"kind\":30049,\"pubkey\":\"a706ad8f73115f90500266f273f7571df9429a4cfb4bbfbcd825227202dabad1\",\"created_at\":1725402765,\"tags\":[[\"d\",\"9166c289b9f905e55f9e3df9f69d7f356b4a22095f894f4715714aa4b56606af\"],[\"p\",\"9166c289b9f905e55f9e3df9f69d7f356b4a22095f894f4715714aa4b56606af\"],[\"e\",\"40808ce2685b0aeaa756d05fc99853db0c79043210a3a949fdbc905ea2984c05\"],[\"setup\",\"{\\\"kind\\\":51,\\\"id\\\":\\\"40808ce2685b0aeaa756d05fc99853db0c79043210a3a949fdbc905ea2984c05\\\",\\\"pubkey\\\":\\\"9166c289b9f905e55f9e3df9f69d7f356b4a22095f894f4715714aa4b56606af\\\",\\\"created_at\\\":1725402764,\\\"tags\\\":[[\\\"p\\\",\\\"4fe17162aa42c96d7757f98cabc8a0b38ceb61a9160195b5d16bce6f6d8064ca\\\"],[\\\"p\\\",\\\"8b57adf363f3abed31ea6e0b664884af07e2a92611154599345f6a63f9c70f02\\\"],[\\\"p\\\",\\\"741a0fb3d23db2c87f82a9a979084893c3f094c47776c1283dd313331fc4b308\\\"],[\\\"threshold\\\",\\\"2\\\"],[\\\"recovery-keys-setup\\\"]],\\\"content\\\":\\\"Setting up my first set of recovery keys! Yay!\\\",\\\"sig\\\":\\\"8e73482ffae5261edb5181960a8d50974de468f20ea9f505cb57812e348ee920468dbb390ab39b497e33ac9aa2e6f784305bea831b232585171ab0878c04c4b3\\\"}\"],[\"recovery-keys-attestation\"]],\"content\":\"\"}",
			"Invalid kind.",
		},
		{
			"{\"kind\":30051,\"pubkey\":\"a706ad8f73115f90500266f273f7571df9429a4cfb4bbfbcd825227202dabad1\",\"created_at\":1725402765,\"tags\":[[\"d\",\"9166c289b9f905e55f9e3df9f69d7f356b4a22095f894f4715714aa4b56606af\"],[\"p\",\"9166c289b9f905e55f9e3df9f69d7f356b4a22095f894f4715714aa4b56606af\"],[\"e\",\"40808ce2685b0aeaa756d05fc99853db0c79043210a3a949fdbc905ea2984c05\"],[\"setup\",\"{\\\"kind\\\":51,\\\"id\\\":\\\"40808ce2685b0aeaa756d05fc99853db0c79043210a3a949fdbc905ea2984c05\\\",\\\"pubkey\\\":\\\"9166c289b9f905e55f9e3df9f69d7f356b4a22095f894f4715714aa4b56606af\\\",\\\"created_at\\\":1725402764,\\\"tags\\\":[[\\\"p\\\",\\\"4fe17162aa42c96d7757f98cabc8a0b38ceb61a9160195b5d16bce6f6d8064ca\\\"],[\\\"p\\\",\\\"8b57adf363f3abed31ea6e0b664884af07e2a92611154599345f6a63f9c70f02\\\"],[\\\"p\\\",\\\"741a0fb3d23db2c87f82a9a979084893c3f094c47776c1283dd313331fc4b308\\\"],[\\\"threshold\\\",\\\"2\\\"],[\\\"recovery-keys-setup\\\"]],\\\"content\\\":\\\"Setting up my first set of recovery keys! Yay!\\\",\\\"sig\\\":\\\"8e73482ffae5261edb5181960a8d50974de468f20ea9f505cb57812e348ee920468dbb390ab39b497e33ac9aa2e6f784305bea831b232585171ab0878c04c4b3\\\"}\"]],\"content\":\"\"}",
			"Must include one safeguard tag.",
		},
		{
			"{\"kind\":30051,\"pubkey\":\"a706ad8f73115f90500266f273f7571df9429a4cfb4bbfbcd825227202dabad1\",\"created_at\":1725402765,\"tags\":[[\"d\",\"9166c289b9f905e55f9e3df9f69d7f356b4a22095f894f4715714aa4b56606af\"],[\"p\",\"9166c289b9f905e55f9e3df9f69d7f356b4a22095f894f4715714aa4b56606af\"],[\"e\",\"40808ce2685b0aeaa756d05fc99853db0c79043210a3a949fdbc905ea2984c05\"],[\"setup\",\"{\\\"kind\\\":51,\\\"id\\\":\\\"40808ce2685b0aeaa756d05fc99853db0c79043210a3a949fdbc905ea2984c05\\\",\\\"pubkey\\\":\\\"9166c289b9f905e55f9e3df9f69d7f356b4a22095f894f4715714aa4b56606af\\\",\\\"created_at\\\":1725402764,\\\"tags\\\":[[\\\"p\\\",\\\"4fe17162aa42c96d7757f98cabc8a0b38ceb61a9160195b5d16bce6f6d8064ca\\\"],[\\\"p\\\",\\\"8b57adf363f3abed31ea6e0b664884af07e2a92611154599345f6a63f9c70f02\\\"],[\\\"p\\\",\\\"741a0fb3d23db2c87f82a9a979084893c3f094c47776c1283dd313331fc4b308\\\"],[\\\"threshold\\\",\\\"2\\\"],[\\\"recovery-keys-setup\\\"]],\\\"content\\\":\\\"Setting up my first set of recovery keys! Yay!\\\",\\\"sig\\\":\\\"8e73482ffae5261edb5181960a8d50974de468f20ea9f505cb57812e348ee920468dbb390ab39b497e33ac9aa2e6f784305bea831b232585171ab0878c04c4b3\\\"}\"],[\"recovery-keys-attestation\"],[\"recovery-keys-attestation\"]],\"content\":\"\"}",
			"Must include one safeguard tag.",
		},
		{
			"{\"kind\":30051,\"pubkey\":\"a706ad8f73115f90500266f273f7571df9429a4cfb4bbfbcd825227202dabad1\",\"created_at\":1725402765,\"tags\":[[\"d\",\"9166c289b9f905e55f9e3df9f69d7f356b4a22095f894f4715714aa4b56606af\"],[\"p\",\"9166c289b9f905e55f9e3df9f69d7f356b4a22095f894f4715714aa4b56606af\"],[\"e\",\"40808ce2685b0aeaa756d05fc99853db0c79043210a3a949fdbc905ea2984c05\"],[\"recovery-keys-attestation\"]],\"content\":\"\"}",
			"Public attestation must include public tags.",
		},
		{
			"{\"kind\":30051,\"pubkey\":\"a706ad8f73115f90500266f273f7571df9429a4cfb4bbfbcd825227202dabad1\",\"created_at\":1725402765,\"tags\":[[\"d\",\"9166c289b9f905e55f9e3df9f69d7f356b4a22095f894f4715714aa4b56606af\"],[\"p\",\"9166c289b9f905e55f9e3df9f69d7f356b4a22095f894f4715714aa4b56606af\"],[\"setup\",\"{\\\"kind\\\":51,\\\"id\\\":\\\"40808ce2685b0aeaa756d05fc99853db0c79043210a3a949fdbc905ea2984c05\\\",\\\"pubkey\\\":\\\"9166c289b9f905e55f9e3df9f69d7f356b4a22095f894f4715714aa4b56606af\\\",\\\"created_at\\\":1725402764,\\\"tags\\\":[[\\\"p\\\",\\\"4fe17162aa42c96d7757f98cabc8a0b38ceb61a9160195b5d16bce6f6d8064ca\\\"],[\\\"p\\\",\\\"8b57adf363f3abed31ea6e0b664884af07e2a92611154599345f6a63f9c70f02\\\"],[\\\"p\\\",\\\"741a0fb3d23db2c87f82a9a979084893c3f094c47776c1283dd313331fc4b308\\\"],[\\\"threshold\\\",\\\"2\\\"],[\\\"recovery-keys-setup\\\"]],\\\"content\\\":\\\"Setting up my first set of recovery keys! Yay!\\\",\\\"sig\\\":\\\"8e73482ffae5261edb5181960a8d50974de468f20ea9f505cb57812e348ee920468dbb390ab39b497e33ac9aa2e6f784305bea831b232585171ab0878c04c4b3\\\"}\"],[\"recovery-keys-attestation\"]],\"content\":\"\"}",
			"Public attestation must include public tags.",
		},
		{
			"{\"kind\":30051,\"pubkey\":\"a706ad8f73115f90500266f273f7571df9429a4cfb4bbfbcd825227202dabad1\",\"created_at\":1725402765,\"tags\":[[\"d\",\"9166c289b9f905e55f9e3df9f69d7f356b4a22095f894f4715714aa4b56606af\"],[\"e\",\"40808ce2685b0aeaa756d05fc99853db0c79043210a3a949fdbc905ea2984c05\"],[\"setup\",\"{\\\"kind\\\":51,\\\"id\\\":\\\"40808ce2685b0aeaa756d05fc99853db0c79043210a3a949fdbc905ea2984c05\\\",\\\"pubkey\\\":\\\"9166c289b9f905e55f9e3df9f69d7f356b4a22095f894f4715714aa4b56606af\\\",\\\"created_at\\\":1725402764,\\\"tags\\\":[[\\\"p\\\",\\\"4fe17162aa42c96d7757f98cabc8a0b38ceb61a9160195b5d16bce6f6d8064ca\\\"],[\\\"p\\\",\\\"8b57adf363f3abed31ea6e0b664884af07e2a92611154599345f6a63f9c70f02\\\"],[\\\"p\\\",\\\"741a0fb3d23db2c87f82a9a979084893c3f094c47776c1283dd313331fc4b308\\\"],[\\\"threshold\\\",\\\"2\\\"],[\\\"recovery-keys-setup\\\"]],\\\"content\\\":\\\"Setting up my first set of recovery keys! Yay!\\\",\\\"sig\\\":\\\"8e73482ffae5261edb5181960a8d50974de468f20ea9f505cb57812e348ee920468dbb390ab39b497e33ac9aa2e6f784305bea831b232585171ab0878c04c4b3\\\"}\"],[\"recovery-keys-attestation\"]],\"content\":\"\"}",
			"Public attestation must include public tags.",
		},
		{
			"{\"kind\":30051,\"id\":\"0aa62d8cff27cc19843c775817ceefacb57c897939aff2439786baeaa31d9826\",\"pubkey\":\"a706ad8f73115f90500266f273f7571df9429a4cfb4bbfbcd825227202dabad1\",\"created_at\":1725402765,\"tags\":[[\"d\",\"442427cc2ef69f8b15b823327b3cd2e94daac101a8ff89c7d3bdbd35bb64e939\"],[\"recovery-keys-attestation\"]],\"content\":\"Av//////////////////////////////////////////ZKqMK1a+YsQxv2pOJvaqQJYCS/nd89hQ+HsMDc0ltpAw8bnHKnl5TiHH9qm3coDsyQTVybJkDch+tl+FlbELRcPkIGqxICUDp5lPzj/u23/+VseJaziv+HU0S6/bS5IAbewdzekaN8H4NNAx/nCWzps0s5cm+PetZkdydJv875Aoh71gWF7u5BFZ1Kr1j8XXnBIzzvBA4kGGzusD0CTyUzZqlXV9OTBzi+1cU0qXR3pRroLCDP3EZ4gemFtK26wqxpg2lIjomkYTcuw8JqX4G2AjcsL9knlqUYKZwBrSe87QgWD3Q0Cy1dBGPmU9OZL6FPpYS7hZMzFWTfvalaoCeCAW1kdFeqIQ2ddX81ksD2QsUFNpLLwQxFKHSpqwgkWq9bpPGxdG8ECV9u218dLuJXFSKFGVVJG2iX8qjIXaBHjkOfmPzuJuho5r1UP7gAopffY7TrZxV1yRaHIXHyGZJDQgbHbi1ssfkq1k9jEbsZlxDM5zwLx1nDYhmob21nR/DhdA8U3OFHvJvzCA5bHBX3nMiY2pYGyNT46WP0anvRpCjezaP/0AD9hkrBqV1eXFeDYkcKKcmAWmvl/AkY+0C7qKxj+L5vAPH6VXBFeZpvTHuovl1ZXS4jHW4su/qV94DaleK55Ddn7zwNsAXCEstCm0TkZmePfkspW8UFe68LQRvbGOheHGpgpUyAxojSB9eMa4F8uQwAYYrf489h+VNy3jQGHRX2z6QXARGo/uHAR7843KCScymyrbWbTCOLXiFhuSI+HS7ag0TXqOw22h+6j7A1KH01E/4ln/EN7v1cOiYv94m5aAiXKVBZVakzwhbZTEsvkc3657h9VZi7Qw0mbwDoSQIyGKX7ZmMKkoRZOaSjbUWbXEZPbh6wnflmnzeP/+qAGhNbB/kzP2G5Nz7YV9kA+f1upnyOG6KXGKJntgn6DIItjU6MuNw2VM3OYdh5DS5xlezQMzx3TJRTo08TAvfEMM/SjoND1TE5PcyhBKXYaBG+eRsEbutc5t4+gqt69W8erzmFRJL3klGJ2kft5RXFD5enrF2om1OXrkaU7o/DKzPy8/38begooZGhXjR0Ruj+ahNHsca6PL0/UQ84AaxpDzZ3lDN0vNSkmEJGrLzxjhqKGYljPMYa6VUgRg2/xvyqB7YUx+m4dUgpSz0bbGdXqHTYab8zLjupPHvxx2FvOdCRYOAygwq0qO/vUWaE/vn78COwPe78BUA8HNOGTA\",\"sig\":\"dd531aa2d853b4a242167d6b8b731b1b7af56ecccb47b7488ebf276ade4dc6fe02e09e3b0fb8545310fe7a89dc0f9c8debbf6897e0d31986e67535ec603e0449\"}",
			"",
		},
		{
			"{\"kind\":30051,\"id\":\"0aa62d8cff27cc19843c775817ceefacb57c897939aff2439786baeaa31d9826\",\"pubkey\":\"a706ad8f73115f90500266f273f7571df9429a4cfb4bbfbcd825227202dabad1\",\"created_at\":1725402765,\"tags\":[[\"d\",\"442427cc2ef69f8b15b823327b3cd2e94daac101a8ff89c7d3bdbd35bb64e939\"],[\"recovery-keys-attestation\"]],\"content\":\"\"}",
			"Public attestation must include public tags.",
		},
		{
			"{\"kind\":30051,\"id\":\"0aa62d8cff27cc19843c775817ceefacb57c897939aff2439786baeaa31d9826\",\"pubkey\":\"a706ad8f73115f90500266f273f7571df9429a4cfb4bbfbcd825227202dabad1\",\"created_at\":1725402765,\"tags\":[[\"d\",\"442427cc2ef69f8b15b823327b3cd2e94daac101a8ff89c7d3bdbd35bb64e939\"],[\"recovery-keys-attestation\"]],\"content\":\"Something not base64 encoded.\"}",
			"Private content must be base64.",
		},
		{
			"{\"kind\":30051,\"id\":\"0aa62d8cff27cc19843c775817ceefacb57c897939aff2439786baeaa31d9826\",\"pubkey\":\"a706ad8f73115f90500266f273f7571df9429a4cfb4bbfbcd825227202dabad1\",\"created_at\":1725402765,\"tags\":[[\"d\",\"442427cc2ef69f8b15b823327b3cd2e94daac101a8ff89c7d3bdbd35bb64e939\"],[\"setup\",\"{\\\"kind\\\":51,\\\"id\\\":\\\"40808ce2685b0aeaa756d05fc99853db0c79043210a3a949fdbc905ea2984c05\\\",\\\"pubkey\\\":\\\"9166c289b9f905e55f9e3df9f69d7f356b4a22095f894f4715714aa4b56606af\\\",\\\"created_at\\\":1725402764,\\\"tags\\\":[[\\\"p\\\",\\\"4fe17162aa42c96d7757f98cabc8a0b38ceb61a9160195b5d16bce6f6d8064ca\\\"],[\\\"p\\\",\\\"8b57adf363f3abed31ea6e0b664884af07e2a92611154599345f6a63f9c70f02\\\"],[\\\"p\\\",\\\"741a0fb3d23db2c87f82a9a979084893c3f094c47776c1283dd313331fc4b308\\\"],[\\\"threshold\\\",\\\"2\\\"],[\\\"recovery-keys-setup\\\"]],\\\"content\\\":\\\"Setting up my first set of recovery keys! Yay!\\\",\\\"sig\\\":\\\"8e73482ffae5261edb5181960a8d50974de468f20ea9f505cb57812e348ee920468dbb390ab39b497e33ac9aa2e6f784305bea831b232585171ab0878c04c4b3\\\"}\"],[\"recovery-keys-attestation\"]],\"content\":\"Av//////////////////////////////////////////ZKqMK1a+YsQxv2pOJvaqQJYCS/nd89hQ+HsMDc0ltpAw8bnHKnl5TiHH9qm3coDsyQTVybJkDch+tl+FlbELRcPkIGqxICUDp5lPzj/u23/+VseJaziv+HU0S6/bS5IAbewdzekaN8H4NNAx/nCWzps0s5cm+PetZkdydJv875Aoh71gWF7u5BFZ1Kr1j8XXnBIzzvBA4kGGzusD0CTyUzZqlXV9OTBzi+1cU0qXR3pRroLCDP3EZ4gemFtK26wqxpg2lIjomkYTcuw8JqX4G2AjcsL9knlqUYKZwBrSe87QgWD3Q0Cy1dBGPmU9OZL6FPpYS7hZMzFWTfvalaoCeCAW1kdFeqIQ2ddX81ksD2QsUFNpLLwQxFKHSpqwgkWq9bpPGxdG8ECV9u218dLuJXFSKFGVVJG2iX8qjIXaBHjkOfmPzuJuho5r1UP7gAopffY7TrZxV1yRaHIXHyGZJDQgbHbi1ssfkq1k9jEbsZlxDM5zwLx1nDYhmob21nR/DhdA8U3OFHvJvzCA5bHBX3nMiY2pYGyNT46WP0anvRpCjezaP/0AD9hkrBqV1eXFeDYkcKKcmAWmvl/AkY+0C7qKxj+L5vAPH6VXBFeZpvTHuovl1ZXS4jHW4su/qV94DaleK55Ddn7zwNsAXCEstCm0TkZmePfkspW8UFe68LQRvbGOheHGpgpUyAxojSB9eMa4F8uQwAYYrf489h+VNy3jQGHRX2z6QXARGo/uHAR7843KCScymyrbWbTCOLXiFhuSI+HS7ag0TXqOw22h+6j7A1KH01E/4ln/EN7v1cOiYv94m5aAiXKVBZVakzwhbZTEsvkc3657h9VZi7Qw0mbwDoSQIyGKX7ZmMKkoRZOaSjbUWbXEZPbh6wnflmnzeP/+qAGhNbB/kzP2G5Nz7YV9kA+f1upnyOG6KXGKJntgn6DIItjU6MuNw2VM3OYdh5DS5xlezQMzx3TJRTo08TAvfEMM/SjoND1TE5PcyhBKXYaBG+eRsEbutc5t4+gqt69W8erzmFRJL3klGJ2kft5RXFD5enrF2om1OXrkaU7o/DKzPy8/38begooZGhXjR0Ruj+ahNHsca6PL0/UQ84AaxpDzZ3lDN0vNSkmEJGrLzxjhqKGYljPMYa6VUgRg2/xvyqB7YUx+m4dUgpSz0bbGdXqHTYab8zLjupPHvxx2FvOdCRYOAygwq0qO/vUWaE/vn78COwPe78BUA8HNOGTA\",\"sig\":\"dd531aa2d853b4a242167d6b8b731b1b7af56ecccb47b7488ebf276ade4dc6fe02e09e3b0fb8545310fe7a89dc0f9c8debbf6897e0d31986e67535ec603e0449\"}",
			"Private attestation must not include public tags.",
		},
		{
			"{\"kind\":30051,\"id\":\"0aa62d8cff27cc19843c775817ceefacb57c897939aff2439786baeaa31d9826\",\"pubkey\":\"a706ad8f73115f90500266f273f7571df9429a4cfb4bbfbcd825227202dabad1\",\"created_at\":1725402765,\"tags\":[[\"d\",\"442427cc2ef69f8b15b823327b3cd2e94daac101a8ff89c7d3bdbd35bb64e939\"],[\"e\",\"40808ce2685b0aeaa756d05fc99853db0c79043210a3a949fdbc905ea2984c05\"],[\"recovery-keys-attestation\"]],\"content\":\"Av//////////////////////////////////////////ZKqMK1a+YsQxv2pOJvaqQJYCS/nd89hQ+HsMDc0ltpAw8bnHKnl5TiHH9qm3coDsyQTVybJkDch+tl+FlbELRcPkIGqxICUDp5lPzj/u23/+VseJaziv+HU0S6/bS5IAbewdzekaN8H4NNAx/nCWzps0s5cm+PetZkdydJv875Aoh71gWF7u5BFZ1Kr1j8XXnBIzzvBA4kGGzusD0CTyUzZqlXV9OTBzi+1cU0qXR3pRroLCDP3EZ4gemFtK26wqxpg2lIjomkYTcuw8JqX4G2AjcsL9knlqUYKZwBrSe87QgWD3Q0Cy1dBGPmU9OZL6FPpYS7hZMzFWTfvalaoCeCAW1kdFeqIQ2ddX81ksD2QsUFNpLLwQxFKHSpqwgkWq9bpPGxdG8ECV9u218dLuJXFSKFGVVJG2iX8qjIXaBHjkOfmPzuJuho5r1UP7gAopffY7TrZxV1yRaHIXHyGZJDQgbHbi1ssfkq1k9jEbsZlxDM5zwLx1nDYhmob21nR/DhdA8U3OFHvJvzCA5bHBX3nMiY2pYGyNT46WP0anvRpCjezaP/0AD9hkrBqV1eXFeDYkcKKcmAWmvl/AkY+0C7qKxj+L5vAPH6VXBFeZpvTHuovl1ZXS4jHW4su/qV94DaleK55Ddn7zwNsAXCEstCm0TkZmePfkspW8UFe68LQRvbGOheHGpgpUyAxojSB9eMa4F8uQwAYYrf489h+VNy3jQGHRX2z6QXARGo/uHAR7843KCScymyrbWbTCOLXiFhuSI+HS7ag0TXqOw22h+6j7A1KH01E/4ln/EN7v1cOiYv94m5aAiXKVBZVakzwhbZTEsvkc3657h9VZi7Qw0mbwDoSQIyGKX7ZmMKkoRZOaSjbUWbXEZPbh6wnflmnzeP/+qAGhNbB/kzP2G5Nz7YV9kA+f1upnyOG6KXGKJntgn6DIItjU6MuNw2VM3OYdh5DS5xlezQMzx3TJRTo08TAvfEMM/SjoND1TE5PcyhBKXYaBG+eRsEbutc5t4+gqt69W8erzmFRJL3klGJ2kft5RXFD5enrF2om1OXrkaU7o/DKzPy8/38begooZGhXjR0Ruj+ahNHsca6PL0/UQ84AaxpDzZ3lDN0vNSkmEJGrLzxjhqKGYljPMYa6VUgRg2/xvyqB7YUx+m4dUgpSz0bbGdXqHTYab8zLjupPHvxx2FvOdCRYOAygwq0qO/vUWaE/vn78COwPe78BUA8HNOGTA\",\"sig\":\"dd531aa2d853b4a242167d6b8b731b1b7af56ecccb47b7488ebf276ade4dc6fe02e09e3b0fb8545310fe7a89dc0f9c8debbf6897e0d31986e67535ec603e0449\"}",
			"Private attestation must not include public tags.",
		},
		{
			"{\"kind\":30051,\"id\":\"0aa62d8cff27cc19843c775817ceefacb57c897939aff2439786baeaa31d9826\",\"pubkey\":\"a706ad8f73115f90500266f273f7571df9429a4cfb4bbfbcd825227202dabad1\",\"created_at\":1725402765,\"tags\":[[\"d\",\"442427cc2ef69f8b15b823327b3cd2e94daac101a8ff89c7d3bdbd35bb64e939\"],[\"p\",\"9166c289b9f905e55f9e3df9f69d7f356b4a22095f894f4715714aa4b56606af\"],[\"recovery-keys-attestation\"]],\"content\":\"Av//////////////////////////////////////////ZKqMK1a+YsQxv2pOJvaqQJYCS/nd89hQ+HsMDc0ltpAw8bnHKnl5TiHH9qm3coDsyQTVybJkDch+tl+FlbELRcPkIGqxICUDp5lPzj/u23/+VseJaziv+HU0S6/bS5IAbewdzekaN8H4NNAx/nCWzps0s5cm+PetZkdydJv875Aoh71gWF7u5BFZ1Kr1j8XXnBIzzvBA4kGGzusD0CTyUzZqlXV9OTBzi+1cU0qXR3pRroLCDP3EZ4gemFtK26wqxpg2lIjomkYTcuw8JqX4G2AjcsL9knlqUYKZwBrSe87QgWD3Q0Cy1dBGPmU9OZL6FPpYS7hZMzFWTfvalaoCeCAW1kdFeqIQ2ddX81ksD2QsUFNpLLwQxFKHSpqwgkWq9bpPGxdG8ECV9u218dLuJXFSKFGVVJG2iX8qjIXaBHjkOfmPzuJuho5r1UP7gAopffY7TrZxV1yRaHIXHyGZJDQgbHbi1ssfkq1k9jEbsZlxDM5zwLx1nDYhmob21nR/DhdA8U3OFHvJvzCA5bHBX3nMiY2pYGyNT46WP0anvRpCjezaP/0AD9hkrBqV1eXFeDYkcKKcmAWmvl/AkY+0C7qKxj+L5vAPH6VXBFeZpvTHuovl1ZXS4jHW4su/qV94DaleK55Ddn7zwNsAXCEstCm0TkZmePfkspW8UFe68LQRvbGOheHGpgpUyAxojSB9eMa4F8uQwAYYrf489h+VNy3jQGHRX2z6QXARGo/uHAR7843KCScymyrbWbTCOLXiFhuSI+HS7ag0TXqOw22h+6j7A1KH01E/4ln/EN7v1cOiYv94m5aAiXKVBZVakzwhbZTEsvkc3657h9VZi7Qw0mbwDoSQIyGKX7ZmMKkoRZOaSjbUWbXEZPbh6wnflmnzeP/+qAGhNbB/kzP2G5Nz7YV9kA+f1upnyOG6KXGKJntgn6DIItjU6MuNw2VM3OYdh5DS5xlezQMzx3TJRTo08TAvfEMM/SjoND1TE5PcyhBKXYaBG+eRsEbutc5t4+gqt69W8erzmFRJL3klGJ2kft5RXFD5enrF2om1OXrkaU7o/DKzPy8/38begooZGhXjR0Ruj+ahNHsca6PL0/UQ84AaxpDzZ3lDN0vNSkmEJGrLzxjhqKGYljPMYa6VUgRg2/xvyqB7YUx+m4dUgpSz0bbGdXqHTYab8zLjupPHvxx2FvOdCRYOAygwq0qO/vUWaE/vn78COwPe78BUA8HNOGTA\",\"sig\":\"dd531aa2d853b4a242167d6b8b731b1b7af56ecccb47b7488ebf276ade4dc6fe02e09e3b0fb8545310fe7a89dc0f9c8debbf6897e0d31986e67535ec603e0449\"}",
			"Private attestation must not include public tags.",
		},
	} {
		var evt nostr.Event
		err := json.Unmarshal([]byte(vector.JSON), &evt)
		assert.Nil(t, err)

		err = ValidateRecoveryKeysAttestationEvent(&evt)

		if vector.ExpectedError == "" {
			// Valid
			assert.Nil(t, err)
		} else {
			// Invalid
			assert.NotNil(t, err)
			assert.EqualErrorf(t, err, vector.ExpectedError, "Error message: %s", err)
		}

	}
}
