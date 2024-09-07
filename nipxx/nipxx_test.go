package nipxx

import (
	"testing"
	"encoding/json"
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"github.com/nbd-wtf/go-nostr"
)

func TestMakeRecoveryKeysSetup(t *testing.T) {
	for _, vector := range []struct {
		PubKeys []string
		Threshold  int
		Comment string
	}{
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
		Error string
	}{
		{
			"{\"kind\":49,\"created_at\":1725402764,\"tags\":[[\"p\",\"4fe17162aa42c96d7757f98cabc8a0b38ceb61a9160195b5d16bce6f6d8064ca\"],[\"p\",\"8b57adf363f3abed31ea6e0b664884af07e2a92611154599345f6a63f9c70f02\"],[\"p\",\"741a0fb3d23db2c87f82a9a979084893c3f094c47776c1283dd313331fc4b308\"],[\"threshold\",\"2\"],[\"recovery-keys-setup\"]],\"content\":\"\"}",
			"Invalid kind.",
		},
		{
			"{\"kind\":51,\"created_at\":1725402764,\"tags\":[[\"p\",\"4fe17162aa42c96d7757f98cabc8a0b38ceb61a9160195b5d16bce6f6d8064ca\"],[\"p\",\"8b57adf363f3abed31ea6e0b664884af07e2a92611154599345f6a63f9c70f02\"],[\"p\",\"741a0fb3d23db2c87f82a9a979084893c3f094c47776c1283dd313331fc4b308\"],[\"threshold\",\"2\"],[\"recovery-keys-setup\", \"recovery-keys-setup\"]],\"content\":\"\"}",
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
			"Threshold tag value must be a non-zero positive integer.",
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

		if vector.Error == "" {
			// Valid
			assert.Nil(t, err)
		} else {
			// Invalid
			assert.Errorf(t, err, vector.Error, err)
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
			"{\"kind\":30051,\"id\":\"4cc2b33067fe1a97fad6feb68e5f9a662bbe4b703616217c0c8e8a95691285c4\",\"pubkey\":\"a706ad8f73115f90500266f273f7571df9429a4cfb4bbfbcd825227202dabad1\",\"created_at\":1725402765,\"tags\":[[\"recovery-keys-attestation\"]],\"content\":\"Av//////////////////////////////////////////ZKqMK1a+YsQxv2pOJvaqQJYCS/nd89hQ+HsMDc0ltpAw8bnHKnl5TiHH9qm3coDsyQTVybJkDch+tl+FlbELRcPkIGqxICUDp5lPzj/u23/+VseJaziv+HU0S6/bS5IAbewdzekaN8H4NNAx/nCWzps0s5cm+PetZkdydJv875Aoh71gWF7u5BFZ1Kr1j8XXnBIzzvBA4kGGzusD0CTyUzZqlXV9OTBzi+1cU0qXR3pRroLCDP3EZ4gemFtK26wqxpg2lIjomkYTcuw8JqX4G2AjcsL9knlqUYKZwBrSe87QgWD3Q0Cy1dBGPmU9OZL6FPpYS7hZMzFWTfvalaoCeCAW1kdFeqIQ2ddX81ksD2QsUFNpLLwQxFKHSpqwgkWq9bpPGxdG8ECV9u218dLuJXFSKFGVVJG2iX8qjIXaBHjkOfmPzuJuho5r1UP7gAopffY7TrZxV1yRaHIXHyGZJDQgbHbi1ssfkq1k9jEbsZlxDM5zwLx1nDYhmob21nR/DhdA8U3OFHvJvzCA5bHBX3nMiY2pYGyNT46WP0anvRpCjezaP/0AD9hkrBqV1eXFeDYkcKKcmAWmvl/AkY+0C7qKxj+L5vAPH6VXBFeZpvTHuovl1ZXS4jHW4su/qV94DaleK55Ddn7zwNsAXCEstCm0TkZmePfkspW8UFe68LQRvbGOheHGpgpUyAxojSB9eMa4F8uQwAYYrf489h+VNy3jQGHRX2z6QXARGo/uHAR7843KCScymyrbWbTCOLXiFhuSI+HS7ag0TXqOw22h+6j7A1KH01E/4ln/EN7v1cOiYv94m5aAiXKVBZVakzwhbZTEsvkc3657h9VZi7Qw0mbwDoSQIyGKX7ZmMKkoRZOaSjbUWbXEZPbh6wnflmnzeP/+qAGhNbB/kzP2G5Nz7YV9kA+f1upnyOG6KXGKJntgn6DIItjU6MuNw2VM3OYdh5DS5xlezQMzx3TJRTo08TAvfEMM/SjoND1TE5PcyhBKXYaBG+eRsEbutc5t4+gqt69W8erzmFRJL3klGJ2kft5RXFD5enrF2om1OXrkaU7o/DKzPy8/38begooZGhXjR0Ruj+ahNHsca6PL0/UQ84AaxpDzZ3lDN0vNSkmEJGrLzxjhqKGYljPMYa6VUgRg2/xvyqB7YUx+m4dUgpSz0bbGdXqHTYab8zLjupPHvxx2FvOdCRYOAygwq0qO/vUWaE/vn78COwPe78BUA8HNOGTA\",\"sig\":\"ef133284fcf41b69fc30c1c212c9107170017a90b8dfc37c3b0948d8c0c66124f9ada71b06d48281a1b35da1512112b16973e119f360d3ae92732612e3beeaf8\"}",
		},
		{
			"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
			"",
			"",
			"9166c289b9f905e55f9e3df9f69d7f356b4a22095f894f4715714aa4b56606af",
			"40808ce2685b0aeaa756d05fc99853db0c79043210a3a949fdbc905ea2984c05",
			"{\"kind\":51,\"id\":\"40808ce2685b0aeaa756d05fc99853db0c79043210a3a949fdbc905ea2984c05\",\"pubkey\":\"9166c289b9f905e55f9e3df9f69d7f356b4a22095f894f4715714aa4b56606af\",\"created_at\":1725402764,\"tags\":[[\"p\",\"4fe17162aa42c96d7757f98cabc8a0b38ceb61a9160195b5d16bce6f6d8064ca\"],[\"p\",\"8b57adf363f3abed31ea6e0b664884af07e2a92611154599345f6a63f9c70f02\"],[\"p\",\"741a0fb3d23db2c87f82a9a979084893c3f094c47776c1283dd313331fc4b308\"],[\"threshold\",\"2\"],[\"recovery-keys-setup\"]],\"content\":\"Setting up my first set of recovery keys! Yay!\",\"sig\":\"8e73482ffae5261edb5181960a8d50974de468f20ea9f505cb57812e348ee920468dbb390ab39b497e33ac9aa2e6f784305bea831b232585171ab0878c04c4b3\"}",
			int64(1725402765),
			"{\"kind\":30051,\"id\":\"efe6437f894d1f7a4ec188f87dcf771d5069826dd24694986b5842f7cf2ad7d4\",\"pubkey\":\"a706ad8f73115f90500266f273f7571df9429a4cfb4bbfbcd825227202dabad1\",\"created_at\":1725402765,\"tags\":[[\"p\",\"9166c289b9f905e55f9e3df9f69d7f356b4a22095f894f4715714aa4b56606af\"],[\"e\",\"40808ce2685b0aeaa756d05fc99853db0c79043210a3a949fdbc905ea2984c05\"],[\"setup\",\"{\\\"kind\\\":51,\\\"id\\\":\\\"40808ce2685b0aeaa756d05fc99853db0c79043210a3a949fdbc905ea2984c05\\\",\\\"pubkey\\\":\\\"9166c289b9f905e55f9e3df9f69d7f356b4a22095f894f4715714aa4b56606af\\\",\\\"created_at\\\":1725402764,\\\"tags\\\":[[\\\"p\\\",\\\"4fe17162aa42c96d7757f98cabc8a0b38ceb61a9160195b5d16bce6f6d8064ca\\\"],[\\\"p\\\",\\\"8b57adf363f3abed31ea6e0b664884af07e2a92611154599345f6a63f9c70f02\\\"],[\\\"p\\\",\\\"741a0fb3d23db2c87f82a9a979084893c3f094c47776c1283dd313331fc4b308\\\"],[\\\"threshold\\\",\\\"2\\\"],[\\\"recovery-keys-setup\\\"]],\\\"content\\\":\\\"Setting up my first set of recovery keys! Yay!\\\",\\\"sig\\\":\\\"8e73482ffae5261edb5181960a8d50974de468f20ea9f505cb57812e348ee920468dbb390ab39b497e33ac9aa2e6f784305bea831b232585171ab0878c04c4b3\\\"}\"],[\"recovery-keys-attestation\"]],\"content\":\"\",\"sig\":\"430587756af52de8113e28625b8a22f85b42ed7fecfc1233af2dedcc0689ca0bc01df6eb116373de5f07cb4e550ef49455c2e5200075eed2e3bbdeef21371111\"}",
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
