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
		JSON string
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
			"{\"kind\":52,\"id\":\"2e9857c30aa364c83d769e7fa6e18bd7975fe58f2bcdb487f8e5289e60b216f2\",\"pubkey\":\"9166c289b9f905e55f9e3df9f69d7f356b4a22095f894f4715714aa4b56606af\",\"created_at\":1725402764,\"tags\":[[\"p\",\"4fe17162aa42c96d7757f98cabc8a0b38ceb61a9160195b5d16bce6f6d8064ca\"],[\"p\",\"8b57adf363f3abed31ea6e0b664884af07e2a92611154599345f6a63f9c70f02\"],[\"p\",\"741a0fb3d23db2c87f82a9a979084893c3f094c47776c1283dd313331fc4b308\"],[\"threshold\",\"2\"],[\"recovery-keys-setup\"]],\"content\":\"Setting up my first set of recovery keys! Yay!\",\"sig\":\"fe17c1ec586fbbf68f0588125d4476c28a4d5bfd9948832036fe00559794f2941161aa82605e59632877edbabe62e35c19d28faf1b676ffdb78a977043af663e\"}",
		},
	} {
		setup := MakeRecoveryKeysSetup(vector.PubKeys, vector.Threshold, vector.Comment)
		evt := MakeRecoveryKeysSetupEvent(setup, nostr.Timestamp(vector.Timestamp))

		evt.Sign(vector.PrivateKey)

		evtjson, err := json.Marshal(evt)

		assert.Nil(t, err)
		assert.Equal(t, vector.JSON, string(evtjson))
	}
}

func TestValidateRecoveryKeysEvent(t *testing.T) {
	for _, vector := range []struct {
		JSON string
		Error string
	}{
		{
			"{\"kind\":50,\"created_at\":1725402764,\"tags\":[[\"p\",\"4fe17162aa42c96d7757f98cabc8a0b38ceb61a9160195b5d16bce6f6d8064ca\"],[\"p\",\"8b57adf363f3abed31ea6e0b664884af07e2a92611154599345f6a63f9c70f02\"],[\"p\",\"741a0fb3d23db2c87f82a9a979084893c3f094c47776c1283dd313331fc4b308\"],[\"threshold\",\"2\"],[\"recovery-keys-setup\"]],\"content\":\"\"}",
			"Invalid kind.",
		},
		{
			"{\"kind\":52,\"created_at\":1725402764,\"tags\":[[\"p\",\"4fe17162aa42c96d7757f98cabc8a0b38ceb61a9160195b5d16bce6f6d8064ca\"],[\"p\",\"8b57adf363f3abed31ea6e0b664884af07e2a92611154599345f6a63f9c70f02\"],[\"p\",\"741a0fb3d23db2c87f82a9a979084893c3f094c47776c1283dd313331fc4b308\"],[\"threshold\",\"2\"],[\"recovery-keys-setup\", \"recovery-keys-setup\"]],\"content\":\"\"}",
			"Must include one safeguard tag.",
		},
		{
			"{\"kind\":52,\"created_at\":1725402764,\"tags\":[[\"p\",\"4fe17162aa42c96d7757f98cabc8a0b38ceb61a9160195b5d16bce6f6d8064ca\"],[\"p\",\"8b57adf363f3abed31ea6e0b664884af07e2a92611154599345f6a63f9c70f02\"],[\"p\",\"741a0fb3d23db2c87f82a9a979084893c3f094c47776c1283dd313331fc4b308\"],[\"threshold\",\"2\"]],\"content\":\"\"}",
			"Must include one safeguard tag.",
		},
		{
			"{\"kind\":52,\"created_at\":1725402764,\"tags\":[[\"p\",\"4fe17162aa42c96d7757f98cabc8a0b38ceb61a9160195b5d16bce6f6d8064ca\"],[\"p\",\"8b57adf363f3abed31ea6e0b664884af07e2a92611154599345f6a63f9c70f02\"],[\"p\",\"741a0fb3d23db2c87f82a9a979084893c3f094c47776c1283dd313331fc4b308\"],[\"threshold\",\"0\"],[\"recovery-keys-setup\"]],\"content\":\"\"}",
			"Threshold tag value must be a non-zero positive integer.",
		},
		{
			"{\"kind\":52,\"created_at\":1725402764,\"tags\":[[\"p\",\"4fe17162aa42c96d7757f98cabc8a0b38ceb61a9160195b5d16bce6f6d8064ca\"],[\"p\",\"8b57adf363f3abed31ea6e0b664884af07e2a92611154599345f6a63f9c70f02\"],[\"p\",\"741a0fb3d23db2c87f82a9a979084893c3f094c47776c1283dd313331fc4b308\"],[\"threshold\",\"-1\"],[\"recovery-keys-setup\"]],\"content\":\"\"}",
			"Threshold tag value must be a non-zero positive integer.",
		},
		{
			"{\"kind\":52,\"created_at\":1725402764,\"tags\":[[\"p\",\"4fe17162aa42c96d7757f98cabc8a0b38ceb61a9160195b5d16bce6f6d8064ca\"],[\"p\",\"8b57adf363f3abed31ea6e0b664884af07e2a92611154599345f6a63f9c70f02\"],[\"p\",\"741a0fb3d23db2c87f82a9a979084893c3f094c47776c1283dd313331fc4b308\"],[\"threshold\",\"wild string\"],[\"recovery-keys-setup\"]],\"content\":\"\"}",
			"Threshold tag value must be a non-zero positive integer.",
		},
		{
			"{\"kind\":52,\"created_at\":1725402764,\"tags\":[[\"p\",\"4fe17162aa42c96d7757f98cabc8a0b38ceb61a9160195b5d16bce6f6d8064ca\"],[\"p\",\"8b57adf363f3abed31ea6e0b664884af07e2a92611154599345f6a63f9c70f02\"],[\"p\",\"741a0fb3d23db2c87f82a9a979084893c3f094c47776c1283dd313331fc4b308\"],[\"recovery-keys-setup\"]],\"content\":\"\"}",
			"Must include one threshold tag.",
		},
		{
			"{\"kind\":52,\"created_at\":1725402764,\"tags\":[[\"p\",\"4fe17162aa42c96d7757f98cabc8a0b38ceb61a9160195b5d16bce6f6d8064ca\"],[\"p\",\"8b57adf363f3abed31ea6e0b664884af07e2a92611154599345f6a63f9c70f02\"],[\"p\",\"741a0fb3d23db2c87f82a9a979084893c3f094c47776c1283dd313331fc4b308\"],[\"threshold\", \"1\", \"1\"],[\"recovery-keys-setup\"]],\"content\":\"\"}",
			"Threshold tag must include only one value.",
		},
		{
			"{\"kind\":52,\"created_at\":1725402764,\"tags\":[[\"p\",\"4fe17162aa42c96d7757f98cabc8a0b38ceb61a9160195b5d16bce6f6d8064ca\"],[\"p\",\"8b57adf363f3abed31ea6e0b664884af07e2a92611154599345f6a63f9c70f02\"],[\"p\",\"741a0fb3d23db2c87f82a9a979084893c3f094c47776c1283dd313331fc4b308\"],[\"threshold\", \"00 00 1 -3\"],[\"recovery-keys-setup\"]],\"content\":\"\"}",
			"Threshold tag value must be an integer.",
		},
		{
			"{\"kind\":52,\"created_at\":1725402764,\"tags\":[[\"threshold\", \"1\"],[\"recovery-keys-setup\"]],\"content\":\"\"}",
			"Must include one or more recovery pubkeys.",
		},
		{
			"{\"kind\":52,\"created_at\":1725402764,\"tags\":[[\"p\",\"4fe17162aa42c96d7757f98cabc8a0b38ceb61a9160195b5d16bce6f6d8064ca\"],[\"threshold\", \"1\"],[\"recovery-keys-setup\"]],\"content\":\"\"}",
			"",
		},
		{
			"{\"kind\":52,\"created_at\":1725402764,\"tags\":[[\"p\",\"4fe17162aa42c96d7757f98cabc8a0b38ceb61a9160195b5d16bce6f6d8064ca\"],[\"p\",\"8b57adf363f3abed31ea6e0b664884af07e2a92611154599345f6a63f9c70f02\"],[\"p\",\"741a0fb3d23db2c87f82a9a979084893c3f094c47776c1283dd313331fc4b308\"],[\"threshold\", \"1\"],[\"recovery-keys-setup\"]],\"content\":\"\"}",
			"",
		},
		{
			"{\"kind\":52,\"created_at\":1725402764,\"tags\":[[\"p\",\"4fe17162aa42c96d7757f98cabc8a0b38ceb61a9160195b5d16bce6f6d8064ca\"],[\"p\",\"8b57adf363f3abed31ea6e0b664884af07e2a92611154599345f6a63f9c70f02\"],[\"p\",\"741a0fb3d23db2c87f82a9a979084893c3f094c47776c1283dd313331fc4b308\"],[\"threshold\", \"5\"],[\"recovery-keys-setup\"]],\"content\":\"\"}",
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
		JSON string
	}{
		{
			"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
			"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			"0000000000000000000000000000000000000000000000000000000000000000",
			"9166c289b9f905e55f9e3df9f69d7f356b4a22095f894f4715714aa4b56606af",
			"40808ce2685b0aeaa756d05fc99853db0c79043210a3a949fdbc905ea2984c05",
			"{\"kind\":52,\"id\":\"2e9857c30aa364c83d769e7fa6e18bd7975fe58f2bcdb487f8e5289e60b216f2\",\"pubkey\":\"9166c289b9f905e55f9e3df9f69d7f356b4a22095f894f4715714aa4b56606af\",\"created_at\":1725402764,\"tags\":[[\"p\",\"4fe17162aa42c96d7757f98cabc8a0b38ceb61a9160195b5d16bce6f6d8064ca\"],[\"p\",\"8b57adf363f3abed31ea6e0b664884af07e2a92611154599345f6a63f9c70f02\"],[\"p\",\"741a0fb3d23db2c87f82a9a979084893c3f094c47776c1283dd313331fc4b308\"],[\"threshold\",\"2\"],[\"recovery-keys-setup\"]],\"content\":\"Setting up my first set of recovery keys! Yay!\",\"sig\":\"fe17c1ec586fbbf68f0588125d4476c28a4d5bfd9948832036fe00559794f2941161aa82605e59632877edbabe62e35c19d28faf1b676ffdb78a977043af663e\"}",
			int64(1725402765),
			"{\"kind\":53,\"id\":\"2623582e3720eb255e5bd022a91f9f3343663463364066bf827c04fa86ba1a5e\",\"pubkey\":\"a706ad8f73115f90500266f273f7571df9429a4cfb4bbfbcd825227202dabad1\",\"created_at\":1725402765,\"tags\":[[\"recovery-keys-attestation\"]],\"content\":\"Av//////////////////////////////////////////ZXKsUh+nLowxvG5KPLfxHI1aUK2B+tUA+i1ZBMl34cA99LfNKnkpRHHG8vzgJYPkklWEyLxlDZl8vwyAxuYORsO+Ijq/dSZQ+YJ31FSujGzkEsGbfyrn7nJtGO7ME4BYObtKme4UapP0NIo48i2WyJlv5sd1p/7/Y0wnc5z8u59+iro2CA3u4UIEjKyqg8aFmRAgp7169FDWjKhDxGm2CkZqnW52PBg01YcMCzSPHyk/uYyuHP7Ca5QEj18fnrYl//N1gculj0dDc+0+cfDzQzkic8WmlH5qX4ealRHbKM6Bg2GiSkTlj9AabGZpOZnyGv4KQrhnJHk7WenMkvcBNxgM3C1TIPIEspg+6RBsGiAtAlM7eO0QzgGHSM/ohhb3orxMSRQVohbC8uu98NPpe3hRK1fDXJa3iXp62IWNCHfhPfqInt96mbRw1Qauh05+O/R2YcgjT0GEbXMSTiPIcDNoAmfy1Z4P9rg4lVgmqogUGdsf2rwrwDR1mNb0jiEoCENO8B+aEnzG6m3cteGQD3Kc34yuOjzYFZr6ciS0/0IB0arQZfVVG5Yl+w6uz9rfOmVzfLWlyCGnjmabkv7lQpLdjn/jjL1JGvkPQ1TEs7SY/OuxxICN6WaUoY2r/B5sCqYcb49RZCK11oVXTWZ94n/7GAAqPqrg/dX7SW3sufMDo8/fsaq/wApC8R9zsjMvL8LhEcuQkQQcpvxu8USVMXnuFjTcCWOuSnhIGtPiTQEsrITHBXw1ni3fWbGWOr3kR0aWK+aH7KBmH3/awTz4n7iQHzy+xBxhow60T4bm1f3hLMZsm6+R4T3/YNMazjkvfcDU/eNB3LFsyJEEnvh3uXSZYMmqN3TWVOB+Xt10Z6nGaGWxLcGtCpHBnnn/+xDTHpaM23WBRtULs1yQO+EWjuoL9X3m9oECsZKbCSjrX1o8vYyUAKu9j5ev+Tlu5IMqtKTq1X84rGYG9UL4IF5WxAEXTXo6zUnQUAhjKqTornV+a77nKdf00X+IgP5YgIofgJek8Ag2KqebAA8yAxtEU6MWQZga97cnhH4QFSgimHuulQ==\",\"sig\":\"a159f09ba959df020f359d77639469f3083cc362e9435cb9569f256915aa0a7289717e52b996aa57435bc7af3ffcba928fd0ee9d6251c05f143b72d350e2535b\"}",
		},
		{
			"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
			"",
			"",
			"9166c289b9f905e55f9e3df9f69d7f356b4a22095f894f4715714aa4b56606af",
			"40808ce2685b0aeaa756d05fc99853db0c79043210a3a949fdbc905ea2984c05",
			"{\"kind\":52,\"id\":\"2e9857c30aa364c83d769e7fa6e18bd7975fe58f2bcdb487f8e5289e60b216f2\",\"pubkey\":\"9166c289b9f905e55f9e3df9f69d7f356b4a22095f894f4715714aa4b56606af\",\"created_at\":1725402764,\"tags\":[[\"p\",\"4fe17162aa42c96d7757f98cabc8a0b38ceb61a9160195b5d16bce6f6d8064ca\"],[\"p\",\"8b57adf363f3abed31ea6e0b664884af07e2a92611154599345f6a63f9c70f02\"],[\"p\",\"741a0fb3d23db2c87f82a9a979084893c3f094c47776c1283dd313331fc4b308\"],[\"threshold\",\"2\"],[\"recovery-keys-setup\"]],\"content\":\"Setting up my first set of recovery keys! Yay!\",\"sig\":\"fe17c1ec586fbbf68f0588125d4476c28a4d5bfd9948832036fe00559794f2941161aa82605e59632877edbabe62e35c19d28faf1b676ffdb78a977043af663e\"}",
			int64(1725402765),
			"{\"kind\":53,\"id\":\"3c913a743a8f401b378e29d48b97e1c4a12b0ffb777fcfcde24221dd3301eede\",\"pubkey\":\"a706ad8f73115f90500266f273f7571df9429a4cfb4bbfbcd825227202dabad1\",\"created_at\":1725402765,\"tags\":[[\"p\",\"9166c289b9f905e55f9e3df9f69d7f356b4a22095f894f4715714aa4b56606af\"],[\"recovery-keys-attestation\"]],\"content\":\"{\\\"kind\\\":52,\\\"id\\\":\\\"2e9857c30aa364c83d769e7fa6e18bd7975fe58f2bcdb487f8e5289e60b216f2\\\",\\\"pubkey\\\":\\\"9166c289b9f905e55f9e3df9f69d7f356b4a22095f894f4715714aa4b56606af\\\",\\\"created_at\\\":1725402764,\\\"tags\\\":[[\\\"p\\\",\\\"4fe17162aa42c96d7757f98cabc8a0b38ceb61a9160195b5d16bce6f6d8064ca\\\"],[\\\"p\\\",\\\"8b57adf363f3abed31ea6e0b664884af07e2a92611154599345f6a63f9c70f02\\\"],[\\\"p\\\",\\\"741a0fb3d23db2c87f82a9a979084893c3f094c47776c1283dd313331fc4b308\\\"],[\\\"threshold\\\",\\\"2\\\"],[\\\"recovery-keys-setup\\\"]],\\\"content\\\":\\\"Setting up my first set of recovery keys! Yay!\\\",\\\"sig\\\":\\\"fe17c1ec586fbbf68f0588125d4476c28a4d5bfd9948832036fe00559794f2941161aa82605e59632877edbabe62e35c19d28faf1b676ffdb78a977043af663e\\\"}\",\"sig\":\"1969068dcce3b49bd69146fd372a551b899d1305c5614edbea5004dd8bb7e2b3aa076c8e86becf1f538caf2e97309b93b200be145d58a267a4605fd78c3be2df\"}",
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
		assert.Equal(t, vector.JSON, string(evtjson))
	}
}
