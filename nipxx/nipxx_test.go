package nipxx

import (
	"testing"
	"encoding/json"
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
			"{\"kind\":51,\"id\":\"40808ce2685b0aeaa756d05fc99853db0c79043210a3a949fdbc905ea2984c05\",\"pubkey\":\"9166c289b9f905e55f9e3df9f69d7f356b4a22095f894f4715714aa4b56606af\",\"created_at\":1725402764,\"tags\":[[\"p\",\"4fe17162aa42c96d7757f98cabc8a0b38ceb61a9160195b5d16bce6f6d8064ca\"],[\"p\",\"8b57adf363f3abed31ea6e0b664884af07e2a92611154599345f6a63f9c70f02\"],[\"p\",\"741a0fb3d23db2c87f82a9a979084893c3f094c47776c1283dd313331fc4b308\"],[\"threshold\",\"2\"],[\"recovery-keys-setup\"]],\"content\":\"Setting up my first set of recovery keys! Yay!\",\"sig\":\"8e73482ffae5261edb5181960a8d50974de468f20ea9f505cb57812e348ee920468dbb390ab39b497e33ac9aa2e6f784305bea831b232585171ab0878c04c4b3\"}",
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
