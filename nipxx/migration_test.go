package nipxx

import (
	"testing"
	"encoding/json"

	"github.com/stretchr/testify/assert"
	"github.com/nbd-wtf/go-nostr"
)

func TestEventSignExternal(t *testing.T) {
	for _, vector := range []struct {
		Event string
		PrivateKey string
		ExpectedSig string
	}{
		{
			"{\"kind\":50,\"pubkey\":\"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\",\"created_at\":1725402774,\"tags\":[[\"successor-key\",\"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\"],[\"key-revocation\"]],\"content\":\"This is an optional comment.\"}",
			"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			"22c3087c7cab53a4e4374fd6f9447404cb8b3a2bf2d014ee8892110267fb0551ca662cb52697286cededf0f7d2ad9f36626b6b711b26b63e97cfff392dcb58d0",
		},
	} {
		var evt nostr.Event
		err := json.Unmarshal([]byte(vector.Event), &evt)
		assert.Nil(t, err)

		sig, err := EventSignExternal(&evt, vector.PrivateKey)
		assert.Nil(t, err)

		assert.Equal(t, vector.ExpectedSig, string(sig))
	}
}

func TestEventVerifySignatureExternal(t *testing.T) {
	for _, vector := range []struct {
		Event string
		PublicKey string
		Sig string
		Result bool
	}{
		{
			"{\"kind\":50,\"pubkey\":\"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\",\"created_at\":1725402774,\"tags\":[[\"successor-key\",\"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\"],[\"key-revocation\"]],\"content\":\"This is an optional comment.\"}",
			"9166c289b9f905e55f9e3df9f69d7f356b4a22095f894f4715714aa4b56606af",
			"22c3087c7cab53a4e4374fd6f9447404cb8b3a2bf2d014ee8892110267fb0551ca662cb52697286cededf0f7d2ad9f36626b6b711b26b63e97cfff392dcb58d0",
			true,
		},
	} {
		var evt nostr.Event
		err := json.Unmarshal([]byte(vector.Event), &evt)
		assert.Nil(t, err)

		valid, err := EventVerifySignatureExternal(&evt, vector.PublicKey, vector.Sig)
		assert.Nil(t, err)

		assert.Equal(t, vector.Result, valid)
	}
}
