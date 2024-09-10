package nipxx

import (
	"testing"
	"encoding/json"

	"github.com/stretchr/testify/assert"
	"github.com/nbd-wtf/go-nostr"
)

func TestMakeKeyRevocationEvent(t *testing.T) {
	for _, vector := range []struct {
		PubKey string
		SuccessorPubKey string
		Comment string
		CreatedAt nostr.Timestamp
		ExpectedJSON string
	}{
		{
			"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
			"This is an optional comment.",
			nostr.Timestamp(1725402774),
			"{\"kind\":50,\"pubkey\":\"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\",\"created_at\":1725402774,\"tags\":[[\"successor-key\",\"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\"],[\"key-revocation\"]],\"content\":\"This is an optional comment.\"}",
		},
	} {
		// Make the migration event.
		revocation := MakeKeyRevocationEvent(
			vector.PubKey,
			vector.SuccessorPubKey,
			vector.Comment,
			vector.CreatedAt)

		actualJSON, err := json.Marshal(revocation)

		assert.Nil(t, err)
		assert.Equal(t, vector.ExpectedJSON, string(actualJSON))
	}
}

func TestValidateKeyMigrationAndRevocationEvent(t *testing.T) {
	for _, vector := range []struct {
		JSON string
		ExpectedError string
	}{
		{
			"{\"kind\":50,\"pubkey\":\"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\",\"created_at\":1725402774,\"tags\":[[\"successor-key\",\"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\"],[\"key-revocation\"]],\"content\":\"This is an optional comment.\"}",
			"",
		},
		{
			"{\"kind\":51,\"pubkey\":\"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\",\"created_at\":1725402774,\"tags\":[[\"successor-key\",\"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\"],[\"key-revocation\"]],\"content\":\"This is an optional comment.\"}",
			"invalid kind",
		},
		{
			"{\"kind\":50,\"pubkey\":\"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\",\"created_at\":1725402774,\"tags\":[[\"successor-key\",\"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\"]],\"content\":\"This is an optional comment.\"}",
			"must include one revocation safeguard tag",
		},
		{
			"{\"kind\":50,\"pubkey\":\"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\",\"created_at\":1725402774,\"tags\":[[\"successor-key\",\"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\"],[\"key-revocation\"],[\"key-revocation\"]],\"content\":\"This is an optional comment.\"}",
			"must include one revocation safeguard tag",
		},
		{
			"{\"kind\":50,\"pubkey\":\"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\",\"created_at\":1725402774,\"tags\":[[\"successor-key\",\"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\"],[\"key-revocation\",\"key-revocation\"]],\"content\":\"This is an optional comment.\"}",
			"must include one revocation safeguard tag value",
		},
	} {
		var evt nostr.Event
		err := json.Unmarshal([]byte(vector.JSON), &evt)
		assert.Nil(t, err)

		err = ValidateKeyRevocationEvent(&evt)

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
