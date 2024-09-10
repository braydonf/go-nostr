package nipxx

import (
	"testing"
	"encoding/json"
	"encoding/hex"

	"github.com/stretchr/testify/assert"
	"github.com/nbd-wtf/go-nostr"
)

func TestAttestation(t *testing.T) {
	forPubKey := "0000000000000000000000000000000000000000000000000000000000000000"
	tags := nostr.Tags{
			nostr.Tag{"i", "twitter:satoshi", "0000000000000000000"},
			nostr.Tag{"i", "github:satoshi", "00000000000000000000000000000000"},
	}
	content := "{\"name\": \"Satoshi Nakamoto\", \"picture\": \"https://domain.tld/satoshi.jpg\", \"display_name\": \"Satoshi Nakamoto\", \"displayName\": \"Satoshi Nakamoto\", \"website\": \"https://domain.tld\",\"nip05\": \"satoshi@domain.tld\"}"
	expectedJSON := "{\"pubkey\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"tags\":[[\"i\",\"twitter:satoshi\",\"0000000000000000000\"],[\"i\",\"github:satoshi\",\"00000000000000000000000000000000\"]],\"content\":\"{\\\"name\\\": \\\"Satoshi Nakamoto\\\", \\\"picture\\\": \\\"https://domain.tld/satoshi.jpg\\\", \\\"display_name\\\": \\\"Satoshi Nakamoto\\\", \\\"displayName\\\": \\\"Satoshi Nakamoto\\\", \\\"website\\\": \\\"https://domain.tld\\\",\\\"nip05\\\": \\\"satoshi@domain.tld\\\"}\"}"

	atts := Attestation{forPubKey, tags, content}

	assert.Equal(t, atts.ForPubKey, forPubKey)
	assert.Equal(t, atts.Tags, tags)
	assert.Equal(t, atts.Content, content)

	actualJSON, err := json.Marshal(atts)

	assert.Nil(t, err)
	assert.Equal(t, expectedJSON, string(actualJSON))
}

func TestMakeUserMetadataAttestationEvent(t *testing.T) {
	for _, vector := range []struct {
		Attestation string
		CreatedAt nostr.Timestamp
		PredecessorPubKey string
		EncryptKey string
		EncryptSalt string
		ExpectedJSON string
	}{
		{
			"{\"pubkey\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"tags\":[[\"i\",\"twitter:satoshi\",\"0000000000000000000\"],[\"i\",\"github:satoshi\",\"00000000000000000000000000000000\"]],\"content\":\"{\\\"name\\\": \\\"Satoshi Nakamoto\\\", \\\"picture\\\": \\\"https://domain.tld/satoshi.jpg\\\", \\\"display_name\\\": \\\"Satoshi Nakamoto\\\", \\\"displayName\\\": \\\"Satoshi Nakamoto\\\", \\\"website\\\": \\\"https://domain.tld\\\",\\\"nip05\\\": \\\"satoshi@domain.tld\\\"}\"}",
			nostr.Timestamp(1724364679),
			"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			"0000000000000000000000000000000000000000000000000000000000000000",
			"1111111111111111111111111111111111111111111111111111111111111111",
			"{\"kind\":30050,\"created_at\":1724364679,\"tags\":[[\"d\",\"771e03f8d330d0320b3ef9cd6464285935c99fc77a0571e31e2fa12a8077ee25\"]],\"content\":\"AhERERERERERERERERERERERERERERERERERERERERERsXKM1vtipQPjEKIbtWvwPYeiJjRUZ97rYgBKH7FPDPhMh4YlD0IVqpvhE4H4CXNOQNo4BO8QcguhRmwuy5XkLL53pAa06cW+pwf7aS3Y8JIvibdZ4ulVLDKokiLtS3wE6iWui1Fzm0rmhrrm2XPVw8x5YPBA/9g5q0b67VTmLuwBFNii49KajezqXfaxZQuk2Mxe7Tlk1HBEwW9TqIzZqYJfCDNVh0luIVqhLKUt1hLuSxaDGC23K9yJlIwVK++zXMSdAqGodf1mBSqBT62rip2x0q41A4d3olvB7ZDsQpdSb0Rk+2i2X+sJytwctKb5sgCqcaMX/Ra4XSH7SUR5p8O3lTPZA5yMmQOFXb7BEX4B9SkpqOgH0XvK+CqOu6FfPAeIHbVWTQD3RDjCXJvGX0a5A4Wo6+/cEHqMTKp5PTWkGqLEAZgzIGoxmg2/zfSKUpQHJUesTEFfLcC8d0AeTzaNjKlGEAf9sQYQ84geJcdPvj6SupaRPCMcSyvwXMmSC/niuDP7hLcKYfS7ONbjbrPOUhAEF0Jsh97aWt/HzwQNNyXBkdy7YCuVh0DuKZAQ2KfoKLfDhPpDaO7PMgeUgsp6eDbRDZf0/z5BNStAgR8gBbkdQtrwEfkpBCoC19gvV64t+IMPl2Pds7b01aa7SPNCaQC38P3R961ekx9P1y4bHTjA9OW230UXYdTWYfkAR0YOSCJNGYDO2q1QEb1dwn5LKM6/XUVDbz6rgl8JwmtMJ6ldTN03lQNePAaFnmAYuUePvKdBZ1ZsEPZ9ThXNEiyJhD3i8yQ/GlLC1r9dJSPuWWA2DlalyjB2CqrCW0TvmrQ5P9c2x7t9h6R37BqP+ugDbjVSCYZBD1DBfPOeRckcMxr5b4npfgjtVHZrvBGKMJs=\"}",
		},
		{
			"{\"pubkey\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"tags\":[[\"i\",\"twitter:satoshi\",\"0000000000000000000\"],[\"i\",\"github:satoshi\",\"00000000000000000000000000000000\"]],\"content\":\"{\\\"name\\\": \\\"Satoshi Nakamoto\\\", \\\"picture\\\": \\\"https://domain.tld/satoshi.jpg\\\", \\\"display_name\\\": \\\"Satoshi Nakamoto\\\", \\\"displayName\\\": \\\"Satoshi Nakamoto\\\", \\\"website\\\": \\\"https://domain.tld\\\",\\\"nip05\\\": \\\"satoshi@domain.tld\\\"}\"}",
			nostr.Timestamp(1724364679),
			"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			"",
			"",
			"{\"kind\":30050,\"created_at\":1724364679,\"tags\":[[\"p\",\"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\"],[\"d\",\"0000000000000000000000000000000000000000000000000000000000000000\"],[\"p\",\"0000000000000000000000000000000000000000000000000000000000000000\"],[\"attestation\",\"{\\\"pubkey\\\":\\\"0000000000000000000000000000000000000000000000000000000000000000\\\",\\\"tags\\\":[[\\\"i\\\",\\\"twitter:satoshi\\\",\\\"0000000000000000000\\\"],[\\\"i\\\",\\\"github:satoshi\\\",\\\"00000000000000000000000000000000\\\"]],\\\"content\\\":\\\"{\\\\\\\"name\\\\\\\": \\\\\\\"Satoshi Nakamoto\\\\\\\", \\\\\\\"picture\\\\\\\": \\\\\\\"https://domain.tld/satoshi.jpg\\\\\\\", \\\\\\\"display_name\\\\\\\": \\\\\\\"Satoshi Nakamoto\\\\\\\", \\\\\\\"displayName\\\\\\\": \\\\\\\"Satoshi Nakamoto\\\\\\\", \\\\\\\"website\\\\\\\": \\\\\\\"https://domain.tld\\\\\\\",\\\\\\\"nip05\\\\\\\": \\\\\\\"satoshi@domain.tld\\\\\\\"}\\\"}\"]],\"content\":\"\"}",
		},
	} {
		encryptKey, err := hex.DecodeString(vector.EncryptKey)
		assert.Nil(t, err)

		encryptSalt, err := hex.DecodeString(vector.EncryptSalt)
		assert.Nil(t, err)

		var atts Attestation
		err = json.Unmarshal([]byte(vector.Attestation), &atts)
		assert.Nil(t, err)

		evt, err := MakeUserMetadataAttestationEvent(
			&atts,
			vector.CreatedAt,
			vector.PredecessorPubKey,
			encryptKey,
			encryptSalt)
		assert.Nil(t, err)

		actualJSON, err := json.Marshal(evt)
		assert.Nil(t, err)
		assert.Equal(t, vector.ExpectedJSON, string(actualJSON))
	}
}

func TestValidateUserMetadataAttestationEvent(t *testing.T) {
	for _, vector := range []struct {
		JSON string
		ExpectedError string
	}{
		{
			"{\"kind\":30050,\"created_at\":1724364679,\"tags\":[[\"p\",\"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\"],[\"d\",\"0000000000000000000000000000000000000000000000000000000000000000\"],[\"p\",\"0000000000000000000000000000000000000000000000000000000000000000\"],[\"attestation\",\"{\\\"pubkey\\\":\\\"0000000000000000000000000000000000000000000000000000000000000000\\\",\\\"tags\\\":[[\\\"i\\\",\\\"twitter:satoshi\\\",\\\"0000000000000000000\\\"],[\\\"i\\\",\\\"github:satoshi\\\",\\\"00000000000000000000000000000000\\\"]],\\\"content\\\":\\\"{\\\\\\\"name\\\\\\\": \\\\\\\"Satoshi Nakamoto\\\\\\\", \\\\\\\"picture\\\\\\\": \\\\\\\"https://domain.tld/satoshi.jpg\\\\\\\", \\\\\\\"display_name\\\\\\\": \\\\\\\"Satoshi Nakamoto\\\\\\\", \\\\\\\"displayName\\\\\\\": \\\\\\\"Satoshi Nakamoto\\\\\\\", \\\\\\\"website\\\\\\\": \\\\\\\"https://domain.tld\\\\\\\",\\\\\\\"nip05\\\\\\\": \\\\\\\"satoshi@domain.tld\\\\\\\"}\\\"}\"]],\"content\":\"\"}",
			"",
		},
		{
			"{\"kind\":30051,\"created_at\":1724364679,\"tags\":[[\"p\",\"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\"],[\"d\",\"0000000000000000000000000000000000000000000000000000000000000000\"],[\"p\",\"0000000000000000000000000000000000000000000000000000000000000000\"],[\"attestation\",\"{\\\"pubkey\\\":\\\"0000000000000000000000000000000000000000000000000000000000000000\\\",\\\"tags\\\":[[\\\"i\\\",\\\"twitter:satoshi\\\",\\\"0000000000000000000\\\"],[\\\"i\\\",\\\"github:satoshi\\\",\\\"00000000000000000000000000000000\\\"]],\\\"content\\\":\\\"{\\\\\\\"name\\\\\\\": \\\\\\\"Satoshi Nakamoto\\\\\\\", \\\\\\\"picture\\\\\\\": \\\\\\\"https://domain.tld/satoshi.jpg\\\\\\\", \\\\\\\"display_name\\\\\\\": \\\\\\\"Satoshi Nakamoto\\\\\\\", \\\\\\\"displayName\\\\\\\": \\\\\\\"Satoshi Nakamoto\\\\\\\", \\\\\\\"website\\\\\\\": \\\\\\\"https://domain.tld\\\\\\\",\\\\\\\"nip05\\\\\\\": \\\\\\\"satoshi@domain.tld\\\\\\\"}\\\"}\"]],\"content\":\"\"}",
			"invalid kind",
		},
		{
			"{\"kind\":30050,\"created_at\":1724364679,\"tags\":[[\"p\",\"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\"],[\"p\",\"0000000000000000000000000000000000000000000000000000000000000000\"],[\"attestation\",\"{\\\"pubkey\\\":\\\"0000000000000000000000000000000000000000000000000000000000000000\\\",\\\"tags\\\":[[\\\"i\\\",\\\"twitter:satoshi\\\",\\\"0000000000000000000\\\"],[\\\"i\\\",\\\"github:satoshi\\\",\\\"00000000000000000000000000000000\\\"]],\\\"content\\\":\\\"{\\\\\\\"name\\\\\\\": \\\\\\\"Satoshi Nakamoto\\\\\\\", \\\\\\\"picture\\\\\\\": \\\\\\\"https://domain.tld/satoshi.jpg\\\\\\\", \\\\\\\"display_name\\\\\\\": \\\\\\\"Satoshi Nakamoto\\\\\\\", \\\\\\\"displayName\\\\\\\": \\\\\\\"Satoshi Nakamoto\\\\\\\", \\\\\\\"website\\\\\\\": \\\\\\\"https://domain.tld\\\\\\\",\\\\\\\"nip05\\\\\\\": \\\\\\\"satoshi@domain.tld\\\\\\\"}\\\"}\"]],\"content\":\"\"}",
			"must include one d tag",
		},
		{
			"{\"kind\":30050,\"created_at\":1724364679,\"tags\":[[\"d\",\"0000000000000000000000000000000000000000000000000000000000000000\"],[\"attestation\",\"{\\\"pubkey\\\":\\\"0000000000000000000000000000000000000000000000000000000000000000\\\",\\\"tags\\\":[[\\\"i\\\",\\\"twitter:satoshi\\\",\\\"0000000000000000000\\\"],[\\\"i\\\",\\\"github:satoshi\\\",\\\"00000000000000000000000000000000\\\"]],\\\"content\\\":\\\"{\\\\\\\"name\\\\\\\": \\\\\\\"Satoshi Nakamoto\\\\\\\", \\\\\\\"picture\\\\\\\": \\\\\\\"https://domain.tld/satoshi.jpg\\\\\\\", \\\\\\\"display_name\\\\\\\": \\\\\\\"Satoshi Nakamoto\\\\\\\", \\\\\\\"displayName\\\\\\\": \\\\\\\"Satoshi Nakamoto\\\\\\\", \\\\\\\"website\\\\\\\": \\\\\\\"https://domain.tld\\\\\\\",\\\\\\\"nip05\\\\\\\": \\\\\\\"satoshi@domain.tld\\\\\\\"}\\\"}\"]],\"content\":\"\"}",
			"public attestation must include public tags",
		},
		{
			"{\"kind\":30050,\"created_at\":1724364679,\"tags\":[[\"p\",\"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\"],[\"d\",\"0000000000000000000000000000000000000000000000000000000000000000\"],[\"p\",\"0000000000000000000000000000000000000000000000000000000000000000\"]],\"content\":\"\"}",
			"public attestation must include public tags",
		},
		{
			"{\"kind\":30050,\"created_at\":1724364679,\"tags\":[[\"d\",\"771e03f8d330d0320b3ef9cd6464285935c99fc77a0571e31e2fa12a8077ee25\"]],\"content\":\"AhERERERERERERERERERERERERERERERERERERERERERsXKM1vtipQPjEKIbtWvwPYeiJjRUZ97rYgBKH7FPDPhMh4YlD0IVqpvhE4H4CXNOQNo4BO8QcguhRmwuy5XkLL53pAa06cW+pwf7aS3Y8JIvibdZ4ulVLDKokiLtS3wE6iWui1Fzm0rmhrrm2XPVw8x5YPBA/9g5q0b67VTmLuwBFNii49KajezqXfaxZQuk2Mxe7Tlk1HBEwW9TqIzZqYJfCDNVh0luIVqhLKUt1hLuSxaDGC23K9yJlIwVK++zXMSdAqGodf1mBSqBT62rip2x0q41A4d3olvB7ZDsQpdSb0Rk+2i2X+sJytwctKb5sgCqcaMX/Ra4XSH7SUR5p8O3lTPZA5yMmQOFXb7BEX4B9SkpqOgH0XvK+CqOu6FfPAeIHbVWTQD3RDjCXJvGX0a5A4Wo6+/cEHqMTKp5PTWkGqLEAZgzIGoxmg2/zfSKUpQHJUesTEFfLcC8d0AeTzaNjKlGEAf9sQYQ84geJcdPvj6SupaRPCMcSyvwXMmSC/niuDP7hLcKYfS7ONbjbrPOUhAEF0Jsh97aWt/HzwQNNyXBkdy7YCuVh0DuKZAQ2KfoKLfDhPpDaO7PMgeUgsp6eDbRDZf0/z5BNStAgR8gBbkdQtrwEfkpBCoC19gvV64t+IMPl2Pds7b01aa7SPNCaQC38P3R961ekx9P1y4bHTjA9OW230UXYdTWYfkAR0YOSCJNGYDO2q1QEb1dwn5LKM6/XUVDbz6rgl8JwmtMJ6ldTN03lQNePAaFnmAYuUePvKdBZ1ZsEPZ9ThXNEiyJhD3i8yQ/GlLC1r9dJSPuWWA2DlalyjB2CqrCW0TvmrQ5P9c2x7t9h6R37BqP+ugDbjVSCYZBD1DBfPOeRckcMxr5b4npfgjtVHZrvBGKMJs=\"}",
			"",
		},
		{
			"{\"kind\":30050,\"created_at\":1724364679,\"tags\":[[\"p\",\"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\"],[\"d\",\"771e03f8d330d0320b3ef9cd6464285935c99fc77a0571e31e2fa12a8077ee25\"],[\"p\",\"0000000000000000000000000000000000000000000000000000000000000000\"],[\"attestation\",\"{\\\"pubkey\\\":\\\"0000000000000000000000000000000000000000000000000000000000000000\\\",\\\"tags\\\":[[\\\"i\\\",\\\"twitter:satoshi\\\",\\\"0000000000000000000\\\"],[\\\"i\\\",\\\"github:satoshi\\\",\\\"00000000000000000000000000000000\\\"]],\\\"content\\\":\\\"{\\\\\\\"name\\\\\\\": \\\\\\\"Satoshi Nakamoto\\\\\\\", \\\\\\\"picture\\\\\\\": \\\\\\\"https://domain.tld/satoshi.jpg\\\\\\\", \\\\\\\"display_name\\\\\\\": \\\\\\\"Satoshi Nakamoto\\\\\\\", \\\\\\\"displayName\\\\\\\": \\\\\\\"Satoshi Nakamoto\\\\\\\", \\\\\\\"website\\\\\\\": \\\\\\\"https://domain.tld\\\\\\\",\\\\\\\"nip05\\\\\\\": \\\\\\\"satoshi@domain.tld\\\\\\\"}\\\"}\"]],\"content\":\"AhERERERERERERERERERERERERERERERERERERERERERsXKM1vtipQPjEKIbtWvwPYeiJjRUZ97rYgBKH7FPDPhMh4YlD0IVqpvhE4H4CXNOQNo4BO8QcguhRmwuy5XkLL53pAa06cW+pwf7aS3Y8JIvibdZ4ulVLDKokiLtS3wE6iWui1Fzm0rmhrrm2XPVw8x5YPBA/9g5q0b67VTmLuwBFNii49KajezqXfaxZQuk2Mxe7Tlk1HBEwW9TqIzZqYJfCDNVh0luIVqhLKUt1hLuSxaDGC23K9yJlIwVK++zXMSdAqGodf1mBSqBT62rip2x0q41A4d3olvB7ZDsQpdSb0Rk+2i2X+sJytwctKb5sgCqcaMX/Ra4XSH7SUR5p8O3lTPZA5yMmQOFXb7BEX4B9SkpqOgH0XvK+CqOu6FfPAeIHbVWTQD3RDjCXJvGX0a5A4Wo6+/cEHqMTKp5PTWkGqLEAZgzIGoxmg2/zfSKUpQHJUesTEFfLcC8d0AeTzaNjKlGEAf9sQYQ84geJcdPvj6SupaRPCMcSyvwXMmSC/niuDP7hLcKYfS7ONbjbrPOUhAEF0Jsh97aWt/HzwQNNyXBkdy7YCuVh0DuKZAQ2KfoKLfDhPpDaO7PMgeUgsp6eDbRDZf0/z5BNStAgR8gBbkdQtrwEfkpBCoC19gvV64t+IMPl2Pds7b01aa7SPNCaQC38P3R961ekx9P1y4bHTjA9OW230UXYdTWYfkAR0YOSCJNGYDO2q1QEb1dwn5LKM6/XUVDbz6rgl8JwmtMJ6ldTN03lQNePAaFnmAYuUePvKdBZ1ZsEPZ9ThXNEiyJhD3i8yQ/GlLC1r9dJSPuWWA2DlalyjB2CqrCW0TvmrQ5P9c2x7t9h6R37BqP+ugDbjVSCYZBD1DBfPOeRckcMxr5b4npfgjtVHZrvBGKMJs=\"}",
			"private attestation must not include public tags",
		},
		{
			"{\"kind\":30050,\"created_at\":1724364679,\"tags\":[[\"d\",\"771e03f8d330d0320b3ef9cd6464285935c99fc77a0571e31e2fa12a8077ee25\"]],\"content\":\"something not very base64\"}",
			"private content must be base64",
		},
	} {
		var evt nostr.Event
		err := json.Unmarshal([]byte(vector.JSON), &evt)
		assert.Nil(t, err)

		err = ValidateUserMetadataAttestationEvent(&evt)

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
