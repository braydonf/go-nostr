package nipxx

import (
	"fmt"

	"github.com/nbd-wtf/go-nostr"
)

func MakeKeyRevocationEvent(
	pubKey string,
	successorPubKey string,
	comment string,
	createdAt nostr.Timestamp) *nostr.Event {

	evt := nostr.Event{}
	evt.CreatedAt = createdAt
	evt.Kind = KindKeyRevocation
	evt.PubKey = pubKey
	evt.Content = comment

	if len(successorPubKey) > 0 {
		evt.Tags = make([]nostr.Tag, 0, 2)
		evt.Tags = evt.Tags.AppendUnique(nostr.Tag{"successor-key", successorPubKey})
	} else {
		evt.Tags = make([]nostr.Tag, 0, 1)
	}

	evt.Tags = evt.Tags.AppendUnique(nostr.Tag{SafeguardKeyRevocation})

	return &evt
}

func ValidateKeyRevocationEvent(evt *nostr.Event) error {
	// Check the kind.
	if evt.Kind != KindKeyRevocation {
		return fmt.Errorf("invalid kind")
	}

	// Check the successor key.
	successorKey := evt.Tags.GetAll([]string{"successor-key"})

	if len(successorKey) > 0 {
		if len(successorKey) > 1 {
			return fmt.Errorf("must only include one successor key")
		}
	}

	// Check the safeguard tag.
	tags := evt.Tags.GetAll([]string{"key-revocation"})
	if len(tags) < 1 || len(tags) > 1 {
		return fmt.Errorf("must include one revocation safeguard tag")
	} else {
		if len(tags[0]) > 1 {
			return fmt.Errorf("must include one revocation safeguard tag value")
		}
	}

	return nil
}
