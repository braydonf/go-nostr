package nipxx

import (
	"crypto/sha256"
	"fmt"
	"encoding/json"
	"encoding/base64"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip44"
)

type Attestation struct {
	ForPubKey string `json:"pubkey,omitempty"`
	Tags nostr.Tags `json:"tags,omitempty"`
	Content string `json:"content,omitempty"`
}

func MakeUserMetadataAttestationEvent(
	attestation *Attestation,
	createdAt nostr.Timestamp,
	predecessorPubKey string,
	encryptKey []byte,
	encryptSalt []byte) (*nostr.Event, error) {

	evt := nostr.Event{}
	evt.CreatedAt = createdAt
	evt.Kind = KindUserMetadataAttestation

	if len(encryptKey) > 0 {
		evt.Tags = make([]nostr.Tag, 0, 1)

		// Create a unique private d tag using their
		// public key and encrypting and hashing it.

		cypherpub, err := nip44.Encrypt(
			attestation.ForPubKey,
			encryptKey,
			nip44.WithCustomSalt(encryptSalt))

		if err != nil {
			return nil, err
		}

		cypherbytes, err := base64.StdEncoding.DecodeString(cypherpub)

		if err != nil {
			return nil, err
		}

		cyphersum := fmt.Sprintf("%x", sha256.Sum256(cypherbytes))

		evt.Tags = evt.Tags.AppendUnique(nostr.Tag{"d", cyphersum})

		// Include all of the private tags in the content
		// and encrypt it to ourselves.

		ptags := nostr.Tags(make([]nostr.Tag, 0, 3))
		ptags = ptags.AppendUnique(nostr.Tag{"p", attestation.ForPubKey})

		atts, err := json.Marshal(attestation)
		if err != nil {
			return nil, err
		}

		ptags = ptags.AppendUnique(nostr.Tag{"attestation", string(atts)})

		tagsJSON, err := json.Marshal(ptags)
		if err != nil {
			return nil, err
		}

		cyphertext, err := nip44.Encrypt(
			string(tagsJSON), encryptKey, nip44.WithCustomSalt(encryptSalt))

		if err != nil {
			return nil, err
		}

		evt.Content = cyphertext
	} else {
		// Public tags for all.
		if len(predecessorPubKey) > 0 {
			evt.Tags = make([]nostr.Tag, 0, 4)
			evt.Tags = evt.Tags.AppendUnique(nostr.Tag{"p", predecessorPubKey})
		} else {
			evt.Tags = make([]nostr.Tag, 0, 3)
		}

		evt.Tags = evt.Tags.AppendUnique(nostr.Tag{"d", attestation.ForPubKey})
		evt.Tags = evt.Tags.AppendUnique(nostr.Tag{"p", attestation.ForPubKey})

		atts, err := json.Marshal(attestation)
		if err != nil {
			return nil, err
		}

		evt.Tags = evt.Tags.AppendUnique(nostr.Tag{"attestation", string(atts)})
	}

	return &evt, nil
}

func ValidateUserMetadataAttestationEvent(evt *nostr.Event) error {
	// Check the kind.
	if evt.Kind != KindUserMetadataAttestation {
		return fmt.Errorf("invalid kind")
	}

	// Must include one d tag.
	lenDtags := len(evt.Tags.GetAll([]string{"d"}))
	if lenDtags == 0 || lenDtags > 1 {
		return fmt.Errorf("must include one d tag")
	}

	if len(evt.Content) > 0 {
		// If content is non-empty (private), public tags must not be included.
		if len(evt.Tags.GetAll([]string{"p"})) > 0 ||
			len(evt.Tags.GetAll([]string{"attestation"})) > 0 {
			return fmt.Errorf("private attestation must not include public tags")
		}

		// Content, if available, must be base64 encoded.
		_, err := base64.StdEncoding.DecodeString(evt.Content)
		if err != nil {
			return fmt.Errorf("private content must be base64")
		}
	} else {
		if len(evt.Tags.GetAll([]string{"p"})) == 0 ||
			len(evt.Tags.GetAll([]string{"attestation"})) == 0 {
			return fmt.Errorf("public attestation must include public tags")
		}
	}

	return nil
}
