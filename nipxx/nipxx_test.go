package nipxx

import (
	"testing"
	"github.com/stretchr/testify/assert"
)

func TestMakeRecoveryKeysSetup(t *testing.T) {
	for _, vector := range []struct {
		PubKeys []string
		Threshold  int
		Comment string
		Error string
	}{
		{[]string{"4fe17162aa42c96d7757f98cabc8a0b38ceb61a9160195b5d16bce6f6d8064ca", "8b57adf363f3abed31ea6e0b664884af07e2a92611154599345f6a63f9c70f02", "741a0fb3d23db2c87f82a9a979084893c3f094c47776c1283dd313331fc4b308"}, 2, "Setting up my first set of recovery keys! Yay!", ""},
		{[]string{"4fe17162aa42c96d7757f98cabc8a0b38ceb61a9160195b5d16bce6f6d8064ca", "8b57adf363f3abed31ea6e0b664884af07e2a92611154599345f6a63f9c70f02", "741a0fb3d23db2c87f82a9a979084893c3f094c47776c1283dd313331fc4b308"}, 0, "Doing something illogical!", "Threshold must not be zero."},
	} {
		err, setup := MakeRecoveryKeysSetup(vector.PubKeys, vector.Threshold, vector.Comment)

		if vector.Error == "" {
			assert.Nil(t, err)
			assert.Equal(t, setup.Comment, vector.Comment)
			assert.Equal(t, setup.RecoveryPubKeys, vector.PubKeys)
			assert.Equal(t, setup.Threshold, vector.Threshold)
		} else {
			assert.NotNil(t, err)
			assert.Errorf(t, err, vector.Error, err)
		}
	}
}
