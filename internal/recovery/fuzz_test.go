package recovery

import (
	"encoding/json"
	"reflect"
	"testing"
)

func FuzzRecoveryBundle(f *testing.F) {
	for _, seed := range []string{
		`{"version":1,"backup_id":"5bdf7d17-81ca-41f1-a719-487219d434e8","environment":{"SYNTHETIC":"value"},"files":{"key.pem":"YQ=="}}`,
		`{"version":1,"Version":2}`, `{"files":{"../outside":"YQ=="}}`,
		`{"environment":{"SYNTHETIC":"\u0000"}}`, `{"files":{"NUL":""}}`,
		`{"files":{"key":"YQ==","Key":"Yg=="}}`, `{"files":{"key":"%%%"}}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxHeaderBytes {
			return
		}
		var b recoveryBundle
		defer b.clear()
		if decodeJSON(data, &b) != nil || validateBundle(&b) != nil {
			return
		}
		encoded, err := json.Marshal(&b)
		if err != nil {
			t.Fatal("validated recovery bundle cannot be encoded")
		}
		defer clear(encoded)
		var roundTrip recoveryBundle
		defer roundTrip.clear()
		if decodeJSON(encoded, &roundTrip) != nil || validateBundle(&roundTrip) != nil || !reflect.DeepEqual(b, roundTrip) {
			t.Fatal("validated recovery bundle changed during canonical encoding")
		}
	})
}
