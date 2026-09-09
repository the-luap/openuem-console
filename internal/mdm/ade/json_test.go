package ade

import "testing"

func TestJSONRejectsCaseFoldedFieldAliases(t *testing.T) {
	for _, data := range []string{
		`{"access_secret":"first","ACCESS_SECRET":"second"}`,
		`{"access_secret":"first","acceſſ_ſecret":"second"}`,
		`{"consumer_key":"first","consumer_Key":"second"}`,
		`{"more_to_follow":true,"More_To_Follow":false}`,
		`{"devices":[],"nested":{"cursor":"first","CURSOR":"second"}}`,
	} {
		var out any
		if decodeJSON([]byte(data), &out) == nil {
			t.Fatal("case-folded duplicate accepted")
		}
	}
	var out struct{ Cursor string }
	if decodeJSON([]byte(`{"cursor":"next","future_field":{"supported":true}}`), &out) != nil || out.Cursor != "next" {
		t.Fatal("additive fields rejected")
	}
}
