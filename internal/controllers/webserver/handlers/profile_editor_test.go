package handlers

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
)

func TestProfileEditorStrictReadAndTagForms(t *testing.T) {
	for _, tc := range []struct {
		method, path, body string
		valid              bool
	}{
		{"POST", "/profiles/17/tags", "agentId=17&tagId=42", true},
		{"DELETE", "/profiles/17/tags?agentId=17&tagId=42&page=2&q=owned%26tag", "", true},
		{"POST", "/profiles/17/tags", "agentId=17&tagId=42&unknown=x", false},
		{"POST", "/profiles/17/tags", "agentId=17&tagId=042", false},
		{"POST", "/profiles/17/tags", "agentId=17&tagId=42&tagId=43", false},
		{"POST", "/profiles/17/tags?tagId=43", "agentId=17&tagId=42", false},
		{"POST", "/profiles/17/tags?", "agentId=17&tagId=42", false},
		{"DELETE", "/profiles/17/tags?agentId=17&tagId=42", "tagId=43", false},
		{"DELETE", "/profiles/17/tags?agentId=18&tagId=42", "", false},
		{"DELETE", "/profiles/17/tags?agentId=17&tagId=42&page=01", "", false},
		{"POST", "/profiles/17/tags", "agentId=17&tagId=42&q=%00", false},
		{"POST", "/profiles/17/tags", "agentId=17&tagId=42&q=%FF", false},
		{"POST", "/profiles/17/tags", "agentId=17&tagId=42&q=" + strings.Repeat("x", 257), false},
		{"POST", "/profiles/17/tags", "agentId=17&tagId=42" + strings.Repeat("&", 8192), false},
	} {
		r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		c := echo.New().NewContext(r, httptest.NewRecorder())
		c.SetParamNames("uuid")
		c.SetParamValues("17")
		id, _, err := profileTagForm(c)
		if tc.valid {
			require.NoError(t, err)
			require.Equal(t, int64(42), id)
		} else {
			require.Error(t, err)
		}
	}
	for _, tc := range []struct {
		query       string
		tags, valid bool
	}{
		{"page=2&pageSize=5", false, true}, {"page=2&q=owned%26tag", true, true}, {"q=owned", false, false}, {"pageSize=5", true, false}, {"q=%00", true, false}, {"q=%FF", true, false}, {"q=a&q=b", true, false}, {"unknown=x", false, false},
	} {
		c := echo.New().NewContext(httptest.NewRequest("GET", "/profiles/17?"+tc.query, nil), httptest.NewRecorder())
		_, err := profileReadQuery(c, tc.tags)
		if tc.valid {
			require.NoError(t, err)
		} else {
			require.Error(t, err)
		}
	}
}
