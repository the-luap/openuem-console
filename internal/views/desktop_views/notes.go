package desktop_views

import (
	"github.com/gomarkdown/markdown"
	"github.com/microcosm-cc/bluemonday"
)

func notesPreview(notes string) string {
	// Links remain usable, but opening a private note must not contact image
	// servers named by its author. Sanitize after Markdown renders raw HTML.
	return string(notesTextPolicy.SanitizeBytes(markdown.ToHTML([]byte(notes), nil, nil)))
}

var notesTextPolicy = func() *bluemonday.Policy {
	p := bluemonday.NewPolicy()
	p.AllowElements("p", "br", "hr", "strong", "b", "em", "i", "del", "s", "blockquote", "pre", "code", "ul", "ol", "li", "h1", "h2", "h3", "h4", "h5", "h6", "table", "thead", "tbody", "tr", "th", "td", "a")
	p.AllowAttrs("href", "title").OnElements("a")
	p.AllowStandardURLs()
	p.RequireNoFollowOnLinks(true)
	p.AllowAttrs("start").OnElements("ol")
	return p
}()
