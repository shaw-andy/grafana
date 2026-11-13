package annotations

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSanitizeText(t *testing.T) {
	t.Run("keeps text without resource-loading markup unchanged", func(t *testing.T) {
		for _, text := range []string{
			"",
			"deploy finished",
			"a < b & c > d",
			"&lt;img src=x&gt;",
			`deploy <b>v2</b> see <a href="https://example.com/notes" target="_blank">notes</a>`,
			"line one\nline two<br>",
		} {
			require.Equal(t, text, SanitizeText(text))
		}
	})

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "img", input: `deploy <img src="/api/x" alt="">done`, expected: "deploy done"},
		{name: "image alias", input: `deploy <image src="/api/x">`, expected: "deploy "},
		{name: "entity-encoded src", input: `deploy <img src="&#47;api&#47;x">`, expected: "deploy "},
		{name: "uppercase tag", input: `deploy <IMG SRC="/api/x">`, expected: "deploy "},
		{name: "audio with source", input: `deploy <audio><source src="/api/x"></audio>`, expected: "deploy "},
		{name: "video poster", input: `deploy <video poster="/api/x"></video>`, expected: "deploy "},
		{name: "picture", input: `<picture><source srcset="/api/x"></picture>note`, expected: "note"},
		{name: "svg image", input: `<svg><image href="/api/x"></image></svg>note`, expected: "note"},
		{name: "stylesheet", input: `<style>@import "/api/x";</style>note`, expected: "note"},
		{name: "link", input: `<link rel="stylesheet" href="/api/x">note`, expected: "note"},
		{name: "noscript content", input: `<noscript><img src="/api/x"></noscript>note`, expected: "note"},
		{name: "nested in allowed markup", input: `<p><b>deploy <img src="/api/x"></b></p>`, expected: "<p><b>deploy </b></p>"},
		{name: "inline style", input: `<div style="background-image:url(/api/x)">note</div>`, expected: "<div>note</div>"},
		{name: "table background", input: `<table background="/api/x"><tbody><tr><td>note</td></tr></tbody></table>`, expected: "<table><tbody><tr><td>note</td></tr></tbody></table>"},
		{name: "link ping", input: `<a href="/d/abc" ping="/api/x">dash</a>`, expected: `<a href="/d/abc">dash</a>`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.expected, SanitizeText(tt.input))
		})
	}
}
