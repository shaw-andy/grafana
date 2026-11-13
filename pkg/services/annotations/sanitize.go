package annotations

import (
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// Annotation text is rendered as HTML for every viewer of a dashboard, so anything that makes the
// browser fetch a URL on render would be requested with the viewer's session. These elements are
// dropped together with their content. noscript, noembed, noframes, svg and math are included
// because browsers and sanitizers can parse their content differently.
var resourceLoadingElements = map[string]bool{
	"applet":      true,
	"audio":       true,
	"base":        true,
	"embed":       true,
	"fencedframe": true,
	"frame":       true,
	"frameset":    true,
	"iframe":      true,
	"image":       true,
	"img":         true,
	"input":       true,
	"link":        true,
	"math":        true,
	"meta":        true,
	"noembed":     true,
	"noframes":    true,
	"noscript":    true,
	"object":      true,
	"picture":     true,
	"portal":      true,
	"script":      true,
	"source":      true,
	"style":       true,
	"svg":         true,
	"track":       true,
	"video":       true,
}

var resourceLoadingAttributes = map[string]bool{
	"background": true,
	"data":       true,
	"dynsrc":     true,
	"lowsrc":     true,
	"ping":       true,
	"poster":     true,
	"src":        true,
	"srcset":     true,
	"style":      true,
}

// SanitizeText removes markup from annotation text that makes a browser request a URL as soon as
// the text is rendered, such as images, audio, video, embedded documents and stylesheets.
// Text without such markup is returned unchanged.
func SanitizeText(text string) string {
	if !strings.Contains(text, "<") {
		return text
	}

	body := &html.Node{Type: html.ElementNode, Data: "body", DataAtom: atom.Body}
	nodes, err := html.ParseFragment(strings.NewReader(text), body)
	if err != nil {
		return html.EscapeString(text)
	}
	for _, n := range nodes {
		body.AppendChild(n)
	}

	if !stripResourceLoads(body) {
		return text
	}

	var sb strings.Builder
	for c := body.FirstChild; c != nil; c = c.NextSibling {
		if err := html.Render(&sb, c); err != nil {
			return html.EscapeString(text)
		}
	}
	return sb.String()
}

func stripResourceLoads(n *html.Node) bool {
	changed := false

	attrs := n.Attr[:0]
	for _, a := range n.Attr {
		if resourceLoadingAttributes[strings.ToLower(a.Key)] {
			changed = true
			continue
		}
		attrs = append(attrs, a)
	}
	n.Attr = attrs

	for c := n.FirstChild; c != nil; {
		next := c.NextSibling
		if c.Type == html.ElementNode && resourceLoadingElements[strings.ToLower(c.Data)] {
			n.RemoveChild(c)
			changed = true
		} else if stripResourceLoads(c) {
			changed = true
		}
		c = next
	}

	return changed
}
