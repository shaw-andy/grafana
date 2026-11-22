package api

import (
	"errors"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/web"
)

// getLocalImageAttachment serves screenshots stored by the local external image
// storage provider. Screenshots can show private dashboards from any org, so
// they are only served to signed-in, non-anonymous users and never marked as
// cacheable by shared caches.
func (hs *HTTPServer) getLocalImageAttachment(c *contextmodel.ReqContext) {
	name := web.Params(c.Req)[":file"]
	if name == "" || name != filepath.Base(name) || strings.ContainsAny(name, `/\`) || !strings.EqualFold(filepath.Ext(name), ".png") {
		c.JsonApiErr(http.StatusNotFound, "Image not found", nil)
		return
	}

	root, err := os.OpenRoot(hs.Cfg.ImagesDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			c.JsonApiErr(http.StatusNotFound, "Image not found", nil)
			return
		}
		c.JsonApiErr(http.StatusInternalServerError, "Could not open images directory", err)
		return
	}
	defer func() { _ = root.Close() }()

	f, err := root.Open(name)
	if err != nil {
		c.JsonApiErr(http.StatusNotFound, "Image not found", nil)
		return
	}
	defer func() { _ = f.Close() }()

	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		c.JsonApiErr(http.StatusNotFound, "Image not found", nil)
		return
	}

	c.Resp.Header().Set("Content-Type", "image/png")
	c.Resp.Header().Set("Cache-Control", "private, no-store")
	http.ServeContent(c.Resp, c.Req, name, fi.ModTime(), f)
}
