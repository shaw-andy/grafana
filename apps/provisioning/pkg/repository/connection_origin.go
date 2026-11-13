package repository

import (
	"runtime"
	"sync"
	"weak"

	provisioning "github.com/grafana/grafana/apps/provisioning/pkg/apis/provisioning/v0alpha1"
)

// connectionOrigins maps an in-memory repository object to the origin its
// connection authorized when it issued the repository credential. It is kept
// outside the API object so that it can never be supplied through the API or
// read back from storage: a stored object has no binding until a connection
// authorizes it again.
var connectionOrigins sync.Map // weak.Pointer[provisioning.Repository] -> string

// BindConnectionOrigin records that repo's connection issued its credential for
// origin ("scheme://host"). Only a connection that has checked repo's URL
// against its own server may call it.
func BindConnectionOrigin(repo *provisioning.Repository, origin string) {
	key := weak.Make(repo)
	if _, loaded := connectionOrigins.Swap(key, origin); !loaded {
		runtime.AddCleanup(repo, func(k weak.Pointer[provisioning.Repository]) {
			connectionOrigins.Delete(k)
		}, key)
	}
}

// BoundConnectionOrigin returns the origin recorded by BindConnectionOrigin for
// this exact object. Copies of the object do not carry the binding.
func BoundConnectionOrigin(repo *provisioning.Repository) (string, bool) {
	v, ok := connectionOrigins.Load(weak.Make(repo))
	if !ok {
		return "", false
	}
	origin, ok := v.(string)
	return origin, ok
}
