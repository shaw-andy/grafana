// Package jwks decodes JSON Web Key Sets that are used to verify token signatures.
package jwks

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	jose "github.com/go-jose/go-jose/v4"
	josejson "github.com/go-jose/go-jose/v4/json"
)

var ErrPrivateKey = errors.New("JWKS contains private key material; only public keys can verify tokens")

// privateParams mirrors the private members go-jose reads from a JWK. It is
// decoded with go-jose's own JSON package so that a member counts as present
// exactly when go-jose would parse it.
type privateParams struct {
	Kid string               `json:"kid"`
	D   *josejson.RawMessage `json:"d"`
	P   *josejson.RawMessage `json:"p"`
	Q   *josejson.RawMessage `json:"q"`
	Dp  *josejson.RawMessage `json:"dp"`
	Dq  *josejson.RawMessage `json:"dq"`
	Qi  *josejson.RawMessage `json:"qi"`
}

// Unmarshal decodes a JWKS document and rejects it if any key carries private
// key material. go-jose validates RSA private keys while unmarshaling, which
// crafted parameters can make arbitrarily expensive, so such keys must be
// refused before go-jose parses them. Private keys cannot verify signatures.
func Unmarshal(data []byte) (jose.JSONWebKeySet, error) {
	var raw struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return jose.JSONWebKeySet{}, err
	}

	var set jose.JSONWebKeySet
	if raw.Keys != nil {
		set.Keys = make([]jose.JSONWebKey, len(raw.Keys))
	}
	for i, key := range raw.Keys {
		var params privateParams
		if err := josejson.Unmarshal(key, &params); err != nil {
			return jose.JSONWebKeySet{}, err
		}
		if params.D != nil || params.P != nil || params.Q != nil ||
			params.Dp != nil || params.Dq != nil || params.Qi != nil {
			return jose.JSONWebKeySet{}, fmt.Errorf("%w (kid %q)", ErrPrivateKey, params.Kid)
		}
		if err := json.Unmarshal(key, &set.Keys[i]); err != nil {
			return jose.JSONWebKeySet{}, err
		}
	}
	return set, nil
}

// WrapClient returns a copy of client that fails any successful response whose
// body Unmarshal rejects. It is for JWKS fetchers that decode the response
// themselves.
func WrapClient(client *http.Client) *http.Client {
	wrapped := *client
	base := client.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	wrapped.Transport = transport{base: base}
	return &wrapped
}

type transport struct {
	base http.RoundTripper
}

func (t transport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return resp, err
	}

	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return nil, err
	}
	if _, err := Unmarshal(body); err != nil {
		return nil, err
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return resp, nil
}
