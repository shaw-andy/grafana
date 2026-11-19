package pluginproxy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/grafana/grafana/pkg/plugins"
)

// maxTokenResponseBytes caps how much of a token endpoint response is read into memory.
const maxTokenResponseBytes = 1 << 20

var (
	tokenCache = tokenCacheType{
		cache: map[string]*jwtToken{},
	}

	// tokenFetches lets concurrent requests for the same cache key share one token
	// request. The HTTP call must not run under tokenCache's lock, otherwise one slow
	// or large token response would stall token lookups for every datasource.
	tokenFetches singleflight.Group
)

type tokenCacheType struct {
	cache map[string]*jwtToken
	sync.Mutex
}

func (c *tokenCacheType) get(key string) (*jwtToken, bool) {
	c.Lock()
	defer c.Unlock()
	token, found := c.cache[key]
	return token, found
}

func (c *tokenCacheType) set(key string, token *jwtToken) {
	c.Lock()
	defer c.Unlock()
	c.cache[key] = token
}

type genericAccessTokenProvider struct {
	datasourceNamespace string
	datasourceUID       string
	datasourceId        int64
	datasourceUpdated   time.Time
	route               *plugins.Route
	authParams          *plugins.JWTTokenAuth
}

type jwtToken struct {
	ExpiresOn   time.Time
	AccessToken string
}

func (token *jwtToken) UnmarshalJSON(b []byte) error {
	var t struct {
		AccessToken string       `json:"access_token"`
		ExpiresOn   *json.Number `json:"expires_on"`
		ExpiresIn   *json.Number `json:"expires_in"`
	}

	if err := json.Unmarshal(b, &t); err != nil {
		return err
	}

	token.AccessToken = t.AccessToken
	token.ExpiresOn = timeNow()

	if t.ExpiresOn != nil {
		expiresOn, err := t.ExpiresOn.Int64()
		if err != nil {
			return err
		}
		token.ExpiresOn = time.Unix(expiresOn, 0)
	} else if t.ExpiresIn != nil {
		expiresIn, err := t.ExpiresIn.Int64()
		if err != nil {
			return err
		}
		token.ExpiresOn = timeNow().Add(time.Duration(expiresIn) * time.Second)
	}

	return nil
}

func newGenericAccessTokenProvider(ds DSInfo, pluginRoute *plugins.Route,
	authParams *plugins.JWTTokenAuth) *genericAccessTokenProvider {
	return &genericAccessTokenProvider{
		datasourceNamespace: ds.Namespace,
		datasourceUID:       ds.UID,
		datasourceId:        ds.ID,
		datasourceUpdated:   ds.Updated,
		route:               pluginRoute,
		authParams:          authParams,
	}
}

func (provider *genericAccessTokenProvider) GetAccessToken() (string, error) {
	cacheKey := provider.getAccessTokenCacheKey()
	if cachedToken, found := tokenCache.get(cacheKey); found {
		if cachedToken.ExpiresOn.After(timeNow().Add(time.Second * 10)) {
			logger.Info("Using token from cache")
			return cachedToken.AccessToken, nil
		}
	}

	accessToken, err, _ := tokenFetches.Do(cacheKey, func() (any, error) {
		token, err := provider.fetchAccessToken()
		if err != nil {
			return "", err
		}
		tokenCache.set(cacheKey, token)
		logger.Info("Got new access token", "ExpiresOn", token.ExpiresOn)
		return token.AccessToken, nil
	})
	if err != nil {
		return "", err
	}
	return accessToken.(string), nil
}

func (provider *genericAccessTokenProvider) fetchAccessToken() (*jwtToken, error) {
	body := provider.tokenRequestParams().Encode()

	getTokenReq, err := http.NewRequest("POST", provider.authParams.Url, bytes.NewBufferString(body))
	if err != nil {
		return nil, err
	}
	getTokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	getTokenReq.Header.Set("Content-Length", strconv.Itoa(len(body)))

	resp, err := client.Do(getTokenReq)
	if err != nil {
		return nil, err
	}

	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.Warn("Failed to close response body", "err", err)
		}
	}()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(respBody) > maxTokenResponseBytes {
		return nil, fmt.Errorf("token response exceeds %d bytes", maxTokenResponseBytes)
	}

	var token jwtToken
	if err := json.NewDecoder(bytes.NewReader(respBody)).Decode(&token); err != nil {
		return nil, err
	}
	return &token, nil
}

func (provider *genericAccessTokenProvider) tokenRequestParams() url.Values {
	params := make(url.Values)
	for key, value := range provider.authParams.Params {
		params.Add(key, value)
	}
	return params
}

func (provider *genericAccessTokenProvider) getAccessTokenCacheKey() string {
	// The token request is hashed so the key changes with the interpolated URL and
	// params without keeping their values, which may hold secrets, in the key itself.
	requestHash := sha256.Sum256([]byte(provider.authParams.Url + "\n" + provider.tokenRequestParams().Encode()))
	return fmt.Sprintf("%v_%v_%v_%v_%v_%v_%v",
		provider.datasourceNamespace,
		provider.datasourceUID,
		provider.datasourceId,
		provider.datasourceUpdated.Unix(),
		provider.route.Path,
		provider.route.Method,
		hex.EncodeToString(requestHash[:]),
	)
}
