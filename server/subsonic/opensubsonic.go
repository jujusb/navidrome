package subsonic

import (
	"context"
	"net/http"

	"github.com/navidrome/navidrome/plugins"
	"github.com/navidrome/navidrome/server/subsonic/responses"
)

func (api *Router) GetOpenSubsonicExtensions(_ *http.Request) (*responses.Subsonic, error) {
	response := newResponse()
	extensions := responses.OpenSubsonicExtensions{
		{Name: "transcodeOffset", Versions: []int32{1}},
		{Name: "formPost", Versions: []int32{1}},
		{Name: "songLyrics", Versions: []int32{1, 2}},
		{Name: "indexBasedQueue", Versions: []int32{1}},
		{Name: "transcoding", Versions: []int32{1}},
		{Name: "playbackReport", Versions: []int32{1}},
	}
	if api.sonic != nil && api.sonic.HasProvider() {
		extensions = append(extensions, responses.OpenSubsonicExtension{
			Name: "sonicSimilarity", Versions: []int32{1},
		})
	}
	response.OpenSubsonicExtensions = &extensions

	auth := &responses.OpenSubsonicAuthentication{
		Password: true,
		Token:    true,
	}
	m := plugins.GetManager(api.ds, api.broker, nil)
	provider, ok := m.ActiveAuthProvider(context.Background())
	if ok {
		status := provider.GetStatus(context.Background())
		if status.Enabled && status.Issuer != "" && status.ClientID != "" {
			auth.OIDC = &responses.OpenSubsonicOIDC{
				Enabled:  true,
				Issuer:   status.Issuer,
				ClientID: status.ClientID,
				Scopes:   status.Scopes,
			}
		}
	}
	response.Authentication = auth

	return response, nil
}
