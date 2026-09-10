package plugins

import (
	"context"

	"github.com/navidrome/navidrome/core/auth"
	"github.com/navidrome/navidrome/plugins/capabilities"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("AuthProviderAdapter", func() {
	Describe("ActiveAuthProvider", func() {
		It("returns not-ok when no plugins are loaded", func() {
			m := &Manager{plugins: make(map[string]*plugin)}
			provider, ok := m.ActiveAuthProvider(context.Background())
			Expect(ok).To(BeFalse())
			Expect(provider).To(BeNil())
		})

		It("returns not-ok when no plugin has the AuthProvider capability", func() {
			m := &Manager{plugins: map[string]*plugin{
				"test-scrobbler": {name: "test-scrobbler", capabilities: []Capability{CapabilityScrobbler}},
			}}
			provider, ok := m.ActiveAuthProvider(context.Background())
			Expect(ok).To(BeFalse())
			Expect(provider).To(BeNil())
		})
	})

	Describe("ToIdentity", func() {
		It("converts a plugin identity to a core identity", func() {
			p := &AuthProviderPlugin{}
			ai := capabilities.AuthIdentity{
				Provider:    "oidc",
				Subject:     "sub-1",
				Username:    "john",
				Email:       "john@example.com",
				DisplayName: "John Doe",
				Groups:      []string{"users"},
				IsAdmin:     true,
				IDToken:     "id-token",
				Claims:      map[string]any{"iss": "https://auth.example.com"},
			}
			identity := p.ToIdentity(context.Background(), ai)
			Expect(identity).To(Equal(&auth.Identity{
				Provider:    "oidc",
				Subject:     "sub-1",
				Username:    "john",
				Email:       "john@example.com",
				DisplayName: "John Doe",
				Groups:      []string{"users"},
				IsAdmin:     true,
				IDToken:     "id-token",
				Claims:      map[string]any{"iss": "https://auth.example.com"},
			}))
		})
	})
})