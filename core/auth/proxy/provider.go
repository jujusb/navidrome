package proxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"

	"github.com/navidrome/navidrome/conf"
	"github.com/navidrome/navidrome/core/auth"
	"github.com/navidrome/navidrome/log"
	"github.com/navidrome/navidrome/model/request"
)

type ProxyIdentityProvider struct{}

func New() *ProxyIdentityProvider {
	return &ProxyIdentityProvider{}
}

func (p *ProxyIdentityProvider) Name() string {
	return "proxy"
}

func (p *ProxyIdentityProvider) Authenticate(ctx context.Context, r *http.Request) (*auth.Identity, error) {
	if conf.Server.ExtAuth.TrustedSources == "" {
		return nil, auth.ErrNotAuthenticated
	}

	reverseProxyIp, ok := request.ReverseProxyIpFrom(r.Context())
	if !ok {
		log.Error("ExtAuth enabled but no proxy IP found in request context. Please report this error.")
		return nil, auth.ErrNotAuthenticated
	}
	if !validateIP(reverseProxyIp, conf.Server.ExtAuth.TrustedSources) {
		log.Warn(ctx, "IP is not whitelisted for external authentication", "proxy-ip", reverseProxyIp, "client-ip", r.RemoteAddr)
		return nil, auth.ErrNotAuthenticated
	}

	username := r.Header.Get(conf.Server.ExtAuth.UserHeader)
	if username == "" {
		return nil, auth.ErrNotAuthenticated
	}

	log.Trace(ctx, "Found username in ExtAuth.UserHeader", "username", username)
	return &auth.Identity{
		Provider: p.Name(),
		Subject:  username,
		Username: username,
		Email:    r.Header.Get("Remote-Email"),
	}, nil
}

func validateIP(ip, commaSeparatedList string) bool {
	if commaSeparatedList == "" || ip == "" {
		return false
	}

	cidrs := strings.Split(commaSeparatedList, ",")

	if ip == "@" && strings.HasPrefix(conf.Server.Address, "unix:") {
		return slices.Contains(cidrs, "@")
	}

	if net.ParseIP(ip) == nil {
		ip, _, _ = net.SplitHostPort(ip)
	}

	if ip == "" {
		return false
	}

	testedIP, _, err := net.ParseCIDR(fmt.Sprintf("%s/32", ip))
	if err != nil {
		return false
	}

	for _, cidr := range cidrs {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err == nil && ipnet.Contains(testedIP) {
			return true
		}
	}

	return false
}
