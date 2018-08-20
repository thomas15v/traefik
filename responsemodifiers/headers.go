package responsemodifiers

import (
	"net/http"

	"github.com/containous/traefik/config"
	"github.com/containous/traefik/middlewares/headers"
	"github.com/unrolled/secure"
)

func buildHeaders(h *config.Headers) func(*http.Response) error {
	opt := secure.Options{
		BrowserXssFilter:        h.BrowserXSSFilter,
		ContentTypeNosniff:      h.ContentTypeNosniff,
		ForceSTSHeader:          h.ForceSTSHeader,
		FrameDeny:               h.FrameDeny,
		IsDevelopment:           h.IsDevelopment,
		SSLRedirect:             h.SSLRedirect,
		SSLForceHost:            h.SSLForceHost,
		SSLTemporaryRedirect:    h.SSLTemporaryRedirect,
		STSIncludeSubdomains:    h.STSIncludeSubdomains,
		STSPreload:              h.STSPreload,
		ContentSecurityPolicy:   h.ContentSecurityPolicy,
		CustomBrowserXssValue:   h.CustomBrowserXSSValue,
		CustomFrameOptionsValue: h.CustomFrameOptionsValue,
		PublicKey:               h.PublicKey,
		ReferrerPolicy:          h.ReferrerPolicy,
		SSLHost:                 h.SSLHost,
		AllowedHosts:            h.AllowedHosts,
		HostsProxyHeaders:       h.HostsProxyHeaders,
		SSLProxyHeaders:         h.SSLProxyHeaders,
		STSSeconds:              h.STSSeconds,
	}

	return func(resp *http.Response) error {
		if h.HasCustomHeadersDefined() || h.HasCorsHeadersDefined() {
			err := headers.NewHeader(nil, *h).ModifyResponseHeaders(resp)
			if err != nil {
				return err
			}
		}

		if h.HasSecureHeadersDefined() {
			err := secure.New(opt).ModifyResponseHeaders(resp)
			if err != nil {
				return err
			}
		}

		return nil
	}
}
