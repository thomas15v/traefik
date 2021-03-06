package responsemodifiers

import (
	"net/http"

	"github.com/containous/traefik/config"
	"github.com/containous/traefik/middlewares/headers"
	"github.com/unrolled/secure"
)

func buildHeaders(hdrs *config.Headers) func(*http.Response) error {
	opt := secure.Options{
		BrowserXssFilter:        hdrs.BrowserXSSFilter,
		ContentTypeNosniff:      hdrs.ContentTypeNosniff,
		ForceSTSHeader:          hdrs.ForceSTSHeader,
		FrameDeny:               hdrs.FrameDeny,
		IsDevelopment:           hdrs.IsDevelopment,
		SSLRedirect:             hdrs.SSLRedirect,
		SSLForceHost:            hdrs.SSLForceHost,
		SSLTemporaryRedirect:    hdrs.SSLTemporaryRedirect,
		STSIncludeSubdomains:    hdrs.STSIncludeSubdomains,
		STSPreload:              hdrs.STSPreload,
		ContentSecurityPolicy:   hdrs.ContentSecurityPolicy,
		CustomBrowserXssValue:   hdrs.CustomBrowserXSSValue,
		CustomFrameOptionsValue: hdrs.CustomFrameOptionsValue,
		PublicKey:               hdrs.PublicKey,
		ReferrerPolicy:          hdrs.ReferrerPolicy,
		SSLHost:                 hdrs.SSLHost,
		AllowedHosts:            hdrs.AllowedHosts,
		HostsProxyHeaders:       hdrs.HostsProxyHeaders,
		SSLProxyHeaders:         hdrs.SSLProxyHeaders,
		STSSeconds:              hdrs.STSSeconds,
	}

	return func(resp *http.Response) error {
		if hdrs.HasCustomHeadersDefined() || hdrs.HasCorsHeadersDefined() {
			err := headers.NewHeader(nil, *hdrs).ModifyResponseHeaders(resp)
			if err != nil {
				return err
			}
		}

		if hdrs.HasSecureHeadersDefined() {
			err := secure.New(opt).ModifyResponseHeaders(resp)
			if err != nil {
				return err
			}
		}

		return nil
	}
}
