// Package headers Middleware based on https://github.com/unrolled/secure.
package headers

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/containous/traefik/config"
	"github.com/containous/traefik/middlewares"
	"github.com/containous/traefik/tracing"
	"github.com/opentracing/opentracing-go/ext"
	"github.com/unrolled/secure"
)

const (
	typeName = "Headers"
)

type headers struct {
	name    string
	handler http.Handler
}

// New creates a Headers middleware.
func New(ctx context.Context, next http.Handler, config config.Headers, name string) (http.Handler, error) {
	// HeaderMiddleware -> SecureMiddleWare -> next
	logger := middlewares.GetLogger(ctx, name, typeName)
	logger.Debug("Creating middleware")

	hasSecureHeaders := config.HasSecureHeadersDefined()
	hasCustomHeaders := config.HasCustomHeadersDefined()
	hasCorsHeaders := config.HasCorsHeadersDefined()

	if !hasSecureHeaders && !hasCustomHeaders && !hasCorsHeaders {
		return nil, errors.New("headers configuration not valid")
	}

	var handler http.Handler
	nextHandler := next

	if hasSecureHeaders {
		logger.Debug("Setting up secureHeaders from %v", config)
		handler = newSecure(next, config)
		nextHandler = handler
	}

	if hasCustomHeaders || hasCorsHeaders {
		logger.Debug("Setting up customHeaders/Cors from %v", config)
		handler = NewHeader(nextHandler, config)
	}

	return &headers{
		handler: handler,
		name:    name,
	}, nil
}

func (h *headers) GetTracingInformation() (string, ext.SpanKindEnum) {
	return h.name, tracing.SpanKindNoneEnum
}

func (h *headers) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	h.handler.ServeHTTP(rw, req)
}

type secureHeader struct {
	next   http.Handler
	secure *secure.Secure
}

// newSecure constructs a new secure instance with supplied options.
func newSecure(next http.Handler, headers config.Headers) *secureHeader {
	opt := secure.Options{
		BrowserXssFilter:        headers.BrowserXSSFilter,
		ContentTypeNosniff:      headers.ContentTypeNosniff,
		ForceSTSHeader:          headers.ForceSTSHeader,
		FrameDeny:               headers.FrameDeny,
		IsDevelopment:           headers.IsDevelopment,
		SSLRedirect:             headers.SSLRedirect,
		SSLForceHost:            headers.SSLForceHost,
		SSLTemporaryRedirect:    headers.SSLTemporaryRedirect,
		STSIncludeSubdomains:    headers.STSIncludeSubdomains,
		STSPreload:              headers.STSPreload,
		ContentSecurityPolicy:   headers.ContentSecurityPolicy,
		CustomBrowserXssValue:   headers.CustomBrowserXSSValue,
		CustomFrameOptionsValue: headers.CustomFrameOptionsValue,
		PublicKey:               headers.PublicKey,
		ReferrerPolicy:          headers.ReferrerPolicy,
		SSLHost:                 headers.SSLHost,
		AllowedHosts:            headers.AllowedHosts,
		HostsProxyHeaders:       headers.HostsProxyHeaders,
		SSLProxyHeaders:         headers.SSLProxyHeaders,
		STSSeconds:              headers.STSSeconds,
	}

	return &secureHeader{
		next:   next,
		secure: secure.New(opt),
	}
}

func (s secureHeader) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	s.secure.HandlerFuncWithNextForRequestOnly(rw, req, s.next.ServeHTTP)
}

// Header is a middleware that helps setup a few basic security features. A single headerOptions struct can be
// provided to configure which features should be enabled, and the ability to override a few of the default values.
type Header struct {
	next         http.Handler
	headers      *config.Headers
	originHeader string
}

// NewHeader constructs a new header instance from supplied frontend header struct.
func NewHeader(next http.Handler, headers config.Headers) *Header {
	return &Header{
		next:    next,
		headers: &headers,
	}
}

func (s *Header) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	reqAcMethod := req.Header.Get("Access-Control-Request-Method")
	reqAcHeaders := req.Header.Get("Access-Control-Request-Headers")
	s.originHeader = req.Header.Get("Origin")

	if reqAcMethod != "" && reqAcHeaders != "" && s.originHeader != "" && req.Method == http.MethodOptions {
		// Preflight request, build response
		if s.headers.AccessControlAllowCredentials {
			rw.Header().Add("Access-Control-Allow-Credentials", "true")
		}

		allowHeaders := strings.Join(s.headers.AccessControlAllowHeaders, ",")
		if allowHeaders != "" {
			rw.Header().Add("Access-Control-Allow-Headers", allowHeaders)
		}

		allowMethods := strings.Join(s.headers.AccessControlAllowMethods, ",")
		if allowMethods != "" {
			rw.Header().Add("Access-Control-Allow-Methods", allowMethods)
		}

		allowOrigin := s.getAllowOrigin()

		if allowOrigin != "" {
			rw.Header().Add("Access-Control-Allow-Origin", allowOrigin)
		}

		rw.Header().Add("Access-Control-Max-Age", strconv.Itoa(int(s.headers.AccessControlMaxAge)))
	} else {
		s.modifyRequestHeaders(req)
		// If there is a next, call it.
		if s.next != nil {
			s.next.ServeHTTP(rw, req)
		}
	}
}

// modifyRequestHeaders set or delete request headers.
func (s *Header) modifyRequestHeaders(req *http.Request) {
	// Loop through Custom request headers
	for header, value := range s.headers.CustomRequestHeaders {
		if value == "" {
			req.Header.Del(header)
		} else {
			req.Header.Set(header, value)
		}
	}
}

// ModifyResponseHeaders set or delete response headers
func (s *Header) ModifyResponseHeaders(res *http.Response) error {
	// Loop through Custom response headers
	for header, value := range s.headers.CustomResponseHeaders {
		if value == "" {
			res.Header.Del(header)
		} else {
			res.Header.Set(header, value)
		}
	}

	allowOrigin := s.getAllowOrigin()

	if allowOrigin != "" {
		res.Header.Set("Access-Control-Allow-Origin", allowOrigin)

		if s.headers.AddVaryHeader {
			varyHeader := res.Header.Get("Vary")
			if varyHeader != "" {
				varyHeader += ",Origin"
			} else {
				varyHeader = "Origin"
			}
			res.Header.Set("Vary", varyHeader)
		}
	}

	if s.headers.AccessControlAllowCredentials {
		res.Header.Set("Access-Control-Allow-Credentials", "true")
	}

	exposeHeaders := strings.Join(s.headers.AccessControlExposeHeaders, ",")
	if exposeHeaders != "" {
		res.Header.Set("Access-Control-Expose-Headers", exposeHeaders)
	}

	return nil
}

func (s *Header) getAllowOrigin() string {
	switch s.headers.AccessControlAllowOrigin {
	case "origin-list-or-null":
		if s.originHeader == "" {
			return "null"
		}
		return s.originHeader
	case "*":
		return "*"
	}
	return ""
}
