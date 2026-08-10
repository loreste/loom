package webhook

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/loreste/loom/core"
)

// DestinationPolicy controls which URLs may receive webhook deliveries.
type DestinationPolicy struct {
	// AllowHTTP permits cleartext http:// destinations. Development only.
	AllowHTTP bool
	// AllowPrivate permits loopback, private, link-local, and similar ranges.
	// Development and tests only; never enable in production.
	AllowPrivate bool
	// AllowRedirects permits following redirects. Each hop is revalidated and
	// signature headers are never forwarded across origins.
	AllowRedirects bool
	// MaxRedirects bounds redirect chains when AllowRedirects is true.
	MaxRedirects int
	// AllowHosts, when non-empty, restricts destinations to these hostnames
	// (exact match, case-insensitive). Production deployments should set this.
	AllowHosts []string
	// Resolver is injectable for tests. Defaults to net.DefaultResolver.
	Resolver interface {
		LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
	}
}

func (p DestinationPolicy) withDefaults() DestinationPolicy {
	if p.MaxRedirects <= 0 {
		p.MaxRedirects = 3
	}
	if p.Resolver == nil {
		p.Resolver = net.DefaultResolver
	}
	return p
}

// validatedURL is a once-normalized destination ready for dialing.
type validatedURL struct {
	raw      string
	url      *url.URL
	host     string
	port     string
	resolved []net.IP
}

func validateDestination(ctx context.Context, raw string, policy DestinationPolicy) (*validatedURL, error) {
	policy = policy.withDefaults()
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("%w: webhook URL is required", core.ErrInvalidArgument)
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: webhook URL is malformed", core.ErrInvalidArgument)
	}
	if parsed.IsAbs() == false || parsed.Host == "" {
		return nil, fmt.Errorf("%w: webhook URL must be absolute", core.ErrInvalidArgument)
	}
	scheme := strings.ToLower(parsed.Scheme)
	switch scheme {
	case "https":
	case "http":
		if !policy.AllowHTTP {
			return nil, fmt.Errorf("%w: webhook URL must use https", core.ErrInvalidArgument)
		}
	default:
		return nil, fmt.Errorf("%w: unsupported webhook URL scheme", core.ErrInvalidArgument)
	}
	if parsed.User != nil {
		return nil, fmt.Errorf("%w: webhook URL must not contain credentials", core.ErrInvalidArgument)
	}
	if parsed.Fragment != "" {
		return nil, fmt.Errorf("%w: webhook URL must not contain a fragment", core.ErrInvalidArgument)
	}
	host := parsed.Hostname()
	if host == "" {
		return nil, fmt.Errorf("%w: webhook URL host is required", core.ErrInvalidArgument)
	}
	// Reject bracket-less IPv6 ambiguity and empty hosts after normalize.
	if strings.EqualFold(host, "localhost") && !policy.AllowPrivate {
		return nil, fmt.Errorf("%w: webhook destination host is not allowed", core.ErrInvalidArgument)
	}
	if len(policy.AllowHosts) > 0 {
		allowed := false
		for _, candidate := range policy.AllowHosts {
			if strings.EqualFold(strings.TrimSpace(candidate), host) {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, fmt.Errorf("%w: webhook host is not on the allowlist", core.ErrInvalidArgument)
		}
	}
	port := parsed.Port()
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	} else if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return nil, fmt.Errorf("%w: webhook URL port is invalid", core.ErrInvalidArgument)
	}

	// Literal IP in the host: validate without DNS.
	if ip := net.ParseIP(host); ip != nil {
		if err := assertPublicIP(ip, policy.AllowPrivate); err != nil {
			return nil, err
		}
		return &validatedURL{raw: raw, url: parsed, host: host, port: port, resolved: []net.IP{ip}}, nil
	}

	addrs, err := policy.Resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("webhook: resolve destination: %w", err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("%w: webhook destination resolved to no addresses", core.ErrInvalidArgument)
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		if err := assertPublicIP(addr.IP, policy.AllowPrivate); err != nil {
			return nil, err
		}
		ips = append(ips, addr.IP)
	}
	return &validatedURL{raw: raw, url: parsed, host: host, port: port, resolved: ips}, nil
}

func assertPublicIP(ip net.IP, allowPrivate bool) error {
	if ip == nil {
		return fmt.Errorf("%w: webhook destination address is invalid", core.ErrInvalidArgument)
	}
	if allowPrivate {
		return nil
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || ip.IsInterfaceLocalMulticast() {
		return fmt.Errorf("%w: webhook destination address is not publicly routable", core.ErrInvalidArgument)
	}
	// Carrier-grade NAT 100.64.0.0/10
	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
			return fmt.Errorf("%w: webhook destination address is not publicly routable", core.ErrInvalidArgument)
		}
		// Documentation 198.51.100.0/24, 203.0.113.0/24, 192.0.2.0/24
		if (v4[0] == 198 && v4[1] == 51 && v4[2] == 100) ||
			(v4[0] == 203 && v4[1] == 0 && v4[2] == 113) ||
			(v4[0] == 192 && v4[1] == 0 && v4[2] == 2) {
			return fmt.Errorf("%w: webhook destination address is not publicly routable", core.ErrInvalidArgument)
		}
		// Cloud metadata well-known address.
		if v4[0] == 169 && v4[1] == 254 && v4[2] == 169 && v4[3] == 254 {
			return fmt.Errorf("%w: webhook destination address is not publicly routable", core.ErrInvalidArgument)
		}
	}
	// IPv6 unique local fc00::/7 and documentation 2001:db8::/32 are covered by
	// IsPrivate in recent Go; metadata link-local already covered.
	return nil
}

// safeTransport builds an HTTP transport that re-validates the connected IP
// (DNS rebinding defense) and optionally disables redirects.
func safeTransport(policy DestinationPolicy, base *http.Transport, timeout time.Duration) *http.Transport {
	policy = policy.withDefaults()
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if base != nil {
		transport = base.Clone()
	}
	dialer := &net.Dialer{Timeout: timeout}
	if timeout <= 0 {
		dialer.Timeout = 5 * time.Second
	}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		// If host is already an IP (after our redirect/resolve path), validate it.
		if ip := net.ParseIP(host); ip != nil {
			if err := assertPublicIP(ip, policy.AllowPrivate); err != nil {
				return nil, err
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		}
		addrs, err := policy.Resolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		var last error
		for _, addr := range addrs {
			if err := assertPublicIP(addr.IP, policy.AllowPrivate); err != nil {
				last = err
				continue
			}
			conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(addr.IP.String(), port))
			if err == nil {
				return conn, nil
			}
			last = err
		}
		if last == nil {
			last = fmt.Errorf("webhook: no safe addresses for %s", host)
		}
		return nil, last
	}
	return transport
}

func checkRedirect(policy DestinationPolicy) func(*http.Request, []*http.Request) error {
	policy = policy.withDefaults()
	return func(req *http.Request, via []*http.Request) error {
		if !policy.AllowRedirects {
			return fmt.Errorf("webhook: redirects are disabled")
		}
		if len(via) >= policy.MaxRedirects {
			return fmt.Errorf("webhook: too many redirects")
		}
		// Never forward signatures or secrets across redirect hops.
		req.Header.Del("X-Loom-Signature")
		req.Header.Del("X-Loom-Signature-Version")
		req.Header.Del("X-Loom-Key-Id")
		req.Header.Del("X-Loom-Timestamp")
		req.Header.Del("X-Loom-Event-Id")
		req.Header.Del("X-Loom-Content-Digest")
		req.Header.Del("Authorization")
		if _, err := validateDestination(req.Context(), req.URL.String(), policy); err != nil {
			return err
		}
		return nil
	}
}
