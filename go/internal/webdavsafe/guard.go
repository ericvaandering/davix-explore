// Package webdavsafe closes a silent failure mode in gowebdav's PROPFIND
// handling.
//
// gowebdav's XML parser discards decoder errors -- parseXML in utils.go walks
// the document with `t, _ := decoder.Token()` -- so a response body that is cut
// short by a timeout, a dropped connection, or a proxy error page parses as a
// *successful* listing with zero entries. ReadDir then returns (nil, nil),
// which is indistinguishable from a genuinely empty directory.
//
// That distinction is load-bearing. webdav-ls-r records such a directory in
// empty_dirs.out, and webdav-rm treats an empty listing as permission to issue
// a DELETE -- which, on a WebDAV collection, is recursive by RFC 4918. A single
// truncated response can therefore delete a populated tree.
//
// Transport makes the failure loud instead: it buffers each response body so
// read errors surface, and validates that every 207 multistatus actually
// contains at least one <response> element. A Depth:1 PROPFIND on a real
// collection always reports the collection itself, so a well-formed listing has
// one response even when the directory is empty. Zero responses means the body
// did not arrive intact.
package webdavsafe

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// Transport wraps a RoundTripper, buffering and validating PROPFIND responses.
// The zero value is not usable; call NewTransport.
type Transport struct {
	rt http.RoundTripper
}

// NewTransport returns a Transport delegating to rt. A nil rt uses
// http.DefaultTransport.
func NewTransport(rt http.RoundTripper) *Transport {
	if rt == nil {
		rt = http.DefaultTransport
	}
	return &Transport{rt: rt}
}

// ErrTruncatedListing reports a multistatus response that did not arrive
// intact. Callers must not interpret it as an empty directory.
var ErrTruncatedListing = errors.New("truncated or malformed PROPFIND response")

func (t *Transport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := t.rt.RoundTrip(r)
	if err != nil {
		return nil, err
	}

	// Buffer the whole body here so a mid-stream read error becomes a transport
	// error rather than a short read that gowebdav silently tolerates. This is
	// the same data the XML parser was about to consume, so the extra cost is
	// holding one listing in memory per in-flight request.
	body, readErr := io.ReadAll(resp.Body)
	resp.Body.Close()
	if readErr != nil {
		return nil, fmt.Errorf("%w: reading body: %w", ErrTruncatedListing, readErr)
	}

	if r.Method == "PROPFIND" && resp.StatusCode == http.StatusMultiStatus {
		if err := validateMultistatus(body); err != nil {
			return nil, err
		}
	}

	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	return resp, nil
}

// validateMultistatus confirms the body is well-formed XML carrying at least
// one <response> element.
func validateMultistatus(body []byte) error {
	decoder := xml.NewDecoder(bytes.NewReader(body))
	responses := 0
	for {
		tok, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("%w: %w", ErrTruncatedListing, err)
		}
		if se, ok := tok.(xml.StartElement); ok && se.Name.Local == "response" {
			responses++
		}
	}
	if responses == 0 {
		// A Depth:0 or Depth:1 PROPFIND on an existing resource always reports
		// that resource. None at all means we did not receive a usable listing.
		return fmt.Errorf("%w: multistatus contained no <response> elements", ErrTruncatedListing)
	}
	return nil
}
