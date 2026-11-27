// These tests run against a local stand-in server that replays recorded API
// responses. No API key and no network access are needed.
package ipwho

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

const testKey = "sk.test_secret_value"

type stub struct {
	status   int
	body     string
	requests []*http.Request
}

func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func newStub(t *testing.T, status int, body string) (*stub, *Client) {
	t.Helper()
	s := &stub{status: status, body: body}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.requests = append(s.requests, r.Clone(r.Context()))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(s.status)
		_, _ = w.Write([]byte(s.body))
	}))
	t.Cleanup(server.Close)
	client, err := NewClient(testKey, WithBaseURL(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	return s, client
}

func TestKeyIsInTheHeaderAndNeverInTheURL(t *testing.T) {
	s, client := newStub(t, 200, fixture(t, "lookup"))
	if _, err := client.Lookup("8.8.8.8", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Me(nil); err != nil {
		t.Fatal(err)
	}
	s.body = fixture(t, "bulk")
	if _, err := client.Bulk([]string{"8.8.8.8", "1.1.1.1"}, nil); err != nil {
		t.Fatal(err)
	}
	if len(s.requests) != 3 {
		t.Fatalf("got %d requests", len(s.requests))
	}
	for _, r := range s.requests {
		if got := r.Header.Get("Authorization"); got != "Bearer "+testKey {
			t.Errorf("Authorization = %q", got)
		}
		url := r.URL.String()
		if strings.Contains(url, testKey) || strings.Contains(strings.ToLower(url), "apikey") {
			t.Errorf("key in URL: %s", url)
		}
	}
}

func TestLookup(t *testing.T) {
	s, client := newStub(t, 200, fixture(t, "lookup"))
	resp, err := client.Lookup("8.8.8.8", nil)
	if err != nil {
		t.Fatal(err)
	}
	d := resp.Data
	if s.requests[0].URL.RequestURI() != "/ip/8.8.8.8" {
		t.Errorf("request URI %s", s.requests[0].URL.RequestURI())
	}
	if d.IP != "8.8.8.8" || *d.GeoLocation.Country != "United States" || *d.GeoLocation.CountryCode != "US" {
		t.Errorf("unexpected data: %+v", d.GeoLocation)
	}
	if *d.Connection.AsnNumber != 15169 || *d.Timezone.TimeZone != "America/Chicago" || *d.Currency.Code != "USD" {
		t.Error("unexpected nested values")
	}
}

func TestLookupNullCurrency(t *testing.T) {
	_, client := newStub(t, 200, fixture(t, "lookup-null-currency"))
	resp, err := client.Lookup("1.1.1.1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Data.IP != "1.1.1.1" || resp.Data.Currency != nil {
		t.Errorf("unexpected data: %+v", resp.Data)
	}
}

func TestBulkReturnsDataForEveryAddress(t *testing.T) {
	_, client := newStub(t, 200, fixture(t, "bulk"))
	rows, err := client.Bulk([]string{"8.8.8.8", "1.1.1.1", "192.168.0.1", "9.9.9.9"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 4 {
		t.Fatalf("got %d rows", len(rows))
	}
	for i, ip := range []string{"8.8.8.8", "1.1.1.1", "192.168.0.1", "9.9.9.9"} {
		if rows[i].Data == nil || rows[i].Data.IP != ip {
			t.Fatalf("row %d: data %+v", i, rows[i].Data)
		}
	}
	if !rows[0].Success || *rows[0].Data.GeoLocation.Country != "United States" || *rows[0].Data.Connection.AsnNumber != 15169 {
		t.Error("row 0 has no data")
	}
	if !rows[1].Success || rows[1].Data.Currency != nil || *rows[1].Data.Connection.AsnNumber != 13335 {
		t.Error("row 1 is wrong")
	}
	if rows[2].Success || rows[2].Data.GeoLocation != nil || *rows[2].Message != "Reserved range/Invalid IP address" {
		t.Error("row 2 should be a failed row")
	}
	if rows[3].Success || !strings.Contains(*rows[3].Message, "quota") {
		t.Error("row 3 should be a rate-limited row")
	}
}

func TestFieldsAndFormat(t *testing.T) {
	s, client := newStub(t, 200, fixture(t, "lookup"))
	if _, err := client.Lookup("8.8.8.8", &LookupOptions{Fields: "geoLocation,timezone"}); err != nil {
		t.Fatal(err)
	}
	if got := s.requests[0].URL.RequestURI(); got != "/ip/8.8.8.8?get=geoLocation%2Ctimezone" {
		t.Errorf("request URI %s", got)
	}
	s.body = "ip,8.8.8.8"
	resp, err := client.Lookup("8.8.8.8", &LookupOptions{Format: "csv"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Data.IP != "ip,8.8.8.8" {
		t.Errorf("raw text %q", resp.Data.IP)
	}
}

func TestHTTPErrors(t *testing.T) {
	_, client := newStub(t, 404, `{"success":false,"message":"Reserved range/Invalid IP address"}`)
	_, err := client.Lookup("8.8.8.8", nil)
	var notFound *NotFoundError
	if !errors.As(err, &notFound) {
		t.Errorf("404: %T %v", err, err)
	}

	_, client = newStub(t, 429, `{"error":"rate_limit_exceeded"}`)
	_, err = client.Lookup("8.8.8.8", nil)
	var rateLimit *RateLimitError
	if !errors.As(err, &rateLimit) {
		t.Errorf("429: %T %v", err, err)
	}

	_, client = newStub(t, 401, `{"error":"invalid_api_key"}`)
	_, err = client.Lookup("8.8.8.8", nil)
	var apiError *IpWhoError
	if !errors.As(err, &apiError) || apiError.StatusCode != 401 {
		t.Errorf("401: %T %v", err, err)
	}
}

func TestConnectionFailureDoesNotRevealTheKey(t *testing.T) {
	client, err := NewClient(testKey, WithBaseURL("http://127.0.0.1:1"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Lookup("8.8.8.8", nil)
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), testKey) {
		t.Errorf("key in error: %v", err)
	}
}
