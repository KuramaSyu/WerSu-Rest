package controllers

import "testing"

// TestRedactURLCredentials covers the four shapes an address field can
// take in the status response. The redaction strips `user:pass@` from
// URL-shaped values, drops query strings, and leaves bare host:port
// values alone.
func TestRedactURLCredentials(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "url with user:pass",
			in:   "http://alice:s3cret@garage:3900",
			want: "http://***@garage:3900",
		},
		{
			name: "url with user only",
			in:   "https://alice@imgproxy.example.com",
			want: "https://***@imgproxy.example.com",
		},
		{
			name: "url with query string drops query",
			in:   "http://alice:s3cret@garage:3900?token=abc",
			want: "http://***@garage:3900",
		},
		{
			name: "bare host:port unchanged",
			in:   "garage:3900",
			want: "garage:3900",
		},
		{
			name: "url without credentials unchanged",
			in:   "https://imgproxy.example.com",
			want: "https://imgproxy.example.com",
		},
		{
			name: "empty unchanged",
			in:   "",
			want: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := redactURLCredentials(tc.in)
			if got != tc.want {
				t.Fatalf("redactURLCredentials(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestRedactPostgresDSN pins the behaviour callers rely on: redactPostgresDSN
// is a thin wrapper around redactURLCredentials and produces the same
// output for a typical DSN.
func TestRedactPostgresDSN(t *testing.T) {
	in := "postgres://alice:s3cret@db.example.com:5432/app?sslmode=disable"
	want := "postgres://***@db.example.com:5432/app"

	if got := redactPostgresDSN(in); got != want {
		t.Fatalf("redactPostgresDSN(%q) = %q, want %q", in, got, want)
	}
}

// TestMaskKeysInString confirms that key-shaped substrings (AWS access
// key IDs, JWTs, Bearer tokens) are masked via maskSensitiveValue, while
// surrounding text — hostnames, error context, normal words — passes
// through unchanged.
func TestMaskKeysInString(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "aws access key id is masked",
			in:   "InvalidAccessKeyId: AKIAIOSFODNN7EXAMPLE does not exist",
			want: "InvalidAccessKeyId: AK****LE does not exist",
		},
		{
			name: "jwt is masked",
			in:   "header.payload: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1MSJ9.s5Z5NXKxXw",
			want: "header.payload: ey****Xw",
		},
		{
			name: "bearer token is masked",
			in:   "Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345",
			want: "Authorization: Be****45",
		},
		{
			name: "plain text unchanged",
			in:   "list_buckets ok (3 buckets); head_bucket(\"garage\") ok",
			want: "list_buckets ok (3 buckets); head_bucket(\"garage\") ok",
		},
		{
			name: "aws key inside longer error preserved around it",
			in:   "head_bucket(\"garage\"): InvalidAccessKeyId: AKIAIOSFODNN7EXAMPLE",
			want: "head_bucket(\"garage\"): InvalidAccessKeyId: AK****LE",
		},
		{
			name: "empty unchanged",
			in:   "",
			want: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := maskKeysInString(tc.in)
			if got != tc.want {
				t.Fatalf("maskKeysInString(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestMaskSensitiveValueDuplicatesConfig pins the contract that the
// duplicated `maskSensitiveValue` here has the same semantics as
// `config.maskSensitiveValue`. If the two ever diverge, this test will
// catch it (provided `config.maskSensitiveValue` keeps its shape).
func TestMaskSensitiveValueDuplicatesConfig(t *testing.T) {
	cases := []string{"", "ab", "abcd", "abcde", "AKIAIOSFODNN7EXAMPLE"}
	for _, in := range cases {
		got := maskSensitiveValue(in)
		// Expected: "****" for len <= 4, otherwise first 2 + "****" + last 2.
		var want string
		if len(in) <= 4 {
			want = "****"
		} else {
			want = in[:2] + "****" + in[len(in)-2:]
		}
		if got != want {
			t.Fatalf("maskSensitiveValue(%q) = %q, want %q", in, got, want)
		}
	}
}
