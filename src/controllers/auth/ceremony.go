package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// ceremonyEntry stores a WebAuthn SessionData under its TTL.
type ceremonyEntry struct {
	data    webauthn.SessionData
	expires time.Time
}

// cleanupCeremonies evicts expired entries on a 1-minute ticker.
// sync.Map cannot delete-by-age, so the loop scans.
func (ac *AuthController) cleanupCeremonies() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for range t.C {
		now := time.Now()
		ac.ceremonyStore.Range(func(k, v any) bool {
			e, ok := v.(ceremonyEntry)
			if !ok || now.After(e.expires) {
				ac.ceremonyStore.Delete(k)
			}
			return true
		})
	}
}

// putCeremony stores SessionData under a random key.
func (ac *AuthController) putCeremony(sd webauthn.SessionData) (string, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	key := base64.RawURLEncoding.EncodeToString(nonce[:])
	expires := time.Now().Add(passkeyCeremonyTTL)
	ac.ceremonyStore.Store(key, ceremonyEntry{data: sd, expires: expires})
	log.Printf("passkey: stored ceremony key=%s expires=%s userID=%q", key, expires.UTC().Format(time.RFC3339), sd.UserID)
	return key, nil
}

// takeCeremony loads and deletes the SessionData under key. The
// store is single-use, so a retried /finish returns an error;
// entries past their TTL are reported with the cutoff time so the
// SPA can decide whether to start a fresh ceremony.
func (ac *AuthController) takeCeremony(key string) (webauthn.SessionData, error) {
	v, ok := ac.ceremonyStore.LoadAndDelete(key)
	if !ok {
		log.Printf("passkey: takeCeremony key=%s -> miss (not found or already consumed)", key)
		return webauthn.SessionData{}, errors.New("ceremony not found")
	}
	e, ok := v.(ceremonyEntry)
	if !ok {
		log.Printf("passkey: takeCeremony key=%s -> corrupted entry of type %T", key, v)
		return webauthn.SessionData{}, fmt.Errorf("ceremony store: unexpected entry type %T", v)
	}
	if now := time.Now(); now.After(e.expires) {
		log.Printf("passkey: takeCeremony key=%s -> expired expires=%s now=%s", key, e.expires.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
		return webauthn.SessionData{}, fmt.Errorf(
			"ceremony expired at %s (now=%s)",
			e.expires.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339),
		)
	}
	log.Printf("passkey: takeCeremony key=%s -> hit userID=%q", key, e.data.UserID)
	return e.data, nil
}
