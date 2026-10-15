package main

// accounts - every player is a verified Nextendo account: emulators prove it with the signed nx2
// token in the BAAS id_token's "nnex" claim, consoles with their NSA id linked to an account.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

var (
	nextendoSecret []byte
	accountBaseURL = envOr("NEXTENDO_ACCOUNT_URL", "http://nextendo-account:8080")
	internalKey    = os.Getenv("NEXTENDO_INTERNAL_KEY")
	accountHTTP    = &http.Client{Timeout: 5 * time.Second}
)

// loadNextendoSecret reads the shared nx2 signing secret; the server refuses to start without it.
func loadNextendoSecret() ([]byte, error) {
	if v := os.Getenv("NEXTENDO_SECRET"); v != "" {
		return []byte(v), nil
	}
	path := os.Getenv("NEXTENDO_SECRET_FILE")
	if path == "" {
		return nil, fmt.Errorf("NEXTENDO_SECRET or NEXTENDO_SECRET_FILE is required")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if dec, derr := hex.DecodeString(strings.TrimSpace(string(b))); derr == nil && len(dec) >= 16 {
		return dec, nil
	}
	if len(b) < 16 {
		return nil, fmt.Errorf("%s: secret is too short", path)
	}
	return b, nil
}

// pidFromNx2 verifies nx2.<b64(pid.username.expiry)>.<b64(hmac)>.
func pidFromNx2(s string) (uint64, bool) {
	if len(nextendoSecret) == 0 || !strings.HasPrefix(s, "nx2.") {
		return 0, false
	}
	parts := strings.Split(s[len("nx2."):], ".")
	if len(parts) != 2 {
		return 0, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return 0, false
	}
	mac := hmac.New(sha256.New, nextendoSecret)
	mac.Write([]byte("nex:" + string(raw)))
	if !hmac.Equal([]byte(base64.RawURLEncoding.EncodeToString(mac.Sum(nil))), []byte(parts[1])) {
		return 0, false
	}
	f := strings.SplitN(string(raw), ".", 3)
	if len(f) != 3 {
		return 0, false
	}
	pid, err := strconv.ParseUint(f[0], 10, 64)
	if err != nil || pid == 0 {
		return 0, false
	}
	if exp, eerr := strconv.ParseInt(f[2], 10, 64); eerr != nil || time.Now().Unix() > exp {
		return 0, false
	}
	return pid, true
}

type idTokenClaims struct {
	Sub  string `json:"sub"`
	Nnex string `json:"nnex"`
}

func parseIDToken(jwt string) (idTokenClaims, bool) {
	var c idTokenClaims
	seg := strings.Split(jwt, ".")
	if len(seg) < 2 {
		return c, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(seg[1], "="))
	if err != nil || json.Unmarshal(payload, &c) != nil {
		return c, false
	}
	return c, true
}

// resolveNSA maps a console's NSA id to its linked Nextendo account PID.
func resolveNSA(nsa uint64) (uint64, error) {
	resp, err := accountHTTP.Get(fmt.Sprintf("%s/api/nsa?id=%d", accountBaseURL, nsa))
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return 0, errNoAccount
	}
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("nsa lookup: %s", resp.Status)
	}
	var out struct {
		PID uint64 `json:"pid"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || out.PID == 0 {
		return 0, fmt.Errorf("nsa lookup: bad response")
	}
	return out.PID, nil
}

var errNoAccount = fmt.Errorf("no Nextendo account")

// onlineCheck asks nextendo-account whether this account may go online (verified, not banned,
// not already online elsewhere). Unlike the NEX servers it fails closed.
func onlineCheck(pid uint64, kind string) (bool, string) {
	body, _ := json.Marshal(map[string]any{"pid": pid, "kind": kind})
	req, err := http.NewRequest(http.MethodPost, accountBaseURL+"/internal/online-check", bytes.NewReader(body))
	if err != nil {
		return false, "internal"
	}
	req.Header.Set("Content-Type", "application/json")
	if internalKey != "" {
		req.Header.Set("X-Internal-Key", internalKey)
	}
	resp, err := accountHTTP.Do(req)
	if err != nil {
		return false, "account service unreachable"
	}
	defer resp.Body.Close()
	var out struct {
		Allow  bool   `json:"allow"`
		Reason string `json:"reason"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&out) != nil {
		return false, "account service error " + resp.Status
	}
	return out.Allow, out.Reason
}

// verifyPlayer turns the console's BAAS id_token into an admitted Nextendo PID.
func verifyPlayer(idToken string) (uint64, error) {
	claims, ok := parseIDToken(idToken)
	if !ok {
		return 0, fmt.Errorf("no id_token")
	}
	var pid uint64
	kind := "ryujinx"
	if claims.Nnex != "" {
		p, ok := pidFromNx2(claims.Nnex)
		if !ok {
			return 0, fmt.Errorf("invalid nx2 token")
		}
		pid = p
	} else {
		nsa, err := strconv.ParseUint(claims.Sub, 16, 64)
		if err != nil || nsa == 0 {
			return 0, fmt.Errorf("no Nextendo identity in id_token")
		}
		if pid, err = resolveNSA(nsa); err != nil {
			return 0, fmt.Errorf("nsa %x: %w", nsa, err)
		}
		kind = "switch"
	}
	if allow, reason := onlineCheck(pid, kind); !allow {
		return 0, fmt.Errorf("pid %d refused: %s", pid, reason)
	}
	return pid, nil
}
