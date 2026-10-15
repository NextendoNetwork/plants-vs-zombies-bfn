package main

// nucleus - EA's OAuth-style identity service. The console's BAAS id_token (nsatoken header)
// is the only way in; codes are one-time and tokens are signed with the Nextendo secret.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	accessTTL  = time.Hour
	refreshTTL = 30 * 24 * time.Hour
	codeTTL    = 2 * time.Minute
)

type player struct {
	PID  uint64
	Name string
}

// persona keeps Blaze ids out of the Nucleus PID range so the two can never collide.
func (p player) persona() int64 { return int64(p.PID | 1<<40) }

type pendingCode struct {
	p   player
	exp time.Time
}

var (
	codesMu sync.Mutex
	codes   = map[string]pendingCode{}
	namesMu sync.Mutex
	names   = map[uint64]string{}
)

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func issueCode(p player) string {
	code := "NXP" + randomHex(16)
	codesMu.Lock()
	defer codesMu.Unlock()
	now := time.Now()
	for k, v := range codes {
		if now.After(v.exp) {
			delete(codes, k)
		}
	}
	codes[code] = pendingCode{p, now.Add(codeTTL)}
	return code
}

func redeemCode(code string) (player, bool) {
	codesMu.Lock()
	defer codesMu.Unlock()
	c, ok := codes[code]
	delete(codes, code)
	if !ok || time.Now().After(c.exp) {
		return player{}, false
	}
	return c.p, true
}

func signToken(kind string, pid uint64, ttl time.Duration) string {
	body := fmt.Sprintf("pvz-%s.%d.%d.%s", kind, pid, time.Now().Add(ttl).Unix(), randomHex(4))
	mac := hmac.New(sha256.New, nextendoSecret)
	mac.Write([]byte(body))
	return body + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func verifyToken(kind, tok string) (player, bool) {
	i := strings.LastIndexByte(tok, '.')
	if i <= 0 {
		return player{}, false
	}
	body, sig := tok[:i], tok[i+1:]
	mac := hmac.New(sha256.New, nextendoSecret)
	mac.Write([]byte(body))
	if !hmac.Equal([]byte(base64.RawURLEncoding.EncodeToString(mac.Sum(nil))), []byte(sig)) {
		return player{}, false
	}
	f := strings.Split(body, ".")
	if len(f) != 4 || f[0] != "pvz-"+kind {
		return player{}, false
	}
	pid, err := strconv.ParseUint(f[1], 10, 64)
	exp, eerr := strconv.ParseInt(f[2], 10, 64)
	if err != nil || eerr != nil || pid == 0 || time.Now().Unix() > exp {
		return player{}, false
	}
	return player{PID: pid, Name: displayName(pid)}, true
}

func rememberName(pid uint64, name string) {
	namesMu.Lock()
	names[pid] = name
	namesMu.Unlock()
}

func displayName(pid uint64) string {
	namesMu.Lock()
	defer namesMu.Unlock()
	if n := names[pid]; n != "" {
		return n
	}
	return "Player"
}

// bearerPlayer accepts our access token from "Authorization: Bearer", a bare Authorization
// value (ByteVault) or the access_token query/header the Nucleus SDK uses.
func bearerPlayer(r *http.Request) (player, bool) {
	cands := []string{r.Header.Get("Authorization"), r.Header.Get("access_token"), r.URL.Query().Get("access_token")}
	for _, c := range cands {
		c = strings.TrimSpace(c)
		if sp := strings.IndexByte(c, ' '); sp > 0 {
			c = strings.TrimSpace(c[sp+1:])
		}
		if p, ok := verifyToken("at", c); ok {
			return p, true
		}
	}
	return player{}, false
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func appendQuery(uri, kv string) string {
	if strings.Contains(uri, "?") {
		return uri + "&" + kv
	}
	return uri + "?" + kv
}

func handleNucleus(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	switch r.URL.Path {
	case "/connect/auth":
		redirect := r.Form.Get("redirect_uri")
		if r.Form.Get("response_type") != "code" || redirect == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
			return
		}
		p, ok := bearerPlayer(r)
		if !ok {
			pid, err := verifyPlayer(r.Header.Get("nsatoken"))
			if err != nil {
				log.Printf("[Nucleus] login refused: %v", err)
				http.Redirect(w, r, appendQuery(redirect, "error=login_required"), http.StatusFound)
				return
			}
			name, _ := url.QueryUnescape(r.Header.Get("nsa_nickname"))
			if name == "" {
				name = "Player"
			}
			if len(name) > 32 {
				name = name[:32]
			}
			rememberName(pid, name)
			p = player{PID: pid, Name: name}
			log.Printf("[Nucleus] pid=%d signed in", pid)
		}
		http.Redirect(w, r, appendQuery(redirect, "code="+issueCode(p)), http.StatusFound)
	case "/connect/token":
		var p player
		var ok bool
		switch r.Form.Get("grant_type") {
		case "authorization_code":
			p, ok = redeemCode(r.Form.Get("code"))
		case "refresh_token":
			p, ok = verifyToken("rt", r.Form.Get("refresh_token"))
		}
		if !ok {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token": signToken("at", p.PID, accessTTL), "token_type": "Bearer",
			"expires_in": int(accessTTL.Seconds()), "refresh_token": signToken("rt", p.PID, refreshTTL),
			"refresh_token_expires_in": int(refreshTTL.Seconds()),
		})
	case "/connect/tokeninfo":
		p, ok := bearerPlayer(r)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
			return
		}
		clientID := r.Form.Get("client_id")
		if clientID == "" {
			clientID = "PVZGW3_NX"
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"client_id": clientID, "scope": "basic.identity offline signin basic.entitlement basic.persona",
			"expires_in": int(accessTTL.Seconds()) - 1, "pid_id": strconv.FormatUint(p.PID, 10), "pid_type": "NUCLEUS",
			"user_id": strconv.FormatUint(p.PID, 10), "persona_id": p.persona(), "is_underage": false, "stopProcess": "OFF",
		})
	case "/connect/invalidate":
		w.WriteHeader(http.StatusOK)
	case "/proxy/identity/pids/me":
		p, ok := bearerPlayer(r)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"pid": map[string]any{
			"pidId": p.PID, "externalRefType": "NX", "externalRefValue": "", "status": "ACTIVE",
			"dob": "1990-01-01", "country": "US", "language": "en", "locale": "en_US", "tosVersion": "",
			"underagePid": false, "emailStatus": "VERIFIED", "dateCreated": "2020-01-01T00:00Z", "lastAuthDate": "2020-01-01T00:00Z",
		}})
	default:
		if strings.HasPrefix(r.URL.Path, "/proxy/identity/pids/me/personas") {
			p, ok := bearerPlayer(r)
			if !ok {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"personas": map[string]any{"persona": []any{map[string]any{
				"personaId": p.persona(), "pidId": p.PID, "displayName": p.Name, "name": p.Name,
				"namespaceName": "cem_ea_id", "isVisible": true, "status": "ACTIVE", "statusReasonCode": "",
				"showPersona": "EVERYONE", "dateCreated": "2020-01-01T00:00Z", "lastAuthenticated": "2020-01-01T00:00Z",
			}}}})
			return
		}
		log.Printf("[Nucleus] unhandled %s %s", r.Method, r.URL.Path)
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_implemented"})
	}
}
