package main

// bytevault - EA ByteVault (Blaze REST, JSON encoder): the player's online profile save.
// The client's login waits for getRecord; a player without a record gets an empty one.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxRecordBytes   = 8 << 20
	maxRecordsPerPID = 64
)

var (
	recordPath     = regexp.MustCompile(`contexts/([^/]+)/categories/([^/]+)/records/([^/?]+)$`)
	recordInfoPath = regexp.MustCompile(`contexts/([^/]+)/categories/([^/]+)/recordinfo$`)
	vaultMu        sync.Mutex
)

type recordMeta struct {
	Context     string `json:"context"`
	Category    string `json:"category"`
	Record      string `json:"record"`
	ContentType string `json:"content_type"`
	Created     int64  `json:"created"`
	Updated     int64  `json:"updated"`
	Size        int    `json:"size"`
}

func vaultDir(pid uint64) string {
	return filepath.Join(cfg.DataDir, "bytevault", strconv.FormatUint(pid, 10))
}

func recordKey(ctx, cat, rec string) string {
	sum := sha256.Sum256([]byte(ctx + "\x00" + cat + "\x00" + rec))
	return hex.EncodeToString(sum[:16])
}

func readMeta(path string) (recordMeta, bool) {
	var m recordMeta
	b, err := os.ReadFile(path)
	return m, err == nil && json.Unmarshal(b, &m) == nil
}

func writeAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// requestShape logs what the client sent without any credential or payload values.
func requestShape(r *http.Request) string {
	var hs []string
	for k := range r.Header {
		hs = append(hs, k)
	}
	sort.Strings(hs)
	return r.Method + " " + r.URL.Path + " headers=" + strings.Join(hs, ",") +
		" token_type=" + r.Header.Get("X-Token-Type") + " user_type=" + r.Header.Get("X-User-Type") +
		" content_type=" + r.Header.Get("Content-Type") + " len=" + strconv.FormatInt(r.ContentLength, 10)
}

func handleByteVault(w http.ResponseWriter, r *http.Request) {
	shape := requestShape(r)
	p, ok := bearerPlayer(r)
	if !ok {
		log.Printf("[ByteVault] unauthenticated %s", shape)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}
	log.Printf("[ByteVault] pid=%d %s", p.PID, shape)
	if m := recordInfoPath.FindStringSubmatch(r.URL.Path); m != nil && r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, map[string]any{})
		return
	}
	m := recordPath.FindStringSubmatch(r.URL.Path)
	if m == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_implemented"})
		return
	}
	ctx, cat, rec := m[1], m[2], m[3]
	dir := vaultDir(p.PID)
	base := filepath.Join(dir, recordKey(ctx, cat, rec))
	vaultMu.Lock()
	defer vaultMu.Unlock()
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		meta, ok := readMeta(base + ".json")
		if !ok {
			// No saved profile yet: an empty record lets the client start a fresh one.
			w.Header().Set("Content-Length", "0")
			w.WriteHeader(http.StatusOK)
			return
		}
		data, err := os.ReadFile(base + ".bin")
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "storage"})
			return
		}
		if meta.ContentType != "" {
			w.Header().Set("Content-Type", meta.ContentType)
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			w.Write(data)
		}
	case http.MethodPut:
		data, err := io.ReadAll(io.LimitReader(r.Body, maxRecordBytes+1))
		if err != nil || len(data) > maxRecordBytes {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "too_large"})
			return
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "storage"})
			return
		}
		meta, existed := readMeta(base + ".json")
		if !existed {
			if entries, _ := filepath.Glob(filepath.Join(dir, "*.json")); len(entries) >= maxRecordsPerPID {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "record_limit"})
				return
			}
			meta = recordMeta{Context: ctx, Category: cat, Record: rec, Created: time.Now().Unix()}
		}
		meta.ContentType = r.Header.Get("Content-Type")
		meta.Updated = time.Now().Unix()
		meta.Size = len(data)
		mb, _ := json.Marshal(meta)
		if writeAtomic(base+".bin", data) != nil || writeAtomic(base+".json", mb) != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "storage"})
			return
		}
		log.Printf("[ByteVault] pid=%d saved %s/%s/%s (%d bytes)", p.PID, ctx, cat, rec, len(data))
		writeJSON(w, http.StatusOK, map[string]any{})
	case http.MethodDelete:
		os.Remove(base + ".bin")
		os.Remove(base + ".json")
		writeJSON(w, http.StatusOK, map[string]any{})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method"})
	}
}
