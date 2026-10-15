package main

// Nextendo server for Plants vs. Zombies: Battle for Neighborville (Switch 0100C56010FD8000, 1.0.4):
// gosredirector, Nucleus and ByteVault over HTTPS, and Blaze over TLS.

import (
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type config struct {
	PublicIP  string
	BlazeHost string // the name clients reach us by; the certificate must cover it
	HTTPSPort int
	BlazePort int
	DataDir   string
	DashAddr  string
	DashToken string
}

var (
	cfg       config
	startTime = time.Now()
	sessions  sync.Map // *blazeSession -> time.Time (connected at)
)

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(k)); err == nil {
		return v
	}
	return def
}

func tlsConfig(certFile, keyFile string) *tls.Config {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("TLS certificate: %v", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		// DirtySDK's ProtoSSL predates many modern suites; keep its RSA/AES ones available.
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305, tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384, tls.TLS_RSA_WITH_AES_128_CBC_SHA, tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
	}
}

func httpsMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/redirector/getServerInstance", handleRedirector)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/connect/"), strings.HasPrefix(r.URL.Path, "/proxy/"):
			handleNucleus(w, r)
		case strings.Contains(r.URL.Path, "contexts"):
			handleByteVault(w, r)
		case strings.HasPrefix(r.URL.Path, "/pvz/"):
			// Game configuration and editorial: answering at all completes the login step; the
			// client then uses its built-in configuration.
			log.Printf("[GameConfig] %s %s", r.Method, r.URL.RequestURI())
			http.NotFound(w, r)
		default:
			log.Printf("[HTTPS] unhandled %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	})
	return mux
}

func serveDashboard() {
	if cfg.DashAddr == "" {
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		if cfg.DashToken == "" || subtle.ConstantTimeCompare([]byte(r.URL.Query().Get("key")), []byte(cfg.DashToken)) != 1 {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		now := time.Now()
		players := []map[string]any{}
		sessions.Range(func(k, v any) bool {
			s := k.(*blazeSession)
			if p := s.p; p != nil {
				players = append(players, map[string]any{
					"pid": p.PID, "name": p.Name, "state": "online", "gathering": 0, "isHost": false,
					"idleSeconds": 0, "onlineSeconds": int(now.Sub(v.(time.Time)).Seconds()),
				})
			}
			return true
		})
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(map[string]any{
			"serverTime": now.Unix(), "uptimeSeconds": int(now.Sub(startTime).Seconds()),
			"connected": len(players), "inLobby": 0, "activeLobbies": 0, "players": players,
			"gatherings": []any{}, "events": []any{}, "methods": []any{},
			"server": map[string]any{"accessKey": "pvzbfn", "stack": "blaze", "nexVersion": 0, "sniHost": cfg.BlazeHost},
		})
	})
	log.Printf("[Dashboard] stats API on %s", cfg.DashAddr)
	if err := http.ListenAndServe(cfg.DashAddr, mux); err != nil {
		log.Printf("[Dashboard] stopped: %v", err)
	}
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	cfg = config{
		PublicIP:  os.Getenv("PUBLIC_IP"),
		BlazeHost: envOr("BLAZE_HOST", "spring18.gosredirector.ea.com"),
		HTTPSPort: envInt("HTTPS_PORT", 42230),
		BlazePort: envInt("BLAZE_PORT", 10046),
		DataDir:   envOr("DATA_DIR", "/data"),
		DashAddr:  os.Getenv("DASH_LISTEN"),
		DashToken: os.Getenv("DASH_TOKEN"),
	}
	if ip := net.ParseIP(cfg.PublicIP); ip == nil || ip.To4() == nil {
		log.Fatal("PUBLIC_IP must be the server's public IPv4 address")
	}
	var err error
	if nextendoSecret, err = loadNextendoSecret(); err != nil {
		log.Fatal(err)
	}
	if internalKey == "" {
		log.Printf("NEXTENDO_INTERNAL_KEY unset: account checks rely on the internal docker network")
	}
	tc := tlsConfig(envOr("CERT_FILE", "/data/server.crt"), envOr("KEY_FILE", "/data/server.key"))

	go serveDashboard()
	go func() {
		srv := &http.Server{
			Addr: ":" + strconv.Itoa(cfg.HTTPSPort), Handler: httpsMux(), TLSConfig: tc,
			ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 60 * time.Second, WriteTimeout: 60 * time.Second,
			MaxHeaderBytes: 32 << 10,
		}
		log.Printf("[HTTPS] redirector/nucleus/bytevault on :%d", cfg.HTTPSPort)
		log.Fatal(srv.ListenAndServeTLS("", ""))
	}()
	ln, err := tls.Listen("tcp", ":"+strconv.Itoa(cfg.BlazePort), tc)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("[Blaze] listening on :%d (host %s, public %s)", cfg.BlazePort, cfg.BlazeHost, cfg.PublicIP)
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("[Blaze] accept: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go func() {
			s := &blazeSession{conn: c}
			sessions.Store(s, time.Now())
			defer sessions.Delete(s)
			serveBlaze(s)
		}()
	}
}
