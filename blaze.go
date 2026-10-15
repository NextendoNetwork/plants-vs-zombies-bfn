package main

// blaze - the Blaze TLS connection: 16-byte frame header, then a TDF payload.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const (
	compAuth         = 1
	compUtil         = 9
	compAssociation  = 25
	compPvzGw        = 2053
	compPvzGwStats   = 2058
	compUserSessions = 0x7802

	kindRequest      = 0
	kindReply        = 1
	kindNotification = 2
	kindError        = 3
	kindPing         = 4
	kindPong         = 5

	maxFrame = 1 << 20
)

var (
	onlinePlayers atomic.Int64
	nextConnID    atomic.Int64

	onlineMu        sync.Mutex
	onlineByPersona = map[int64]*blazeSession{}
)

type blazeSession struct {
	id         int64
	conn       net.Conn
	p          *player
	sessionKey string
	loginTime  int64
	platform   int64
	platformID []byte // the client's own AIDS.EXID member, echoed back
	hwFlags    int64
	netAddr    []byte // NetworkAddress union value from updateNetworkInfo
}

func reply(hdr []byte, payload []byte, kind byte, errCode uint16) []byte {
	out := make([]byte, 16, 16+len(payload))
	copy(out, hdr)
	binary.BigEndian.PutUint32(out[0:4], uint32(len(payload)))
	binary.BigEndian.PutUint16(out[4:6], 0)
	out[13] = kind<<5 | hdr[13]&31
	binary.BigEndian.PutUint16(out[14:16], errCode)
	return append(out, payload...)
}

// blazeError is a full Blaze error code: system errors are 0x4000xxxx, component errors are
// code<<16 | component. Fire2 carries it in the reply metadata (ERRC), not the frame header.
type blazeError uint32

func (e blazeError) Error() string { return fmt.Sprintf("blaze error %#08x", uint32(e)) }

const (
	errSystem              blazeError = 0x40010000
	errCommandNotFound     blazeError = 0x40030000
	errAuthRequired        blazeError = 0x40040000
	errPvzFeatureInactive  blazeError = 0x3d<<16 | compPvzGw
	errPvzBlueMoonNotFound blazeError = 0x43<<16 | compPvzGw
)

var errNotImplemented = errors.New("not implemented")

func errorReply(hdr []byte, code blazeError) []byte {
	meta := *new(tdfBuf).Int("ERRC", int64(int32(code)))
	out := reply(hdr, meta, kindError, 0)
	binary.BigEndian.PutUint32(out[0:4], 0)
	binary.BigEndian.PutUint16(out[4:6], uint16(len(meta)))
	return out
}

func notification(hdr []byte, component, command uint16, payload []byte) []byte {
	n := make([]byte, 16)
	copy(n, hdr)
	binary.BigEndian.PutUint16(n[6:8], component)
	binary.BigEndian.PutUint16(n[8:10], command)
	n[10], n[11], n[12] = 0, 0, 0
	return reply(n, payload, kindNotification, 0)
}

func serveBlaze(s *blazeSession) {
	c := s.conn
	s.id = nextConnID.Add(1)
	defer c.Close()
	defer s.endSession("disconnected")
	hdr := make([]byte, 16)
	for {
		c.SetReadDeadline(time.Now().Add(90 * time.Second))
		if _, err := io.ReadFull(c, hdr); err != nil {
			return
		}
		size := binary.BigEndian.Uint32(hdr[0:4])
		meta := binary.BigEndian.Uint16(hdr[4:6])
		component := binary.BigEndian.Uint16(hdr[6:8])
		command := binary.BigEndian.Uint16(hdr[8:10])
		kind := hdr[13] >> 5
		if size+uint32(meta) > maxFrame || kind > kindPong {
			log.Printf("[Blaze] invalid frame size=%d meta=%d kind=%d", size, meta, kind)
			return
		}
		body := make([]byte, int(size)+int(meta))
		c.SetReadDeadline(time.Now().Add(20 * time.Second))
		if _, err := io.ReadFull(c, body); err != nil {
			return
		}
		var out []byte
		switch kind {
		case kindPing:
			out = reply(hdr, nil, kindPong, 0)
		case kindRequest:
			out = s.dispatch(hdr, component, command, body[meta:])
		default:
			continue
		}
		c.SetWriteDeadline(time.Now().Add(15 * time.Second))
		if _, err := c.Write(out); err != nil {
			return
		}
	}
}

var errNoSession = errors.New("no session")

func (s *blazeSession) dispatch(hdr []byte, component, command uint16, payload []byte) []byte {
	if !(component == compUtil && command == 2) {
		log.Printf("[Blaze] conn=%d rpc component=%d command=%d bytes=%d", s.id, component, command, len(payload))
	}
	resp, err := s.handle(hdr, component, command, payload)
	if err == nil {
		return resp
	}
	var code blazeError
	switch {
	case errors.As(err, &code):
	case errors.Is(err, errNoSession):
		code = errAuthRequired
	case errors.Is(err, errNotImplemented):
		code = errCommandNotFound
		dump := payload
		if len(dump) > 256 {
			dump = dump[:256]
		}
		log.Printf("[Blaze] conn=%d rpc component=%d command=%d not implemented payload=%x", s.id, component, command, dump)
	default:
		code = errSystem
		if errors.Is(err, errTDF) {
			dump := payload
			if len(dump) > 4096 {
				dump = dump[:4096]
			}
			log.Printf("[Blaze] conn=%d rpc component=%d command=%d undecodable payload=%x", s.id, component, command, dump)
		}
	}
	log.Printf("[Blaze] conn=%d rpc component=%d command=%d failed: %v", s.id, component, command, err)
	return errorReply(hdr, code)
}

func (s *blazeSession) handle(hdr []byte, component, command uint16, payload []byte) ([]byte, error) {
	ok := func(b *tdfBuf) ([]byte, error) {
		if b == nil {
			return reply(hdr, nil, kindReply, 0), nil
		}
		return reply(hdr, *b, kindReply, 0), nil
	}
	needSession := func() error {
		if s.p == nil {
			return errNoSession
		}
		return nil
	}
	empty := func() ([]byte, error) {
		if err := needSession(); err != nil {
			return nil, err
		}
		return ok(nil)
	}
	if component == compGameManager {
		return s.gameManager(hdr, command, payload)
	}
	switch [2]uint16{component, command} {
	case [2]uint16{compUtil, 2}: // ping
		return ok(new(tdfBuf).Int("STIM", time.Now().Unix()))
	case [2]uint16{compUtil, 7}: // preAuth
		return ok(preAuth())
	case [2]uint16{compUtil, 1}: // fetchClientConfig
		f, err := decodeTDF(payload)
		if err != nil {
			return nil, err
		}
		section := f["CFID"].Str
		log.Printf("[Blaze] fetchClientConfig section=%q", section)
		conf := clientConfig[section]
		keys := make([]string, 0, len(conf))
		for k := range conf {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		return ok(new(tdfBuf).StringMap("CONF", keys, conf))
	case [2]uint16{compAuth, 10}: // login
		return s.login(hdr, payload)
	case [2]uint16{compAuth, 70}: // logout
		return s.logout(hdr), nil
	case [2]uint16{compUtil, 8}: // postAuth
		if err := needSession(); err != nil {
			return nil, err
		}
		b := new(tdfBuf).
			Struct("TELE", new(tdfBuf).Str("ADRS", "").Int("EDCT", 0).Int("PORT", 0).Int("SPCT", 0)).
			Struct("TICK", new(tdfBuf).Str("ADRS", "").Int("PORT", 0).Str("SKEY", "")).
			Struct("UROP", new(tdfBuf).Int("TMOP", 0).Int("UID", s.p.persona()))
		return ok(b)
	case [2]uint16{compUtil, 28}: // userSettingsLoadAll: nothing stored server-side
		return empty()
	case [2]uint16{compUserSessions, 3}: // fetchExtendedData
		if err := needSession(); err != nil {
			return nil, err
		}
		f, err := decodeTDF(payload)
		if err != nil || f["BUID"].Int != s.p.persona() {
			return nil, errors.New("unknown session")
		}
		return ok(s.extendedData())
	case [2]uint16{compUserSessions, 8}: // updateHardwareFlags
		if err := needSession(); err != nil {
			return nil, err
		}
		f, err := decodeTDF(payload)
		if err != nil {
			return nil, err
		}
		s.hwFlags = f["HWFG"].Int
		return ok(nil)
	case [2]uint16{compUserSessions, 20}: // updateNetworkInfo: keep the address a hosted game advertises
		if err := needSession(); err != nil {
			return nil, err
		}
		f, err := decodeTDF(payload)
		if err != nil {
			return nil, err
		}
		if addr, found := f["INFO"].Members["ADDR"]; found && addr.Type == tdfUnion && len(addr.Raw) > 4 {
			s.netAddr = append([]byte(nil), addr.Raw[4:]...)
			log.Printf("[Blaze] conn=%d pid=%d network address %x", s.id, s.p.PID, s.netAddr)
		}
		return ok(nil)
	case [2]uint16{compPvzGw, 30}: // getPlaylists: no live playlists are served yet
		if err := needSession(); err != nil {
			return nil, err
		}
		return ok(new(tdfBuf).StructList("PL", nil))
	case [2]uint16{compPvzGw, 17}: // getClientSettings
		if err := needSession(); err != nil {
			return nil, err
		}
		return ok(clientSettings())
	case [2]uint16{compPvzGw, 90}, [2]uint16{compPvzGw, 91}, [2]uint16{compPvzGw, 110}:
		// get{Active,Available}Challenges, getFestivalInfo: no live content is served. The
		// challenge manager re-polls every frame unless it sees FEATURE_INACTIVE, which stops it.
		if err := needSession(); err != nil {
			return nil, err
		}
		return nil, errPvzFeatureInactive
	case [2]uint16{compPvzGw, 100}: // getBlueMoonSchemaPayload: entities fall back to their own data
		if err := needSession(); err != nil {
			return nil, err
		}
		if f, err := decodeTDF(payload); err == nil {
			log.Printf("[Blaze] conn=%d bluemoon schema %q not served", s.id, f["SCID"].Str)
		}
		return nil, errPvzBlueMoonNotFound
	case [2]uint16{compPvzGw, 97}: // getStatRewards
		if err := needSession(); err != nil {
			return nil, err
		}
		return ok(new(tdfBuf).EmptyStructList("SRIL"))
	case [2]uint16{compPvzGw, 112}: // postLogin (NO_SUBSCRIPTION here would force a trial disconnect)
		return empty()
	case [2]uint16{compPvzGw, 113}: // updateInstalledLicenses
		return empty()
	case [2]uint16{compUtil, 5}: // getTelemetryServer: telemetry stays off
		if err := needSession(); err != nil {
			return nil, err
		}
		return ok(new(tdfBuf).Str("ADRS", "").Int("ANON", 0).Blob("BKEY", nil).Str("DISA", "").
			Int("EDCT", 0).Str("FILT", "").Int("PORT", 0).Str("SESS", s.sessionKey).Str("SKEY", "").
			Int("SPCT", 0).Str("STIM", ""))
	case [2]uint16{compUserSessions, 12}: // lookupUser
		if err := needSession(); err != nil {
			return nil, err
		}
		return s.lookupUser(hdr, payload)
	case [2]uint16{compUserSessions, 25}: // updateUserSessionClientData
		return empty()
	case [2]uint16{compAssociation, 6}: // getLists
		if err := needSession(); err != nil {
			return nil, err
		}
		return s.getLists(hdr, payload)
	}
	if component == compPvzGwStats {
		if err := needSession(); err != nil {
			return nil, err
		}
		return s.stats(hdr, command, payload)
	}
	return nil, errNotImplemented
}

// endSession forgets the logged-in player (the connection itself may stay open).
func (s *blazeSession) endSession(why string) {
	if s.p == nil {
		return
	}
	s.dropGames()
	onlineMu.Lock()
	if onlineByPersona[s.p.persona()] == s {
		delete(onlineByPersona, s.p.persona())
	}
	onlineMu.Unlock()
	onlinePlayers.Add(-1)
	log.Printf("[Blaze] conn=%d pid=%d %s", s.id, s.p.PID, why)
	s.p = nil
	s.sessionKey = ""
}

// logout ends the session. The client only finishes signing out - and can log in again - once
// UserSessions UserUnauthenticated (9) names its BlazeId (UserManager::onUserUnauthenticated).
func (s *blazeSession) logout(hdr []byte) []byte {
	out := reply(hdr, nil, kindReply, 0)
	if s.p == nil {
		return out
	}
	info := new(tdfBuf).Int("BID", s.p.persona()).Int("USTP", 0)
	out = append(out, notification(hdr, compUserSessions, 9, *info)...)
	s.endSession("logged out")
	return out
}

func (s *blazeSession) login(hdr []byte, payload []byte) ([]byte, error) {
	f, err := decodeTDF(payload)
	if err != nil {
		return nil, err
	}
	auth, okAuth := f["AUTH"]
	if !okAuth || auth.Type != tdfString {
		return nil, errors.New("login without AUTH")
	}
	p, valid := redeemCode(auth.Str)
	if !valid {
		return nil, errors.New("unknown or expired authorization code")
	}
	if s.p == nil {
		onlinePlayers.Add(1)
	}
	s.p = &p
	s.sessionKey = randomHex(32)
	s.loginTime = time.Now().Unix()
	if aids, ok := f["AIDS"]; ok && aids.Type == tdfStruct {
		if plat, ok := aids.Members["PLAT"]; ok && plat.Type == tdfInt {
			s.platform = plat.Int
		}
		if exid, ok := aids.Members["EXID"]; ok && exid.Type == tdfStruct {
			s.platformID = exid.Raw
		}
	}
	onlineMu.Lock()
	onlineByPersona[p.persona()] = s
	onlineMu.Unlock()
	log.Printf("[Blaze] conn=%d pid=%d logged in", s.id, p.PID)
	sess := new(tdfBuf).Int("1CON", 0).Raw(s.platformInfo()).
		Int("BUID", p.persona()).Int("FRST", 0).Int("GEO", 0).Str("KEY", s.sessionKey).
		Int("LLOG", s.loginTime).Str("MAIL", "").
		Struct("PDTL", new(tdfBuf).Str("DSNM", p.Name).Int("LAST", s.loginTime).
			Int("PID", p.persona()).Int("STAS", 2).Int("XREF", 0)).
		Int("UID", int64(p.PID))
	resp := new(tdfBuf).Int("ANON", 0).Struct("SESS", sess).Int("SPAM", 0).Int("UNDR", 0)
	out := reply(hdr, *resp, kindReply, 0)
	// The client finishes authenticating only after these two UserSessions notifications.
	loginInfo := new(tdfBuf).Int("1CON", 0).Raw(s.platformInfo()).
		Int("BUID", p.persona()).Str("DSNM", p.Name).Int("FRST", 0).Str("KEY", s.sessionKey).
		Int("LAST", s.loginTime).Int("LLOG", s.loginTime).Str("MAIL", "").Str("NASP", "cem_ea_id").
		Int("PID", p.persona()).Int("PLAT", s.platform).Int("UID", int64(p.PID)).Int("USTP", 0).Int("XREF", 0)
	out = append(out, notification(hdr, compUserSessions, 8, *loginInfo)...)
	ext := new(tdfBuf).Struct("DATA", s.extendedData()).Int("SUBS", 1).Int("USID", p.persona())
	out = append(out, notification(hdr, compUserSessions, 1, *ext)...)
	return out, nil
}

func (s *blazeSession) platformInfo() []byte {
	eaid := new(tdfBuf).Str("NAME", s.p.Name).Int("NID", int64(s.p.PID)).Int("PCID", s.p.persona())
	in := new(tdfBuf).Struct("EAID", eaid)
	if s.platformID != nil {
		in.Raw(s.platformID)
	} else {
		in.Struct("EXID", nil)
	}
	in.Int("PLAT", s.platform)
	return *new(tdfBuf).Struct("AIDS", in)
}

func (s *blazeSession) extendedData() *tdfBuf {
	return new(tdfBuf).Int("HWFG", s.hwFlags).Int("UATT", 0)
}

func preAuth() *tdfBuf {
	nucleus := "https://" + cfg.BlazeHost + ":" + strconv.Itoa(cfg.HTTPSPort)
	conf := map[string]string{
		"associationListSkipInitialSet": "1",
		"autoReconnectEnabled":          "0",
		"bytevaultHostname":             cfg.BlazeHost,
		"bytevaultPort":                 strconv.Itoa(cfg.HTTPSPort),
		"bytevaultSecure":               "true",
		"connIdleTimeout":               "40s",
		"defaultRequestTimeout":         "20s",
		"nucleusConnect":                nucleus,
		"nucleusConnectTrusted":         nucleus,
		"nucleusPortal":                 nucleus,
		"nucleusProxy":                  nucleus,
		"pingPeriod":                    "20s",
	}
	keys := make([]string, 0, len(conf))
	for k := range conf {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	qoss := new(tdfBuf).Struct("BWPS", new(tdfBuf).Str("PSA", cfg.PublicIP).Int("PSP", 0)).
		Int("LNP", 10).Int("TIME", 10000000)
	return new(tdfBuf).
		Str("ASRC", "nextendo").
		IntList("CIDS", []int64{61448, 1, 61449, 25, 61450, 27, 4, 7, 9, 10, 33, 126978, 15,
			61440, 61441, 61442, 61443, 61444, 61445, 61446, 61447, 3984}).
		Str("CLID", "PVZGW3-NX-NEXTENDO").
		Struct("CONF", new(tdfBuf).StringMap("CONF", keys, conf)).
		Str("ESRC", "nextendo").
		Str("INST", "plantsvszombies-gw3-nx").
		Int("MINR", 1).
		Str("NASP", "cem_ea_id").
		Str("PILD", "").
		Str("PLAT", "nx").
		Struct("QOSS", qoss).
		Str("RSRC", "nextendo").
		Str("SVER", "Blaze 15.1.1.8.2 (Nextendo)")
}

var clientConfig = map[string]map[string]string{
	"IdentityParams": {"display": "console2/welcome", "redirect_uri": "http://127.0.0.1/success"},
}

// clientSettings imposes no minimum game revision and offers no downloadable patch. Login waits
// for the game-configuration download (EditorialRootUrl + "/" + GameConfigurationUrl) to finish;
// any HTTP answer completes it, and an empty root made the client retry a blank host forever.
func clientSettings() *tdfBuf {
	setting := func(k, v string) *tdfBuf { return new(tdfBuf).Str("IDEN", k).Str("VALU", v) }
	root := "https://" + cfg.BlazeHost + ":" + strconv.Itoa(cfg.HTTPSPort) + "/pvz"
	return new(tdfBuf).
		StructList("GENS", []*tdfBuf{
			setting("Online.MandatedVersion.Required", "0"),
			setting("Online.MandatedVersion.ExactMatch", "false"),
			setting("Online.EditorialRootUrl", root),
			setting("Online.GameConfigurationUrl", "gameconfiguration"),
		}).
		Struct("PACF", new(tdfBuf).Str("LCUV", "").Str("PRSF", "").Int("PSTA", 0).Str("PURL", ""))
}
