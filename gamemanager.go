package main

// gamemanager - Blaze GameManager (component 4). After QoS the client's primary user creates a
// game group from a template; login only completes once that group reaches
// GAME_GROUP_INITIALIZED (createGameTemplate → NotifyGameSetup → advanceGameState(16)).
// Schemas come from the 1.0.4 binary's TDF member tables.

import (
	"errors"
	"log"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const (
	compGameManager = 4

	gmAdvanceGameState   = 3
	gmDestroyGame        = 2
	gmCreateGameTemplate = 10
	gmFinalizeCreation   = 15

	notifyGameSetup       = 20
	notifyGameStateChange = 100

	gameStateInitializing = 1
	gameTypeSession       = 0
	gameTypeGroup         = 1
	topologyPeerHosted    = 0
	topologyDisabled      = 255
	playerActiveConnected = 4
	presenceStandard      = 1
)

type game struct {
	id       int64
	gameType int64
	topology int64
	state    int64
	template string
	version  string
	attrs    map[string]string
	host     *player
	hostAddr []byte // host's NetworkAddress union value (index byte + member)
	created  time.Time
}

var (
	gamesMu    sync.Mutex
	games      = map[int64]*game{}
	nextGameID atomic.Int64
)

func init() { nextGameID.Store(time.Now().Unix() << 8) }

func hostInfo(p *player) *tdfBuf {
	return new(tdfBuf).Int("HPID", p.persona()).Int("HSES", p.persona()).Int("HSLT", 0)
}

// unionMember appends a union-typed member from its value bytes (index byte + active member).
func unionMember(b *tdfBuf, name string, value []byte) {
	b.head(name, tdfUnion)
	*b = append(*b, value...)
}

func (s *blazeSession) gameSetup(hdr []byte, g *game) []byte {
	p := s.p
	name := "Group"
	if g.gameType != gameTypeGroup {
		name = p.Name
	}
	data := new(tdfBuf).IntList("ADMN", []int64{p.persona()})
	if len(g.attrs) > 0 {
		keys := make([]string, 0, len(g.attrs))
		for k := range g.attrs {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		data.StringMap("ATTR", keys, g.attrs)
	}
	data.IntList("CAP", []int64{4, 0, 0, 0}).
		Int("GGTY", g.gameType).
		Int("GID", g.id).
		Str("GNAM", name).
		Int("GSET", 0).
		Int("GSTA", g.state)
	if g.hostAddr != nil {
		// topologyHostNetworkAddressList: list<NetworkAddress union>.
		data.head("HNET", tdfList)
		*data = append(*data, tdfUnion, 1)
		*data = append(*data, g.hostAddr...)
	}
	data.Int("MCAP", 4).
		Int("MNCP", 1).
		Int("NTOP", g.topology).
		Struct("PHST", hostInfo(p)).
		Int("PRES", presenceStandard).
		Int("QCAP", 0).
		Str("TAME", g.template).
		Struct("THST", hostInfo(p)).
		Str("UUID", randomHex(16)).
		Int("VOIP", 0).
		Str("VSTR", g.version)
	member := new(tdfBuf).
		Raw(s.platformInfo()).
		Int("GID", g.id).
		Str("NAME", p.Name).
		Str("NASP", "cem_ea_id").
		Int("PID", p.persona())
	if g.hostAddr != nil {
		unionMember(member, "PNET", g.hostAddr)
	}
	member.Int("SID", 0).
		Int("SLOT", 0).
		Int("STAT", playerActiveConnected).
		Int("TIDX", 0).
		Int("UID", p.persona())
	// GameSetupReason union: active member 0 (datalessSetupContext, encoded under its own tag),
	// CREATE_GAME_SETUP_CONTEXT.
	reason := tdfTag("REAS")
	setup := new(tdfBuf).Struct("GAME", data).StructList("PROS", []*tdfBuf{member})
	*setup = append(*setup, reason[0], reason[1], reason[2], 6, 0)
	setup.Struct("DLSC", new(tdfBuf).Int("DCTX", 0))
	return notification(hdr, compGameManager, notifyGameSetup, *setup)
}

// templateAttributes flattens createGameTemplate's map<string, generic> into game attributes.
func templateAttributes(tmpa tdfValue) map[string]string {
	attrs := map[string]string{}
	for i := 0; i+1 < len(tmpa.List); i += 2 {
		key, v := tmpa.List[i].Str, tmpa.List[i+1]
		switch {
		case v.Type == tdfString:
			attrs[key] = v.Str
		case v.Type == tdfInt:
			attrs[key] = strconv.FormatInt(v.Int, 10)
		default:
			for _, m := range v.Members {
				if m.Type == tdfString {
					attrs[key] = m.Str
				} else if m.Type == tdfInt {
					attrs[key] = strconv.FormatInt(m.Int, 10)
				}
			}
		}
	}
	return attrs
}

func (s *blazeSession) gameManager(hdr []byte, command uint16, payload []byte) ([]byte, error) {
	if s.p == nil {
		return nil, errNoSession
	}
	dump := payload
	if len(dump) > 2048 {
		dump = dump[:2048]
	}
	log.Printf("[GameManager] conn=%d pid=%d command=%d payload=%x", s.id, s.p.PID, command, dump)
	f, err := decodeTDF(payload)
	if err != nil {
		return nil, err
	}
	switch command {
	case gmCreateGameTemplate:
		g := &game{id: nextGameID.Add(1), gameType: gameTypeGroup, topology: topologyDisabled,
			state: gameStateInitializing, template: f["TMPN"].Str, host: s.p, created: time.Now()}
		if cgd, ok := f["CGD"]; ok && cgd.Type == tdfStruct {
			g.version = cgd.Members["GVER"].Str
		}
		// "gameGroup" is the client's party; every other template (e.g. co-op's "peerHosted") is
		// a game session served by the creating player's own built-in server.
		if g.template != "gameGroup" {
			g.gameType = gameTypeSession
			g.topology = topologyPeerHosted
			g.attrs = templateAttributes(f["TMPA"])
			g.hostAddr = s.netAddr
		}
		gamesMu.Lock()
		games[g.id] = g
		gamesMu.Unlock()
		log.Printf("[GameManager] pid=%d created game %d type=%d from template %q attrs=%v hostAddr=%x",
			s.p.PID, g.id, g.gameType, g.template, g.attrs, g.hostAddr)
		out := reply(hdr, *new(tdfBuf).Int("GID", g.id), kindReply, 0)
		return append(out, s.gameSetup(hdr, g)...), nil
	case gmAdvanceGameState:
		id, state := f["GID"].Int, f["GSTA"].Int
		gamesMu.Lock()
		g := games[id]
		if g != nil && g.host == s.p {
			g.state = state
		}
		gamesMu.Unlock()
		if g == nil || g.host != s.p {
			return nil, errors.New("unknown game")
		}
		log.Printf("[GameManager] pid=%d group %d -> state %d", s.p.PID, id, state)
		change := new(tdfBuf).Int("GID", id).Int("GSTA", state)
		out := reply(hdr, nil, kindReply, 0)
		return append(out, notification(hdr, compGameManager, notifyGameStateChange, *change)...), nil
	case gmFinalizeCreation:
		return reply(hdr, nil, kindReply, 0), nil
	case gmDestroyGame:
		id := f["GID"].Int
		gamesMu.Lock()
		if g := games[id]; g != nil && g.host == s.p {
			delete(games, id)
		}
		gamesMu.Unlock()
		return reply(hdr, *new(tdfBuf).Int("GID", id), kindReply, 0), nil
	}
	return nil, errNotImplemented
}

// dropGames removes groups hosted by a disconnected session.
func (s *blazeSession) dropGames() {
	gamesMu.Lock()
	defer gamesMu.Unlock()
	for id, g := range games {
		if g.host == s.p {
			delete(games, id)
		}
	}
}
