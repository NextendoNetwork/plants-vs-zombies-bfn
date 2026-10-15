package main

// social - UserSessions lookups and Association (friend/block) lists.

import (
	"strings"
)

const userDataOnline = 3 // UserDataFlags: SUBSCRIBED | ONLINE

// userIdentification describes this session's player (Blaze UserIdentification).
func (s *blazeSession) userIdentification() *tdfBuf {
	p := s.p
	return new(tdfBuf).Int("AID", int64(p.PID)).Raw(s.platformInfo()).
		Int("ALOC", 0x656e5553). // enUS
		Int("CNTY", 0x5553).
		Int("ID", p.persona()).Str("NAME", p.Name).Str("NASP", "cem_ea_id").
		Int("ORIG", int64(p.PID)).Int("PIDI", int64(p.PID)).Int("PLAT", s.platform)
}

// findSession resolves a UserIdentification against the players currently online.
func findSession(f map[string]tdfValue) *blazeSession {
	id, name := f["ID"].Int, f["NAME"].Str
	pid := f["PIDI"].Int
	if pid == 0 {
		pid = f["AID"].Int
	}
	onlineMu.Lock()
	defer onlineMu.Unlock()
	if s := onlineByPersona[id]; id != 0 && s != nil {
		return s
	}
	for _, s := range onlineByPersona {
		if (name != "" && strings.EqualFold(s.p.Name, name)) || (pid != 0 && int64(s.p.PID) == pid) {
			return s
		}
	}
	return nil
}

func (s *blazeSession) lookupUser(hdr []byte, payload []byte) ([]byte, error) {
	f, err := decodeTDF(payload)
	if err != nil {
		return nil, err
	}
	t := findSession(f)
	if t == nil {
		return nil, errSystem
	}
	data := new(tdfBuf).Struct("EDAT", t.extendedData()).Int("FLGS", userDataOnline).
		Struct("USER", t.userIdentification())
	return reply(hdr, *data, kindReply, 0), nil
}

// getLists returns every requested list empty: friends come from the platform, not Blaze.
func (s *blazeSession) getLists(hdr []byte, payload []byte) ([]byte, error) {
	f, err := decodeTDF(payload)
	if err != nil {
		return nil, err
	}
	var lists []*tdfBuf
	for _, e := range f["ALST"].List {
		if e.Type != tdfStruct {
			continue
		}
		info := e.Raw
		if _, isInfo := e.Members["LID"]; !isInfo {
			// A bare ListIdentification: wrap it as ListInfo.LID.
			info = appendStructBody(nil, new(tdfBuf).StructRaw("LID", e.Raw))
		}
		lists = append(lists, new(tdfBuf).StructRaw("INFO", info).EmptyStructList("MEML").
			Int("OFRC", 0).Int("TOCT", 0))
	}
	return reply(hdr, *new(tdfBuf).StructList("LMAP", lists), kindReply, 0), nil
}
