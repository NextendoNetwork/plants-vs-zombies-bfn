package main

// stats - PvzGwStats (component 2058), the player's progression stats. Reads are answered
// with a reply and then a result notification carrying the request's TASK id; the client
// only finishes downloading (and leaves the loading screen) once that notification arrives.
// Values persist per PID under DATA_DIR/stats.

import (
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
)

const (
	statsGetCategoryIds      = 4
	statsGetUserStats        = 100
	statsGetAllUserStats     = 101
	statsGetUnknownUserStats = 102
	statsUpdateUserStats     = 200

	notifyGetUserStats        = 10
	notifyGetAllUserStats     = 11
	notifyGetUnknownUserStats = 12
	notifyUpdateUserStats     = 20

	opSum       = 1
	opDecrement = 2
	opMin       = 3
	opMax       = 4
	opReplace   = 5

	maxStatsPerPlayer = 20000
)

type dimValue struct {
	Dims  map[string]string `json:"dims"`
	Value float32           `json:"value"`
}

// statStore is category -> stat -> value, plus dimensioned values keyed the same way.
type statStore struct {
	Values      map[string]map[string]float32    `json:"values"`
	Dimensioned map[string]map[string][]dimValue `json:"dimensioned,omitempty"`
}

var statsMu sync.Mutex

func statsPath(pid uint64) string {
	return filepath.Join(cfg.DataDir, "stats", strconv.FormatUint(pid, 10)+".json")
}

// loadStats must be called with statsMu held.
func loadStats(pid uint64) *statStore {
	st := &statStore{}
	if b, err := os.ReadFile(statsPath(pid)); err == nil {
		if err := json.Unmarshal(b, st); err != nil {
			log.Printf("[Stats] pid=%d unreadable store: %v", pid, err)
		}
	}
	if st.Values == nil {
		st.Values = map[string]map[string]float32{}
	}
	if st.Dimensioned == nil {
		st.Dimensioned = map[string]map[string][]dimValue{}
	}
	return st
}

func saveStats(pid uint64, st *statStore) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(statsPath(pid)), 0o700); err != nil {
		return err
	}
	return writeAtomic(statsPath(pid), b)
}

// statOwner maps a stats entity id (persona or Nucleus PID) to a PID.
func statOwner(eid int64) uint64 {
	if eid > 1<<40 {
		return uint64(eid &^ (1 << 40))
	}
	return uint64(eid)
}

func sameDims(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// statValueResponse encodes one category's values; want limits it to the named stats.
func statValueResponse(vals map[string]float32, dims map[string][]dimValue, want []string) *tdfBuf {
	names := want
	if len(names) == 0 {
		for k := range vals {
			names = append(names, k)
		}
		for k := range dims {
			names = append(names, k)
		}
		sort.Strings(names)
	}
	var sivm, dsvm []byte
	nSivm, nDsvm := 0, 0
	seen := map[string]bool{}
	for _, n := range names {
		if seen[n] {
			continue
		}
		seen[n] = true
		if v, ok := vals[n]; ok {
			sivm = appendRawString(sivm, n)
			sivm = appendFloat(sivm, v)
			nSivm++
		}
		if dv := dims[n]; len(dv) > 0 {
			dsvm = appendRawString(dsvm, n)
			dsvm = append(dsvm, tdfStruct)
			dsvm = appendVarint(dsvm, int64(len(dv)))
			for _, d := range dv {
				keys := make([]string, 0, len(d.Dims))
				for k := range d.Dims {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				e := new(tdfBuf).StringMap("DIMV", keys, d.Dims)
				e.head("VAL", tdfFloat)
				*e = appendFloat(*e, d.Value)
				dsvm = appendStructBody(dsvm, e)
			}
			nDsvm++
		}
	}
	// Nested collections are typed as struct (3) with the bare list body; see nestedKinds.
	return new(tdfBuf).Map("DSVM", tdfString, tdfStruct, nDsvm, dsvm).Int("ERR", 0).
		Map("SIVM", tdfString, tdfFloat, nSivm, sivm)
}

func notificationInfo(task int64) *tdfBuf {
	return new(tdfBuf).Int("NNUM", 0).Int("TASK", task).Int("TNUM", 1)
}

func strList(v tdfValue) []string {
	out := make([]string, 0, len(v.List))
	for _, e := range v.List {
		out = append(out, e.Str)
	}
	return out
}

func (s *blazeSession) stats(hdr []byte, command uint16, payload []byte) ([]byte, error) {
	f, err := decodeTDF(payload)
	if err != nil {
		return nil, err
	}
	task := f["TASK"].Int
	switch command {
	case statsGetCategoryIds:
		statsMu.Lock()
		st := loadStats(s.p.PID)
		statsMu.Unlock()
		cats := make([]string, 0, len(st.Values))
		for c := range st.Values {
			cats = append(cats, c)
		}
		sort.Strings(cats)
		return reply(hdr, *new(tdfBuf).StrList("CIDL", cats), kindReply, 0), nil

	case statsGetAllUserStats:
		eid := f["EID"].Int
		statsMu.Lock()
		st := loadStats(statOwner(eid))
		statsMu.Unlock()
		var cats []string
		want := map[string][]string{}
		for i := 0; i+1 < len(f["SIDS"].List); i += 2 {
			c := f["SIDS"].List[i].Str
			cats = append(cats, c)
			want[c] = strList(f["SIDS"].List[i+1])
		}
		if len(cats) == 0 {
			for c := range st.Values {
				cats = append(cats, c)
			}
			sort.Strings(cats)
		}
		var body []byte
		for _, c := range cats {
			body = appendRawString(body, c)
			body = appendStructBody(body, statValueResponse(st.Values[c], st.Dimensioned[c], want[c]))
		}
		log.Printf("[Stats] conn=%d getAllUserStats eid=%d task=%d categories=%v", s.id, eid, task, cats)
		result := new(tdfBuf).Map("CSVM", tdfString, tdfStruct, len(cats), body).Int("EID", eid).
			Struct("NNFO", notificationInfo(task))
		out := reply(hdr, *new(tdfBuf).StrList("CATS", nil), kindReply, 0)
		return append(out, notification(hdr, compPvzGwStats, notifyGetAllUserStats, *result)...), nil

	case statsGetUnknownUserStats:
		eid := f["EID"].Int
		statsMu.Lock()
		st := loadStats(statOwner(eid))
		statsMu.Unlock()
		wanted := strList(f["SIDS"])
		for i := 0; i < len(f["DSID"].List); i += 2 {
			wanted = append(wanted, f["DSID"].List[i].Str)
		}
		// Group the requested stats by the category they were stored under.
		byCat := map[string][]string{}
		for _, n := range wanted {
			for c, vals := range st.Values {
				if _, ok := vals[n]; ok {
					byCat[c] = append(byCat[c], n)
				}
			}
			for c, dims := range st.Dimensioned {
				if _, ok := dims[n]; ok {
					byCat[c] = append(byCat[c], n)
				}
			}
		}
		cats := make([]string, 0, len(byCat))
		for c := range byCat {
			cats = append(cats, c)
		}
		sort.Strings(cats)
		var body []byte
		for _, c := range cats {
			body = appendRawString(body, c)
			body = appendStructBody(body, statValueResponse(st.Values[c], st.Dimensioned[c], byCat[c]))
		}
		log.Printf("[Stats] conn=%d getUnknownUserStats eid=%d task=%d stats=%d found=%d", s.id, eid, task, len(wanted), len(cats))
		result := new(tdfBuf).Map("CSVM", tdfString, tdfStruct, len(cats), body).Int("EID", eid).
			Struct("NNFO", notificationInfo(task))
		out := reply(hdr, nil, kindReply, 0)
		return append(out, notification(hdr, compPvzGwStats, notifyGetUnknownUserStats, *result)...), nil

	case statsGetUserStats:
		want := strList(f["SIDS"])
		var body []byte
		ids := f["IDS"].List
		for _, id := range ids {
			statsMu.Lock()
			st := loadStats(statOwner(id.Int))
			statsMu.Unlock()
			merged := map[string]float32{}
			for _, vals := range st.Values {
				for k, v := range vals {
					merged[k] = v
				}
			}
			body = appendVarint(body, id.Int)
			body = appendStructBody(body, statValueResponse(merged, nil, want))
		}
		log.Printf("[Stats] conn=%d getUserStats view=%q task=%d entities=%d", s.id, f["VIEW"].Str, task, len(ids))
		result := new(tdfBuf).Map("ESVM", tdfInt, tdfStruct, len(ids), body).Struct("NNFO", notificationInfo(task))
		out := reply(hdr, *new(tdfBuf).StrList("STAT", nil), kindReply, 0)
		return append(out, notification(hdr, compPvzGwStats, notifyGetUserStats, *result)...), nil

	case statsUpdateUserStats:
		cat := f["CAT"].Str
		if err := s.applyStatUpdates(cat, f["ESUM"]); err != nil {
			return nil, err
		}
		result := new(tdfBuf).EmptyStructList("FUSR").Struct("NNFO", notificationInfo(task))
		out := reply(hdr, *new(tdfBuf).StrList("STAT", nil), kindReply, 0)
		return append(out, notification(hdr, compPvzGwStats, notifyUpdateUserStats, *result)...), nil
	}
	return nil, errNotImplemented
}

// applyStatUpdates applies ESUM (entity -> stat -> StatValueUpdate) for the session's own player.
// The client sends most updates without a category; those are stored under "" and found again
// through getUnknownUserStats, which looks stats up by name.
func (s *blazeSession) applyStatUpdates(cat string, esum tdfValue) error {
	statsMu.Lock()
	defer statsMu.Unlock()
	st := loadStats(s.p.PID)
	changed := 0
	for i := 0; i+1 < len(esum.List); i += 2 {
		if statOwner(esum.List[i].Int) != s.p.PID {
			log.Printf("[Stats] conn=%d pid=%d refused update for entity %d", s.id, s.p.PID, esum.List[i].Int)
			continue
		}
		updates := esum.List[i+1].List
		for j := 0; j+1 < len(updates); j += 2 {
			name, u := updates[j].Str, updates[j+1].Members
			op, val := u["OPRT"].Int, u["VAL"].Float
			var dims map[string]string
			if d := u["DIMS"].List; len(d) > 0 {
				dims = map[string]string{}
				for k := 0; k+1 < len(d); k += 2 {
					dims[d[k].Str] = d[k+1].Str
				}
			}
			if dims == nil {
				vals := st.Values[cat]
				if vals == nil {
					vals = map[string]float32{}
					st.Values[cat] = vals
				}
				cur, exists := vals[name]
				if !exists && (op == opMin || op == opMax) {
					cur = val
				}
				vals[name] = applyStatOp(cur, val, op)
			} else {
				byStat := st.Dimensioned[cat]
				if byStat == nil {
					byStat = map[string][]dimValue{}
					st.Dimensioned[cat] = byStat
				}
				found := false
				for k := range byStat[name] {
					if sameDims(byStat[name][k].Dims, dims) {
						byStat[name][k].Value = applyStatOp(byStat[name][k].Value, val, op)
						found = true
					}
				}
				if !found {
					byStat[name] = append(byStat[name], dimValue{Dims: dims, Value: applyStatOp(0, val, op)})
				}
			}
			changed++
		}
	}
	total := 0
	for _, vals := range st.Values {
		total += len(vals)
	}
	if total > maxStatsPerPlayer {
		return errors.New("stat limit reached")
	}
	if changed > 0 {
		if err := saveStats(s.p.PID, st); err != nil {
			return err
		}
	}
	log.Printf("[Stats] conn=%d pid=%d category=%q updated %d stats", s.id, s.p.PID, cat, changed)
	return nil
}

// applyStatOp mirrors the client's PVZClientOnlineStatisticsManager::getUpdatedValue.
func applyStatOp(cur, val float32, op int64) float32 {
	switch op {
	case opSum:
		return cur + val
	case opDecrement:
		return cur - val
	case opMin:
		if val < cur {
			return val
		}
		return cur
	case opMax:
		if val > cur {
			return val
		}
		return cur
	}
	return val
}
