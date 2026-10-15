package main

// tdf - EA Blaze TDF binary encoding (Blaze 15, as spoken by the Switch 1.0.4 client).
// Every member is a 3-byte packed tag, a 1-byte wire type, then the value. Integers use a
// 6-bit first group (with a sign bit) followed by 7-bit groups.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

const (
	tdfInt    = 0
	tdfString = 1
	tdfBlob   = 2
	tdfStruct = 3
	tdfList   = 4
	tdfMap      = 5
	tdfUnion    = 6
	tdfVariable = 7
	tdfFloat    = 10 // 4 bytes, big-endian IEEE 754
	tdfGeneric  = 12
)

func tdfTag(name string) [3]byte {
	var bits uint32
	for i := 0; i < 4; i++ {
		c := byte(' ')
		if i < len(name) {
			c = name[i]
		}
		bits = bits<<6 | uint32(c-32)&63
	}
	return [3]byte{byte(bits >> 16), byte(bits >> 8), byte(bits)}
}

func tagName(t [3]byte) string {
	bits := uint32(t[0])<<16 | uint32(t[1])<<8 | uint32(t[2])
	out := make([]byte, 0, 4)
	for i := 3; i >= 0; i-- {
		c := byte(bits>>(6*uint(i))&63) + 32
		if c != ' ' {
			out = append(out, c)
		}
	}
	return string(out)
}

// tdfBuf builds an encoded TDF member list.
type tdfBuf []byte

func appendVarint(b []byte, n int64) []byte {
	var sign byte
	u := uint64(n)
	if n < 0 {
		sign = 0x40
		u = uint64(-n)
	}
	b = append(b, byte(u&63)|sign)
	u >>= 6
	for u != 0 {
		b[len(b)-1] |= 0x80
		b = append(b, byte(u&127))
		u >>= 7
	}
	return b
}

func appendRawString(b []byte, s string) []byte {
	b = appendVarint(b, int64(len(s)+1))
	b = append(b, s...)
	return append(b, 0)
}

func (b *tdfBuf) head(name string, typ byte) {
	t := tdfTag(name)
	*b = append(*b, t[0], t[1], t[2], typ)
}

func (b *tdfBuf) Int(name string, v int64) *tdfBuf {
	b.head(name, tdfInt)
	*b = appendVarint(*b, v)
	return b
}

func (b *tdfBuf) Str(name, v string) *tdfBuf {
	b.head(name, tdfString)
	*b = appendRawString(*b, v)
	return b
}

func (b *tdfBuf) Struct(name string, members *tdfBuf) *tdfBuf {
	b.head(name, tdfStruct)
	if members != nil {
		*b = append(*b, *members...)
	}
	*b = append(*b, 0)
	return b
}

// Raw appends an already-encoded member (for example one echoed from a request).
func (b *tdfBuf) Raw(member []byte) *tdfBuf {
	*b = append(*b, member...)
	return b
}

func (b *tdfBuf) IntList(name string, vals []int64) *tdfBuf {
	b.head(name, tdfList)
	*b = append(*b, tdfInt)
	*b = appendVarint(*b, int64(len(vals)))
	for _, v := range vals {
		*b = appendVarint(*b, v)
	}
	return b
}

// EmptyStructList encodes a list of structs with no elements.
func (b *tdfBuf) EmptyStructList(name string) *tdfBuf {
	b.head(name, tdfList)
	*b = append(*b, tdfStruct, 0)
	return b
}

// StructList encodes a list whose elements are struct bodies (members without terminators).
func (b *tdfBuf) StructList(name string, elems []*tdfBuf) *tdfBuf {
	b.head(name, tdfList)
	*b = append(*b, tdfStruct)
	*b = appendVarint(*b, int64(len(elems)))
	for _, e := range elems {
		*b = append(*b, *e...)
		*b = append(*b, 0)
	}
	return b
}

// StringMap encodes map<string,string> with keys in the given order.
func (b *tdfBuf) StringMap(name string, keys []string, m map[string]string) *tdfBuf {
	b.head(name, tdfMap)
	*b = append(*b, tdfString, tdfString)
	*b = appendVarint(*b, int64(len(keys)))
	for _, k := range keys {
		*b = appendRawString(*b, k)
		*b = appendRawString(*b, m[k])
	}
	return b
}

// EmptyMap encodes an empty map with the given key/value wire types.
func (b *tdfBuf) EmptyMap(name string, keyType, valType byte) *tdfBuf {
	b.head(name, tdfMap)
	*b = append(*b, keyType, valType, 0)
	return b
}

func (b *tdfBuf) Blob(name string, v []byte) *tdfBuf {
	b.head(name, tdfBlob)
	*b = appendVarint(*b, int64(len(v)))
	*b = append(*b, v...)
	return b
}

// StructRaw appends a struct member whose body (members plus terminator) is already encoded.
func (b *tdfBuf) StructRaw(name string, body []byte) *tdfBuf {
	b.head(name, tdfStruct)
	*b = append(*b, body...)
	return b
}

// StrList encodes list<string>.
func (b *tdfBuf) StrList(name string, vals []string) *tdfBuf {
	b.head(name, tdfList)
	*b = append(*b, tdfString)
	*b = appendVarint(*b, int64(len(vals)))
	for _, v := range vals {
		*b = appendRawString(*b, v)
	}
	return b
}

// Map encodes a map whose n key/value pairs are already encoded in body.
func (b *tdfBuf) Map(name string, keyType, valType byte, n int, body []byte) *tdfBuf {
	b.head(name, tdfMap)
	*b = append(*b, keyType, valType)
	*b = appendVarint(*b, int64(n))
	*b = append(*b, body...)
	return b
}

func appendFloat(b []byte, f float32) []byte {
	return binary.BigEndian.AppendUint32(b, math.Float32bits(f))
}

// appendStructBody encodes a struct value (map value or list element): members then terminator.
func appendStructBody(b []byte, members *tdfBuf) []byte {
	if members != nil {
		b = append(b, *members...)
	}
	return append(b, 0)
}

// tdfValue is one decoded member. Raw is the member's full encoding (tag through value); for a
// list element it is the element's value encoding. Map entries are List pairs (key, value).
type tdfValue struct {
	Type    byte
	Int     int64
	Float   float32
	Str     string
	Blob    []byte
	Members map[string]tdfValue // struct
	List    []tdfValue
	Raw     []byte
}

var errTDF = errors.New("malformed TDF")

// Heat2 tags a list element or map value that is itself a collection as type 3 (struct) but
// writes the bare collection body (types, count, items), so it can only be read with the schema.
// nestedKinds names the members whose type-3 elements are maps ('m') or lists ('l').
var nestedKinds = map[string]byte{
	"ESUM": 'm', // UpdateUserStatsRequest: entity -> stat -> StatValueUpdate
	"DSID": 'm', // GetUnknownUserStatsRequest: stat -> dimensions
	"SIDS": 'l', // GetAllUserStatsRequest: category -> stat ids
	"DSVM": 'l', // StatValueResponse: stat -> DimensionedStatValue list
	"CHIM": 'l',
	"CGCM": 'm',
}

type tdfReader struct {
	b     []byte
	pos   int
	depth int
}

func (r *tdfReader) varint() (int64, error) {
	if r.pos >= len(r.b) {
		return 0, errTDF
	}
	c := r.b[r.pos]
	r.pos++
	neg := c&0x40 != 0
	u := uint64(c & 63)
	for shift := uint(6); c&0x80 != 0; shift += 7 {
		if r.pos >= len(r.b) || shift > 62 {
			return 0, errTDF
		}
		c = r.b[r.pos]
		r.pos++
		u |= uint64(c&127) << shift
	}
	if neg {
		return -int64(u), nil
	}
	return int64(u), nil
}

func (r *tdfReader) value(typ byte) (tdfValue, error) { return r.valueOf(typ, 0) }

// element reads one list element or map value; nested says what a type-3 element really is.
func (r *tdfReader) element(typ, nested byte) (tdfValue, error) {
	if typ != tdfStruct || nested == 0 {
		return r.value(typ)
	}
	if nested == 'm' {
		return r.valueOf(tdfMap, 0)
	}
	return r.valueOf(tdfList, 0)
}

func (r *tdfReader) valueOf(typ, nested byte) (tdfValue, error) {
	v := tdfValue{Type: typ}
	switch typ {
	case tdfInt:
		n, err := r.varint()
		v.Int = n
		return v, err
	case tdfFloat:
		if r.pos+4 > len(r.b) {
			return v, errTDF
		}
		v.Float = math.Float32frombits(binary.BigEndian.Uint32(r.b[r.pos:]))
		r.pos += 4
		return v, nil
	case tdfString, tdfBlob:
		n, err := r.varint()
		if err != nil || n < 0 || r.pos+int(n) > len(r.b) {
			return v, errTDF
		}
		data := r.b[r.pos : r.pos+int(n)]
		r.pos += int(n)
		if typ == tdfString {
			if n == 0 || data[n-1] != 0 {
				return v, errTDF
			}
			v.Str = string(data[:n-1])
		} else {
			v.Blob = data
		}
		return v, nil
	case tdfStruct:
		r.depth++
		if r.depth > 16 {
			return v, errTDF
		}
		m, err := r.members(true)
		r.depth--
		v.Members = m
		return v, err
	case tdfList:
		if r.pos >= len(r.b) {
			return v, errTDF
		}
		et := r.b[r.pos]
		r.pos++
		n, err := r.varint()
		if err != nil || n < 0 || n > 4096 {
			return v, errTDF
		}
		for i := int64(0); i < n; i++ {
			start := r.pos
			e, err := r.element(et, nested)
			if err != nil {
				return v, err
			}
			e.Raw = r.b[start:r.pos]
			v.List = append(v.List, e)
		}
		return v, nil
	case tdfUnion:
		// Active member index (0x7f = none), then that member under its own tag.
		if r.pos >= len(r.b) {
			return v, errTDF
		}
		v.Int = int64(r.b[r.pos])
		r.pos++
		if v.Int == 0x7f {
			return v, nil
		}
		r.depth++
		if r.depth > 16 || r.pos+4 > len(r.b) {
			return v, errTDF
		}
		name := tagName([3]byte{r.b[r.pos], r.b[r.pos+1], r.b[r.pos+2]})
		typ := r.b[r.pos+3]
		start := r.pos
		r.pos += 4
		m, err := r.valueOf(typ, nestedKinds[name])
		r.depth--
		m.Raw = r.b[start:r.pos]
		v.Members = map[string]tdfValue{name: m}
		return v, err
	case tdfVariable, tdfGeneric:
		// Presence byte; if set, the TDF id then a struct body.
		if r.pos >= len(r.b) {
			return v, errTDF
		}
		present := r.b[r.pos]
		r.pos++
		if present == 0 {
			return v, nil
		}
		id, err := r.varint()
		if err != nil {
			return v, err
		}
		v.Int = id
		return r.value(tdfStruct)
	case tdfMap:
		if r.pos+2 > len(r.b) {
			return v, errTDF
		}
		kt, vt := r.b[r.pos], r.b[r.pos+1]
		r.pos += 2
		n, err := r.varint()
		if err != nil || n < 0 || n > 4096 {
			return v, errTDF
		}
		for i := int64(0); i < n; i++ {
			k, err := r.value(kt)
			if err != nil {
				return v, err
			}
			val, err := r.element(vt, nested)
			if err != nil {
				return v, err
			}
			v.List = append(v.List, k, val)
		}
		return v, nil
	}
	return v, fmt.Errorf("%w: unsupported wire type %d", errTDF, typ)
}

// members decodes a member list; inStruct stops at the 0x00 struct terminator.
func (r *tdfReader) members(inStruct bool) (map[string]tdfValue, error) {
	out := map[string]tdfValue{}
	for r.pos < len(r.b) {
		if inStruct && r.b[r.pos] == 0 {
			r.pos++
			return out, nil
		}
		start := r.pos
		if r.pos+4 > len(r.b) {
			return out, errTDF
		}
		name := tagName([3]byte{r.b[r.pos], r.b[r.pos+1], r.b[r.pos+2]})
		typ := r.b[r.pos+3]
		r.pos += 4
		v, err := r.valueOf(typ, nestedKinds[name])
		if err != nil {
			return out, err
		}
		v.Raw = r.b[start:r.pos]
		out[name] = v
	}
	if inStruct {
		return out, errTDF
	}
	return out, nil
}

func decodeTDF(b []byte) (map[string]tdfValue, error) {
	r := &tdfReader{b: b}
	return r.members(false)
}
