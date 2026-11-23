// Command grind searches for the two P-256 rejection inputs pinned by VC-P256.
//
//	grind seed <prefixHex> <label> <seconds> <workers>
//	    ikm = prefix (56 bytes) || uint64be(counter); finds the smallest counter
//	    whose HKDF-SHA-256(ikm, salt "", info label, L 32) is >= n (KEYS §1.4.3).
//	grind path <hmacKeyHex> <prefix> <seconds> <workers>
//	    identifier = prefix || 16 Crockford base32 digits of counter; finds the
//	    smallest counter whose HMAC-SHA256(key, identifier) is >= n (KEYS §1.8.2).
//
// Workers interleave counters and continue until each has passed the best hit,
// so the reported counter is the smallest hit regardless of thread timing.
// The output is one JSON object. Every checker re-verifies the pinned result;
// this program is needed only to reproduce the search.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"math"
	"os"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

var order, _ = hex.DecodeString("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// hmacState holds SHA-256 states after the ipad and opad blocks of a fixed key.
type hmacState struct{ inner, outer []byte }

func pads(key []byte) hmacState {
	if len(key) > 64 {
		panic("key longer than one block")
	}
	block := make([]byte, 64)
	copy(block, key)
	state := func(pad byte) []byte {
		h := sha256.New()
		x := make([]byte, 64)
		for i := range block {
			x[i] = block[i] ^ pad
		}
		h.Write(x)
		s, err := h.(encoding.BinaryMarshaler).MarshalBinary()
		if err != nil {
			panic(err)
		}
		return s
	}
	return hmacState{state(0x36), state(0x5c)}
}

func (s hmacState) sum(h hash.Hash, msg []byte, out []byte) []byte {
	if err := h.(encoding.BinaryUnmarshaler).UnmarshalBinary(s.inner); err != nil {
		panic(err)
	}
	h.Write(msg)
	inner := h.Sum(out[:0])
	if err := h.(encoding.BinaryUnmarshaler).UnmarshalBinary(s.outer); err != nil {
		panic(err)
	}
	h.Write(inner)
	return h.Sum(out[:0])
}

// expand is HMAC-SHA256(prk, info) for a per-try key, without allocation.
func expand(h hash.Hash, prk [32]byte, info []byte, out []byte) []byte {
	var ipad, opad [64]byte
	for i := 0; i < 64; i++ {
		var k byte
		if i < 32 {
			k = prk[i]
		}
		ipad[i], opad[i] = k^0x36, k^0x5c
	}
	h.Reset()
	h.Write(ipad[:])
	h.Write(info)
	inner := h.Sum(out[:0])
	h.Reset()
	h.Write(opad[:])
	h.Write(inner)
	return h.Sum(out[:0])
}

func crockford16(dst []byte, c uint64) []byte {
	var digits [16]byte
	for i := 15; i >= 0; i-- {
		digits[i] = crockford[c&31]
		c >>= 5
	}
	return append(dst, digits[:]...)
}

func main() {
	if len(os.Args) != 6 || (os.Args[1] != "seed" && os.Args[1] != "path") {
		fmt.Fprintln(os.Stderr, "usage: grind seed <prefixHex> <label> <seconds> <workers> | grind path <hmacKeyHex> <prefix> <seconds> <workers>")
		os.Exit(2)
	}
	mode := os.Args[1]
	seconds, err1 := strconv.Atoi(os.Args[4])
	workers, err2 := strconv.Atoi(os.Args[5])
	if err1 != nil || err2 != nil || seconds < 1 || workers < 1 || workers > 4 {
		fmt.Fprintln(os.Stderr, "seconds must be positive and workers in 1..4")
		os.Exit(2)
	}
	var try func(h hash.Hash, c uint64, buf, out []byte) ([]byte, []byte)
	switch mode {
	case "seed":
		prefix, err := hex.DecodeString(os.Args[2])
		if err != nil || len(prefix) != 56 {
			fmt.Fprintln(os.Stderr, "seed prefix must be 56 bytes of hex")
			os.Exit(2)
		}
		extract := pads(nil) // HKDF salt "" is the HMAC key
		info := append([]byte(os.Args[3]), 1)
		try = func(h hash.Hash, c uint64, buf, out []byte) ([]byte, []byte) {
			ikm := binary.BigEndian.AppendUint64(append(buf[:0], prefix...), c)
			var prk [32]byte
			copy(prk[:], extract.sum(h, ikm, out))
			return ikm, expand(h, prk, info, out)
		}
	case "path":
		key, err := hex.DecodeString(os.Args[2])
		if err != nil || len(key) != 33 {
			fmt.Fprintln(os.Stderr, "HMAC key must be a 33-byte compressed point in hex")
			os.Exit(2)
		}
		state := pads(key)
		prefix := []byte(os.Args[3])
		try = func(h hash.Hash, c uint64, buf, out []byte) ([]byte, []byte) {
			id := crockford16(append(buf[:0], prefix...), c)
			return id, state.sum(h, id, out)
		}
	}
	runtime.GOMAXPROCS(workers)
	var best atomic.Uint64
	best.Store(math.MaxUint64)
	var tries atomic.Uint64
	var timedOut atomic.Bool
	deadline := time.Now().Add(time.Duration(seconds) * time.Second)
	start := time.Now()
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w uint64) {
			defer wg.Done()
			h := sha256.New()
			buf := make([]byte, 0, 256)
			out := make([]byte, 0, 32)
			var n uint64
			for c := w; c < best.Load(); c += uint64(workers) {
				if _, v := try(h, c, buf, out); bytes.Compare(v, order) >= 0 {
					for {
						cur := best.Load()
						if c >= cur || best.CompareAndSwap(cur, c) {
							break
						}
					}
					break
				}
				if n++; n&0xffff == 0 {
					tries.Add(0x10000)
					if time.Now().After(deadline) {
						timedOut.Store(true)
						return
					}
				}
			}
			tries.Add(n & 0xffff)
		}(uint64(w))
	}
	wg.Wait()
	elapsed := time.Since(start).Seconds()
	result := map[string]any{"mode": mode, "workers": workers, "seconds": math.Round(elapsed*10) / 10, "tries": tries.Load()}
	if c := best.Load(); c != math.MaxUint64 {
		value, v := try(sha256.New(), c, make([]byte, 0, 256), make([]byte, 0, 32))
		result["found"], result["counter"], result["output"], result["smallest"] = true, c, hex.EncodeToString(v), !timedOut.Load()
		if mode == "seed" {
			result["ikm"] = hex.EncodeToString(value)
		} else {
			result["identifier"] = string(value)
		}
	} else {
		result["found"] = false
	}
	encoded, _ := json.Marshal(result)
	fmt.Println(string(encoded))
}
