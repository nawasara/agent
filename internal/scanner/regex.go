package scanner

import (
	"regexp"
	"sync"
)

// fastRe wraps a compiled regexp.  The cache avoids recompiling the same
// pattern for every file when the signature DB is reloaded.
type fastRe struct {
	re *regexp.Regexp
}

func (f *fastRe) Match(data []byte) bool {
	return f.re.Match(data)
}

var (
	reCacheMu sync.RWMutex
	reCache   = map[string]*fastRe{}
)

func compileRe(pattern string) *fastRe {
	reCacheMu.RLock()
	if f, ok := reCache[pattern]; ok {
		reCacheMu.RUnlock()
		return f
	}
	reCacheMu.RUnlock()

	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}
	f := &fastRe{re: re}
	reCacheMu.Lock()
	reCache[pattern] = f
	reCacheMu.Unlock()
	return f
}
