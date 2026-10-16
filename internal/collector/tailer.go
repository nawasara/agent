package collector

import (
	"bufio"
	"errors"
	"io"
	"log"
	"os"
	"time"
)

// errNotRegular: the path is a directory or device, never something to tail.
var errNotRegular = errors.New("not a regular file")

// Tailer reads new lines appended to a log file (like `tail -F`).
// Seeks to end of file on open, emits new lines via Out channel.
// Handles log rotation: when the file is renamed/truncated, reopens it.
type Tailer struct {
	Path   string
	Out    chan<- Line
	stopCh chan struct{}
}

func NewTailer(path string, out chan<- Line) *Tailer {
	return &Tailer{Path: path, Out: out, stopCh: make(chan struct{})}
}

func (t *Tailer) Start() {
	go t.run()
}

func (t *Tailer) Stop() {
	close(t.stopCh)
}

func (t *Tailer) run() {
	for {
		select {
		case <-t.stopCh:
			return
		default:
		}

		f, err := t.openAndSeek()
		if err != nil {
			select {
			case <-t.stopCh:
				return
			case <-time.After(5 * time.Second):
				continue
			}
		}

		failed := t.readLoop(f)
		f.Close()

		// A read error (not EOF/rotation) reopens immediately otherwise, and a
		// path that always fails turns into a busy loop that floods the log.
		if failed {
			select {
			case <-t.stopCh:
				return
			case <-time.After(5 * time.Second):
			}
		}
	}
}

// openAndSeek opens the file and seeks to the end so we only tail new lines.
func (t *Tailer) openAndSeek() (*os.File, error) {
	f, err := os.Open(t.Path)
	if err != nil {
		return nil, err
	}
	if info, err := f.Stat(); err == nil && !info.Mode().IsRegular() {
		f.Close()
		return nil, errNotRegular
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		f.Close()
		log.Printf("tailer: seek error %s: %v", t.Path, err)
		return nil, err
	}
	return f, nil
}

// readLoop reads lines until EOF/error then returns so the outer loop can
// reopen the file (handles log rotation where the file is replaced). It reports
// true when it stopped on a real read error, so the caller can back off.
func (t *Tailer) readLoop(f *os.File) bool {
	reader := bufio.NewReader(f)
	for {
		select {
		case <-t.stopCh:
			return false
		default:
		}

		line, err := reader.ReadString('\n')
		if len(line) > 0 {
			select {
			case t.Out <- Line{Text: line, Source: t.Path}:
			case <-t.stopCh:
				return false
			default:
				// Channel full — drop line (non-blocking)
			}
		}
		if err != nil {
			if err != io.EOF {
				log.Printf("tailer: read error %s: %v", t.Path, err)
				return true
			}
			// EOF: check if file was rotated (new inode or truncated)
			if t.wasRotated(f) {
				return false // outer loop will reopen
			}
			select {
			case <-t.stopCh:
				return false
			case <-time.After(200 * time.Millisecond):
			}
		}
	}
}

// wasRotated returns true if the open file handle points to a different
// inode than the path on disk (file was renamed/replaced by logrotate).
func (t *Tailer) wasRotated(f *os.File) bool {
	fi1, err := f.Stat()
	if err != nil {
		return true
	}
	fi2, err := os.Stat(t.Path)
	if err != nil {
		return false // file temporarily gone, keep waiting
	}
	return !os.SameFile(fi1, fi2)
}
