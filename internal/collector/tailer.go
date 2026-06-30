package collector

import (
	"bufio"
	"io"
	"log"
	"os"
	"time"
)

// Tailer reads new lines appended to a log file (like `tail -F`).
// Seeks to end of file on open, emits new lines via Out channel.
type Tailer struct {
	Path   string
	Out    chan<- string
	stopCh chan struct{}
}

func NewTailer(path string, out chan<- string) *Tailer {
	return &Tailer{Path: path, Out: out, stopCh: make(chan struct{})}
}

func (t *Tailer) Start() {
	go t.run()
}

func (t *Tailer) Stop() {
	close(t.stopCh)
}

func (t *Tailer) run() {
	var f *os.File
	var err error

	for {
		f, err = os.Open(t.Path)
		if err != nil {
			select {
			case <-t.stopCh:
				return
			case <-time.After(5 * time.Second):
				continue
			}
		}
		break
	}
	defer f.Close()

	// Seek to end so we only read new lines
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		log.Printf("tailer: seek error %s: %v", t.Path, err)
		return
	}

	reader := bufio.NewReader(f)
	for {
		select {
		case <-t.stopCh:
			return
		default:
		}

		line, err := reader.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				log.Printf("tailer: read error %s: %v", t.Path, err)
			}
			time.Sleep(200 * time.Millisecond)
			continue
		}
		if line != "" {
			select {
			case t.Out <- line:
			case <-t.stopCh:
				return
			default:
				// Channel full — drop oldest by skipping (non-blocking send)
			}
		}
	}
}
