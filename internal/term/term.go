// Package term drives the terminal with the standard library only: raw
// mode, the alternate screen, key decoding and resize notifications.
package term

import (
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// Event is a key press or a resize.
type Event struct {
	Key    Key
	Resize bool
}

// Key is a decoded key press. Name is set for special keys ("up", "enter",
// "esc", "ctrl+c", ...); Rune for printable characters.
type Key struct {
	Name string
	Rune rune
}

// String returns the key as matched by the UI: the name, or the rune.
func (k Key) String() string {
	if k.Name != "" {
		return k.Name
	}
	return string(k.Rune)
}

// Terminal is the controlling terminal in raw mode.
type Terminal struct {
	in, out *os.File
	saved   syscall.Termios
	Events  chan Event

	mu     sync.Mutex // held while reading; Suspend takes it to stop reads
	paused bool
	stop   chan struct{}
}

func ioctl(fd uintptr, req uintptr, arg unsafe.Pointer) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, req, uintptr(arg))
	if errno != 0 {
		return errno
	}
	return nil
}

// IsTerminal reports whether f is a terminal.
func IsTerminal(f *os.File) bool {
	var t syscall.Termios
	return ioctl(f.Fd(), syscall.TCGETS, unsafe.Pointer(&t)) == nil
}

// Open puts the terminal in raw mode on the alternate screen.
func Open(in, out *os.File) (*Terminal, error) {
	t := &Terminal{in: in, out: out, Events: make(chan Event, 64), stop: make(chan struct{})}
	if err := ioctl(in.Fd(), syscall.TCGETS, unsafe.Pointer(&t.saved)); err != nil {
		return nil, err
	}
	if err := t.raw(); err != nil {
		return nil, err
	}
	t.enter()
	go t.readLoop()
	winch := make(chan os.Signal, 1)
	signal.Notify(winch, syscall.SIGWINCH)
	go func() {
		for {
			select {
			case <-winch:
				t.Events <- Event{Resize: true}
			case <-t.stop:
				signal.Stop(winch)
				return
			}
		}
	}()
	return t, nil
}

func (t *Terminal) raw() error {
	r := t.saved
	r.Iflag &^= syscall.IGNBRK | syscall.BRKINT | syscall.PARMRK | syscall.ISTRIP | syscall.INLCR | syscall.IGNCR | syscall.ICRNL | syscall.IXON
	r.Lflag &^= syscall.ECHO | syscall.ECHONL | syscall.ICANON | syscall.ISIG | syscall.IEXTEN
	r.Cflag &^= syscall.CSIZE | syscall.PARENB
	r.Cflag |= syscall.CS8
	// Reads return after 100ms with no input, so the reader can be paused.
	r.Cc[syscall.VMIN] = 0
	r.Cc[syscall.VTIME] = 1
	return ioctl(t.in.Fd(), syscall.TCSETS, unsafe.Pointer(&r))
}

func (t *Terminal) enter() {
	t.out.WriteString("\x1b[?1049h\x1b[?25l\x1b[H\x1b[2J")
}

func (t *Terminal) leave() {
	t.out.WriteString("\x1b[0m\x1b[?25h\x1b[?1049l")
}

// Close restores the terminal.
func (t *Terminal) Close() {
	close(t.stop)
	t.mu.Lock()
	t.paused = true
	t.leave()
	_ = ioctl(t.in.Fd(), syscall.TCSETS, unsafe.Pointer(&t.saved))
	t.mu.Unlock()
}

// Suspend restores the normal terminal so another program (sudo) can use
// it. Call Resume afterwards.
func (t *Terminal) Suspend() {
	t.mu.Lock()
	t.paused = true
	t.leave()
	_ = ioctl(t.in.Fd(), syscall.TCSETS, unsafe.Pointer(&t.saved))
	t.mu.Unlock()
}

// Resume re-enters raw mode after Suspend.
func (t *Terminal) Resume() {
	t.mu.Lock()
	_ = t.raw()
	t.enter()
	t.paused = false
	t.mu.Unlock()
	t.Events <- Event{Resize: true} // forces a full redraw
}

// Size returns the terminal's columns and rows.
func (t *Terminal) Size() (int, int) {
	var ws struct{ Row, Col, X, Y uint16 }
	if err := ioctl(t.out.Fd(), syscall.TIOCGWINSZ, unsafe.Pointer(&ws)); err != nil || ws.Col == 0 {
		return 80, 24
	}
	return int(ws.Col), int(ws.Row)
}

// Write writes to the terminal.
func (t *Terminal) Write(p []byte) (int, error) { return t.out.Write(p) }

func (t *Terminal) readLoop() {
	buf := make([]byte, 256)
	for {
		select {
		case <-t.stop:
			return
		default:
		}
		t.mu.Lock()
		if t.paused {
			t.mu.Unlock()
			time.Sleep(50 * time.Millisecond)
			continue
		}
		n, err := syscall.Read(int(t.in.Fd()), buf)
		t.mu.Unlock()
		if err != nil && err != syscall.EINTR && err != syscall.EAGAIN {
			return
		}
		if n <= 0 {
			continue
		}
		for _, k := range Decode(buf[:n]) {
			t.Events <- Event{Key: k}
		}
	}
}

var csi = map[string]string{
	"A": "up", "B": "down", "C": "right", "D": "left", "H": "home", "F": "end",
	"5~": "pgup", "6~": "pgdn", "1~": "home", "4~": "end", "7~": "home", "8~": "end", "3~": "delete",
	"Z": "shift+tab",
}

// Decode splits raw input into keys.
func Decode(b []byte) []Key {
	var keys []Key
	for len(b) > 0 {
		c := b[0]
		switch {
		case c == 0x1b:
			if len(b) == 1 {
				keys = append(keys, Key{Name: "esc"})
				b = b[1:]
				continue
			}
			if b[1] == '[' || b[1] == 'O' {
				// CSI/SS3: parameters then a final byte in 0x40–0x7e.
				i := 2
				for i < len(b) && (b[i] < 0x40 || b[i] > 0x7e) {
					i++
				}
				if i < len(b) {
					seq := string(b[2 : i+1])
					if name, ok := csi[seq]; ok {
						keys = append(keys, Key{Name: name})
					}
					b = b[i+1:]
					continue
				}
				b = b[len(b):]
				continue
			}
			// Alt+key: report as esc then the key; good enough here.
			keys = append(keys, Key{Name: "esc"})
			b = b[1:]
		case c == '\r' || c == '\n':
			keys = append(keys, Key{Name: "enter"})
			b = b[1:]
		case c == '\t':
			keys = append(keys, Key{Name: "tab"})
			b = b[1:]
		case c == 0x7f || c == 0x08:
			keys = append(keys, Key{Name: "backspace"})
			b = b[1:]
		case c == 0x03:
			keys = append(keys, Key{Name: "ctrl+c"})
			b = b[1:]
		case c == 0x0c:
			keys = append(keys, Key{Name: "ctrl+l"})
			b = b[1:]
		case c < 0x20:
			b = b[1:]
		default:
			r, size := decodeRune(b)
			keys = append(keys, Key{Rune: r})
			b = b[size:]
		}
	}
	return keys
}

func decodeRune(b []byte) (rune, int) {
	s := string(b)
	for _, r := range s {
		return r, len(string(r))
	}
	return 0, 1
}
