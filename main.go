// Lampa Downloader — agent (headless core).
// Holds an outbound WSS to the relay, receives E2E-encrypted jobs, and
// forwards the magnet links to a Transmission daemon via its JSON-RPC.
// No payload is ever downloaded locally and no home IP ever leaves.
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/nacl/box"
)

// ---------- config ----------

type Config struct {
	Priv string `json:"priv"` // base64 X25519 private
	Pub  string `json:"pub"`  // base64 X25519 public
	// DownloadDir       string       `json:"download_dir"`         // legacy; unused
	// TorrentDir        string       `json:"torrent_dir"`          // legacy; unused
	// KeepSeeding       bool         `json:"keep_seeding"`         // legacy; unused
	// Autostart         bool         `json:"autostart"`            // launch with the OS
	// KeepFilesOnCancel bool         `json:"keep_files_on_cancel"` // legacy; unused
	TransmissionURL  string       `json:"transmission_url"`  // e.g. "http://192.168.1.50:9091/transmission/rpc"
	TransmissionUser string       `json:"transmission_user"` // optional basic-auth user
	TransmissionPass string       `json:"transmission_pass"` // optional basic-auth password
	Trusted          []string     `json:"trusted,omitempty"` // LEGACY (<= v1.0.6)
	Devices          []Device     `json:"devices"`
	Pending          []PendingJob `json:"pending"`
	History          []HistEntry  `json:"history"`
}

// Device is a paired plugin (a TV). Pub is the trust anchor; Name is only for
// the panel. LastSeen updates when a job/command arrives from this key.
type Device struct {
	Pub      string `json:"pub"`
	Name     string `json:"name"`
	AddedAt  int64  `json:"added_at"`
	LastSeen int64  `json:"last_seen"`
}

// HistEntry is one completed hand-off to Transmission, persisted so the list
// survives restarts.
type HistEntry struct {
	Name string `json:"name"`
	// Dir  string `json:"dir"`  // category label (informational)
	MiB  int64 `json:"mib"`  // unused (0)
	Done int64 `json:"done"` // unix seconds of completion
}

const historyCap = 50

// PendingJob is persisted so an interrupted hand-off retries after a restart.
type PendingJob struct {
	ID     string `json:"id,omitempty"`
	Magnet string `json:"magnet"`
	// Dir    string `json:"dir"`
	Name string `json:"name"`
}

var (
	hex40Re = regexp.MustCompile(`^[0-9A-Fa-f]{40}$`)
	b32Re   = regexp.MustCompile(`^[A-Za-z2-7]{32}$`)
	btihRe  = regexp.MustCompile(`btih:([0-9A-Fa-f]{40}|[A-Za-z2-7]{32})`)
)

func osExit() { time.Sleep(150 * time.Millisecond); os.Exit(0) }

func validMagnet(s string) bool {
	if !strings.HasPrefix(s, "magnet:?") {
		return false
	}
	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	for _, xt := range u.Query()["xt"] {
		if h, ok := strings.CutPrefix(xt, "urn:btih:"); ok {
			if hex40Re.MatchString(h) || b32Re.MatchString(h) {
				return true
			}
		}
	}
	return false
}

func infoHash(magnet string) string {
	m := btihRe.FindStringSubmatch(magnet)
	if m == nil {
		return ""
	}
	h := m[1]
	if len(h) == 40 {
		return strings.ToLower(h)
	}
	raw, err := base32.StdEncoding.DecodeString(strings.ToUpper(h))
	if err != nil || len(raw) != 20 {
		return ""
	}
	return hex.EncodeToString(raw)
}

func deriveCode(pub []byte) string {
	h := sha256.Sum256(pub)
	return fmt.Sprintf("%06d", binary.BigEndian.Uint32(h[:4])%1000000)
}

// rotWriter is a tiny size-rotating log file writer (keeps one previous file).
type rotWriter struct {
	mu    sync.Mutex
	path  string
	f     *os.File
	size  int64
	limit int64
}

func newRotWriter(path string, limit int64) *rotWriter {
	w := &rotWriter{path: path, limit: limit}
	w.open()
	return w
}
func (w *rotWriter) open() {
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return
	}
	w.f = f
	if st, e := f.Stat(); e == nil {
		w.size = st.Size()
	}
}
func (w *rotWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return len(p), nil
	}
	if w.size+int64(len(p)) > w.limit {
		w.f.Close()
		os.Rename(w.path, w.path+".1")
		w.open()
		w.size = 0
	}
	n, err := w.f.Write(p)
	w.size += int64(n)
	return n, err
}

func setupLogging(cfgPath string) string {
	logPath := filepath.Join(filepath.Dir(cfgPath), "agent.log")
	rw := newRotWriter(logPath, 2<<20)
	log.SetOutput(io.MultiWriter(os.Stderr, rw))
	return logPath
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// func loopbackBind(addr string) bool {
// 	host, _, err := net.SplitHostPort(addr)
// 	if err != nil {
// 		return false
// 	}
// 	return host == "" || host == "127.0.0.1" || host == "localhost" || host == "::1"
// }

func randID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func unb64(s string) []byte {
	d, _ := base64.StdEncoding.DecodeString(s)
	return d
}

// var unsafeFileChars = regexp.MustCompile(`[<>:"/\\|?*\x00-\x1f]`)

// func sanitizeFilename(s string) string {
// 	s = strings.TrimSpace(s)
// 	s = unsafeFileChars.ReplaceAllString(s, "_")
// 	if r := []rune(s); len(r) > 120 {
// 		s = string(r[:120])
// 	}
// 	return strings.Trim(s, " .")
// }

// var categoryDir = map[string]string{
// 	"movies": "Movies",
// 	"shows":  "Shows",
// }

// ---------- agent ----------

type Job struct {
	id     string
	name   string
	magnet string
	// dir    string
	state string // connecting|done|error
	err   string
	pct   int

	cancelled bool
	cancelCh  chan struct{}
	doneCh    chan struct{}
}

type Agent struct {
	cfgPath string
	cfg     Config
	priv    *[32]byte
	pub     *[32]byte
	code    string

	mu       sync.Mutex
	jobs     map[string]*Job
	saveMu   sync.Mutex
	cfgSeq   uint64
	savedSeq uint64
	devices  map[string]*Device

	pairUntil time.Time
	pairLeft  int

	seenNonces map[string]int64
	conn       *websocket.Conn
	relayUp    bool
	// uiToken    string
	// uiPort     string
	logPath string
	started time.Time

	outCh chan map[string]any
}

// ---------- manual add (panel) ----------

// func magnetDisplayName(m string) string {
// 	u, err := url.Parse(m)
// 	if err != nil {
// 		return "Загрузка"
// 	}
// 	dn := strings.TrimSpace(u.Query().Get("dn"))
// 	if dn == "" {
// 		return "Загрузка"
// 	}
// 	if r := []rune(dn); len(r) > 120 {
// 		dn = string(r[:120]) + "…"
// 	}
// 	return dn
// }

// func buildMagnet(hashHex, name string, trackers []string) string {
// 	m := "magnet:?xt=urn:btih:" + hashHex
// 	if name != "" {
// 		m += "&dn=" + url.QueryEscape(name)
// 	}
// 	for _, tr := range trackers {
// 		if tr != "" {
// 			m += "&tr=" + url.QueryEscape(tr)
// 		}
// 	}
// 	return m
// }

// func (a *Agent) addManual(magnet, cat string) (string, error) {
// 	magnet = strings.TrimSpace(magnet)
// 	if !validMagnet(magnet) {
// 		return "", fmt.Errorf("некорректная magnet-ссылка")
// 	}
// 	name := magnetDisplayName(magnet)
// 	return name, a.launchManual(magnet, cat, name)
// }

// func (a *Agent) addTorrentFile(data []byte, cat string) (string, error) {
// 	// The .torrent upload path is no longer supported in Transmission-only
// 	// mode; the panel should send a magnet instead. Kept as a stub so the
// 	// panel's existing handler still links.
// 	_ = data
// 	_ = cat
// 	return "", fmt.Errorf(".torrent upload not supported; use a magnet link")
// }

// func (a *Agent) launchManual(magnet, cat, name string) error {
// 	dir, ok := categoryDir[cat]
// 	if !ok {
// 		dir = "Other"
// 	}
// 	ih := infoHash(magnet)
// 	a.mu.Lock()
// 	for _, ex := range a.jobs {
// 		if ih != "" && ex.state != "error" && infoHash(ex.magnet) == ih {
// 			a.mu.Unlock()
// 			return fmt.Errorf("этот торрент уже в обработке: %s", ex.name)
// 		}
// 	}
// 	a.mu.Unlock()
// 	log.Printf("manual add: %q -> %s", name, dir)
// 	go a.startDownload(randID(), magnet, dir, name)
// 	return nil
// }

func validKeys(c *Config) bool {
	return len(unb64(c.Priv)) == 32 && len(unb64(c.Pub)) == 32
}

func normalizeConfig(c *Config) {
	for _, k := range c.Trusted {
		dup := false
		for _, d := range c.Devices {
			if d.Pub == k {
				dup = true
				break
			}
		}
		if !dup && len(unb64(k)) == 32 {
			c.Devices = append(c.Devices, Device{
				Pub: k, Name: defaultDevName(k), AddedAt: time.Now().Unix(),
			})
		}
	}
	c.Trusted = nil
	// if c.DownloadDir == "" {
	// 	home, _ := os.UserHomeDir()
	// 	c.DownloadDir = filepath.Join(home, "Downloads", "Lampa")
	// }
	// if c.TorrentDir == "" {
	// 	home, _ := os.UserHomeDir()
	// 	c.TorrentDir = filepath.Join(home, "Downloads", "Lampa", "Torrents")
	// }
	if c.TransmissionURL == "" {
		c.TransmissionURL = "http://127.0.0.1:9091/transmission/rpc"
	}
	if len(c.History) > historyCap {
		c.History = c.History[len(c.History)-historyCap:]
	}
}

func defaultDevName(pubB string) string {
	p := unb64(pubB)
	if len(p) != 32 {
		return "ТВ"
	}
	return "ТВ " + deriveCode(p)[:4]
}

func loadOrInitConfig(path string) (Config, error) {
	var c Config
	b, err := os.ReadFile(path)
	if err == nil {
		if jerr := json.Unmarshal(b, &c); jerr == nil && validKeys(&c) {
			normalizeConfig(&c)
			return c, nil
		}
		bak := path + ".broken-" + time.Now().Format("20060102-150405")
		if werr := os.WriteFile(bak, b, 0600); werr == nil {
			log.Printf("config unreadable, backed up to %s and re-initialized", bak)
		} else {
			log.Printf("config unreadable and backup failed (%v); re-initializing", werr)
		}
		c = Config{}
	}
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return c, err
	}
	c.Priv = b64(priv[:])
	c.Pub = b64(pub[:])
	// home, _ := os.UserHomeDir()
	// c.DownloadDir = filepath.Join(home, "Downloads", "Lampa")
	// c.TorrentDir = filepath.Join(home, "Downloads", "Lampa", "Torrents")
	c.TransmissionURL = "http://127.0.0.1:9091/transmission/rpc"
	// c.KeepSeeding = false
	// c.Autostart = true
	// c.KeepFilesOnCancel = false

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return c, err
	}
	b, err = json.MarshalIndent(c, "", "  ")
	if err != nil {
		return c, err
	}
	if err := writeFileAtomic(path, b); err != nil {
		return c, fmt.Errorf("config save: %w", err)
	}
	return c, nil
}

func writeFileAtomic(path string, b []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

func (a *Agent) saveConfig() {
	a.mu.Lock()
	a.cfg.Devices = a.cfg.Devices[:0]
	for _, d := range a.devices {
		a.cfg.Devices = append(a.cfg.Devices, *d)
	}
	sort.Slice(a.cfg.Devices, func(i, j int) bool {
		if a.cfg.Devices[i].AddedAt != a.cfg.Devices[j].AddedAt {
			return a.cfg.Devices[i].AddedAt < a.cfg.Devices[j].AddedAt
		}
		return a.cfg.Devices[i].Pub < a.cfg.Devices[j].Pub
	})
	b, merr := json.MarshalIndent(a.cfg, "", "  ")
	a.cfgSeq++
	seq := a.cfgSeq
	a.mu.Unlock()
	if merr != nil {
		log.Printf("config save: %v", merr)
		return
	}
	a.saveMu.Lock()
	defer a.saveMu.Unlock()
	if seq <= a.savedSeq {
		return
	}
	if err := writeFileAtomic(a.cfgPath, b); err != nil {
		log.Printf("config save: %v", err)
		return
	}
	a.savedSeq = seq
}

func (a *Agent) addPending(id, magnet /*dir,*/, name string) {
	a.mu.Lock()
	for _, p := range a.cfg.Pending {
		if p.Magnet == magnet {
			a.mu.Unlock()
			return
		}
	}
	a.cfg.Pending = append(a.cfg.Pending, PendingJob{ID: id, Magnet: magnet /*Dir: dir,*/, Name: name})
	a.mu.Unlock()
	a.saveConfig()
}

func (a *Agent) removePending(magnet string) {
	a.mu.Lock()
	out := a.cfg.Pending[:0]
	for _, p := range a.cfg.Pending {
		if p.Magnet != magnet {
			out = append(out, p)
		}
	}
	a.cfg.Pending = out
	a.mu.Unlock()
	a.saveConfig()
}

func (a *Agent) send(m map[string]any) {
	select {
	case a.outCh <- m:
	default:
	}
}

// ---------- relay connection ----------

func (a *Agent) connectLoop(wsURL string) {
	backoff := time.Second
	for {
		conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
		if err != nil {
			log.Printf("relay dial failed: %v (retry in %s)", err, backoff)
			time.Sleep(backoff)
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		log.Printf("relay connected: %s", wsURL)
		backoff = time.Second
		a.mu.Lock()
		a.relayUp = true
		a.conn = conn
		a.mu.Unlock()
		a.handleConn(conn)
		a.mu.Lock()
		a.relayUp = false
		a.conn = nil
		a.mu.Unlock()
		log.Printf("relay disconnected, reconnecting")
	}
}

func (a *Agent) handleConn(conn *websocket.Conn) {
	defer conn.Close()
	done := make(chan struct{})

	a.mu.Lock()
	helloPub, helloCode := a.cfg.Pub, a.code
	a.mu.Unlock()
	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err := conn.WriteJSON(map[string]any{"type": "hello", "pub": helloPub, "id": helloCode}); err != nil {
		return
	}

	go func() {
		ping := time.NewTicker(25 * time.Second)
		defer ping.Stop()
		for {
			select {
			case <-done:
				return
			case m := <-a.outCh:
				conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if err := conn.WriteJSON(m); err != nil {
					return
				}
			case <-ping.C:
				conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
					return
				}
			}
		}
	}()

	conn.SetReadDeadline(time.Now().Add(70 * time.Second))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(70 * time.Second))
		return nil
	})

	for {
		var m map[string]any
		if err := conn.ReadJSON(&m); err != nil {
			close(done)
			return
		}
		switch m["type"] {
		case "pair":
			a.onPairRequest(m)
		case "paired":
			a.onPaired(str(m["pub"]))
		case "job":
			a.onJob(m)
		case "cmd":
			a.onCmd(m)
		}
	}
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

const (
	pairWindowDur   = 10 * time.Minute
	pairFirstRunDur = 15 * time.Minute
	pairMaxAccepts  = 5
)

func (a *Agent) openPairWindow(d time.Duration) {
	a.mu.Lock()
	a.pairUntil = time.Now().Add(d)
	a.pairLeft = pairMaxAccepts
	a.mu.Unlock()
	log.Printf("pairing window open for %s (up to %d new devices)", d, pairMaxAccepts)
}

// func (a *Agent) pairWindowLeft() int {
// 	a.mu.Lock()
// 	defer a.mu.Unlock()
// 	if a.pairLeft <= 0 {
// 		return 0
// 	}
// 	left := int(time.Until(a.pairUntil).Seconds())
// 	if left < 0 {
// 		return 0
// 	}
// 	return left
// }

func (a *Agent) acceptPair(pubB string) bool {
	if len(unb64(pubB)) != 32 {
		return false
	}
	now := time.Now()
	a.mu.Lock()
	if d, known := a.devices[pubB]; known {
		d.LastSeen = now.Unix()
		a.mu.Unlock()
		a.saveConfig()
		log.Printf("re-paired with a known device")
		return true
	}
	if now.After(a.pairUntil) || a.pairLeft <= 0 {
		a.mu.Unlock()
		log.Printf("pairing rejected: window closed — press «Разрешить подключение» in the panel")
		return false
	}
	a.pairLeft--
	left := a.pairLeft
	a.devices[pubB] = &Device{Pub: pubB, Name: defaultDevName(pubB), AddedAt: now.Unix(), LastSeen: now.Unix()}
	a.mu.Unlock()
	a.saveConfig()
	log.Printf("paired with a new device (%s), window slots left: %d", defaultDevName(pubB), left)
	return true
}

func (a *Agent) onPairRequest(m map[string]any) {
	pubB := str(m["pub"])
	ok := a.acceptPair(pubB)
	resp := map[string]any{"type": "pair_result", "id": str(m["id"]), "ok": ok}
	if ok {
		if nonceB, ctB, err := a.sealHostname(pubB); err == nil {
			resp["nonce"], resp["ct"] = nonceB, ctB
		}
	}
	a.send(resp)
}

func (a *Agent) sealHostname(pubB string) (nonceB64, ctB64 string, err error) {
	host, _ := os.Hostname()
	host = strings.TrimSpace(host)
	if host == "" {
		host = "ПК"
	}
	if r := []rune(host); len(r) > 40 {
		host = string(r[:40])
	}
	pt, err := json.Marshal(map[string]string{"name": host})
	if err != nil {
		return "", "", err
	}
	peerB := unb64(pubB)
	if len(peerB) != 32 {
		return "", "", fmt.Errorf("bad peer key")
	}
	var peer [32]byte
	copy(peer[:], peerB)
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", "", err
	}
	a.mu.Lock()
	priv := a.priv
	a.mu.Unlock()
	return b64(nonce[:]), b64(box.Seal(nil, pt, &nonce, &peer, priv)), nil
}

func (a *Agent) onPaired(pubB string) {
	a.acceptPair(pubB)
}

func (a *Agent) seenNonce(n string) bool {
	const ttl = 600
	now := time.Now().Unix()
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.seenNonces == nil {
		a.seenNonces = make(map[string]int64)
	}
	if len(a.seenNonces) > 4096 {
		for k, ts := range a.seenNonces {
			if now-ts > ttl {
				delete(a.seenNonces, k)
			}
		}
	}
	if ts, dup := a.seenNonces[n]; dup && now-ts <= ttl {
		return true
	}
	a.seenNonces[n] = now
	return false
}

func freshTS(ts int64) bool {
	if ts == 0 {
		return true
	}
	d := time.Now().Unix() - ts
	if d < 0 {
		d = -d
	}
	return d <= 300
}

func (a *Agent) touchDevice(pubB string) {
	a.mu.Lock()
	d := a.devices[pubB]
	if d != nil {
		d.LastSeen = time.Now().Unix()
	}
	a.mu.Unlock()
	if d != nil {
		a.saveConfig()
	}
}

// func (a *Agent) renameDevice(pubB, name string) error {
// 	name = strings.TrimSpace(name)
// 	if name == "" || len([]rune(name)) > 40 {
// 		return fmt.Errorf("имя: от 1 до 40 символов")
// 	}
// 	a.mu.Lock()
// 	d := a.devices[pubB]
// 	if d != nil {
// 		d.Name = name
// 	}
// 	a.mu.Unlock()
// 	if d == nil {
// 		return fmt.Errorf("устройство не найдено")
// 	}
// 	a.saveConfig()
// 	log.Printf("device renamed to %q", name)
// 	return nil
// }

// func (a *Agent) revokeDevice(pubB string) {
// 	a.mu.Lock()
// 	_, ok := a.devices[pubB]
// 	delete(a.devices, pubB)
// 	a.mu.Unlock()
// 	if ok {
// 		a.saveConfig()
// 		log.Printf("device access revoked")
// 	}
// }

// func (a *Agent) resetKeys() error {
// 	pub, priv, err := box.GenerateKey(rand.Reader)
// 	if err != nil {
// 		return err
// 	}
// 	a.mu.Lock()
// 	a.cfg.Priv, a.cfg.Pub = b64(priv[:]), b64(pub[:])
// 	a.priv, a.pub = priv, pub
// 	a.code = deriveCode(pub[:])
// 	a.devices = make(map[string]*Device)
// 	conn := a.conn
// 	a.mu.Unlock()
// 	a.saveConfig()
// 	if conn != nil {
// 		conn.Close()
// 	}
// 	log.Printf("keys reset: new pairing code, all devices revoked")
// 	return nil
// }

func (a *Agent) onCmd(m map[string]any) {
	pubB := str(m["pub"])
	a.mu.Lock()
	_, trusted := a.devices[pubB]
	priv := a.priv
	a.mu.Unlock()
	if !trusted {
		log.Printf("cmd from untrusted key -> dropped")
		return
	}
	var nonce [24]byte
	nb := unb64(str(m["nonce"]))
	if len(nb) != 24 {
		return
	}
	if a.seenNonce(str(m["nonce"])) {
		log.Printf("replayed nonce -> dropped")
		return
	}
	copy(nonce[:], nb)
	var peer [32]byte
	copy(peer[:], unb64(pubB))

	pt, ok := box.Open(nil, unb64(str(m["ct"])), &nonce, &peer, priv)
	if !ok {
		log.Printf("cmd decrypt failed -> dropped")
		return
	}
	var payload struct {
		Act string `json:"act"`
		ID  string `json:"id"`
		TS  int64  `json:"ts"`
	}
	if err := json.Unmarshal(pt, &payload); err != nil || payload.ID == "" {
		log.Printf("cmd payload parse failed -> dropped")
		return
	}
	if !freshTS(payload.TS) {
		log.Printf("cmd with a stale timestamp -> dropped (replay?)")
		return
	}
	a.touchDevice(pubB)
	switch payload.Act {
	case "pause":
		log.Printf("cmd pause ignored (Transmission owns the download)")
	case "resume":
		log.Printf("cmd resume ignored (Transmission owns the download)")
	case "cancel":
		a.cancelJob(payload.ID)
	default:
		log.Printf("cmd %q unknown -> dropped", payload.Act)
	}
}

func (a *Agent) onJob(m map[string]any) {
	pubB := str(m["pub"])
	a.mu.Lock()
	_, trusted := a.devices[pubB]
	priv := a.priv
	a.mu.Unlock()
	if !trusted {
		log.Printf("job from untrusted key -> dropped")
		return
	}
	var nonce [24]byte
	nb := unb64(str(m["nonce"]))
	if len(nb) != 24 {
		return
	}
	if a.seenNonce(str(m["nonce"])) {
		log.Printf("replayed nonce -> dropped")
		return
	}
	copy(nonce[:], nb)
	var peer [32]byte
	copy(peer[:], unb64(pubB))

	pt, ok := box.Open(nil, unb64(str(m["ct"])), &nonce, &peer, priv)
	if !ok {
		log.Printf("job decrypt failed -> dropped")
		return
	}
	var payload struct {
		Magnet string `json:"magnet"`
		Cat    string `json:"cat"`
		Name   string `json:"name"`
		TS     int64  `json:"ts"`
	}
	if err := json.Unmarshal(pt, &payload); err != nil {
		log.Printf("job payload parse failed -> dropped")
		return
	}
	if !freshTS(payload.TS) {
		log.Printf("job with a stale timestamp -> dropped (replay?)")
		return
	}
	if !validMagnet(payload.Magnet) {
		log.Printf("job magnet rejected (not a magnet URI) -> dropped")
		return
	}
	// dir, ok := categoryDir[payload.Cat]
	// if !ok {
	// 	dir = "Other"
	// }
	a.touchDevice(pubB)
	id := str(m["id"])
	go a.startDownload(id, payload.Magnet /*dir,*/, payload.Name)
}

// ---------- Transmission RPC ----------

// transmissionAdd sends a magnet to the Transmission daemon via its JSON-RPC.
// It first performs the 409 handshake to obtain the X-Transmission-Session-Id.
func (a *Agent) transmissionAdd(magnet string) error {
	if a.cfg.TransmissionURL == "" {
		return fmt.Errorf("transmission_url not configured")
	}
	sid, err := a.transmissionSessionID()
	if err != nil {
		return fmt.Errorf("session handshake: %w", err)
	}

	body := map[string]any{
		"method": "torrent-add",
		"arguments": map[string]any{
			"filename": magnet,
			"paused":   false,
		},
	}
	buf, _ := json.Marshal(body)

	req, err := http.NewRequest("POST", a.cfg.TransmissionURL, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Transmission-Session-Id", sid)
	if a.cfg.TransmissionUser != "" {
		req.SetBasicAuth(a.cfg.TransmissionUser, a.cfg.TransmissionPass)
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("rpc %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}

// transmissionSessionID triggers the 409 handshake and returns the session id.
func (a *Agent) transmissionSessionID() (string, error) {
	req, err := http.NewRequest("POST", a.cfg.TransmissionURL, strings.NewReader(`{"method":"session-get"}`))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if a.cfg.TransmissionUser != "" {
		req.SetBasicAuth(a.cfg.TransmissionUser, a.cfg.TransmissionPass)
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if sid := resp.Header.Get("X-Transmission-Session-Id"); sid != "" {
		return sid, nil
	}
	return "", fmt.Errorf("no X-Transmission-Session-Id header (status %d)", resp.StatusCode)
}

// ---------- job lifecycle ----------

// func (a *Agent) pauseJob(id string) {
// 	log.Printf("pause ignored for job %s (Transmission owns the download)", id)
// }

// func (a *Agent) resumeJob(id string) {
// 	log.Printf("resume ignored for job %s (Transmission owns the download)", id)
// }

func (a *Agent) cancelJob(id string) {
	a.mu.Lock()
	j := a.jobs[id]
	if j == nil {
		a.mu.Unlock()
		return
	}
	delete(a.jobs, id)
	if !j.cancelled {
		j.cancelled = true
		if j.cancelCh != nil {
			close(j.cancelCh)
		}
	}
	magnet := j.magnet
	name := j.name
	a.mu.Unlock()

	if j.doneCh != nil {
		select {
		case <-j.doneCh:
		case <-time.After(3 * time.Second):
			log.Printf("job %s: worker did not exit within 3s, proceeding", id)
		}
	}

	if magnet != "" {
		a.removePending(magnet)
	}
	a.pushStatus()
	log.Printf("job %s cancelled: %q", id, name)
}

// func (j *Job) dirOrEmpty() string {
// 	if j == nil {
// 		return ""
// 	}
// 	return j.dir
// }

// func (a *Agent) setDir(dir string) error {
// 	if dir == "" {
// 		return fmt.Errorf("empty path")
// 	}
// 	a.mu.Lock()
// 	a.cfg.DownloadDir = dir
// 	a.mu.Unlock()
// 	a.saveConfig()
// 	log.Printf("legacy download dir changed: %s", dir)
// 	return nil
// }

// func (a *Agent) setTorrentDir(dir string) error {
// 	if dir == "" {
// 		return fmt.Errorf("empty path")
// 	}
// 	a.mu.Lock()
// 	a.cfg.TorrentDir = dir
// 	a.mu.Unlock()
// 	a.saveConfig()
// 	log.Printf("legacy torrent dir changed: %s", dir)
// 	return nil
// }

// setTransmission updates the Transmission RPC settings.
// func (a *Agent) setTransmission(url, user, pass string) error {
// 	url = strings.TrimSpace(url)
// 	if url == "" {
// 		return fmt.Errorf("transmission_url is empty")
// 	}
// 	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
// 		return fmt.Errorf("transmission_url must start with http:// or https://")
// 	}
// 	a.mu.Lock()
// 	a.cfg.TransmissionURL = url
// 	a.cfg.TransmissionUser = user
// 	a.cfg.TransmissionPass = pass
// 	a.mu.Unlock()
// 	a.saveConfig()
// 	log.Printf("transmission settings updated: %s", url)
// 	return nil
// }

// failJob marks a job as failed with a human-readable reason and removes the
// pending record so a restart does not silently retry it.
func (a *Agent) failJob(j *Job, reason string) {
	a.mu.Lock()
	if j.cancelled {
		a.mu.Unlock()
		return
	}
	j.state = "error"
	j.err = reason
	a.mu.Unlock()
	if j.magnet != "" {
		a.removePending(j.magnet)
	}
	a.pushStatus()
	log.Printf("job %s failed: %q — %s", j.id, j.name, reason)
}

// startDownload forwards a magnet to Transmission. No payload is downloaded
// locally, no .torrent is saved — Transmission does all of that.
func (a *Agent) startDownload(id, magnet /*catDir,*/, name string) {
	ih := infoHash(magnet)
	a.mu.Lock()
	if ih != "" {
		for _, ex := range a.jobs {
			if ex.state != "error" && infoHash(ex.magnet) == ih {
				a.mu.Unlock()
				log.Printf("job %s duplicate of active %q -> skipped", id, ex.name)
				return
			}
		}
	}
	j := &Job{
		id: id, name: name, magnet: magnet /*dir: catDir,*/, state: "connecting",
		cancelCh: make(chan struct{}), doneCh: make(chan struct{}),
	}
	a.jobs[id] = j
	a.mu.Unlock()
	defer close(j.doneCh)

	a.addPending(id, magnet /*catDir,*/, name)
	log.Printf("job %s queued for Transmission: %q", id, name)

	// The only thing we do: hand the magnet to Transmission.
	err := a.transmissionAdd(magnet)
	if err != nil {
		a.failJob(j, "Transmission: "+err.Error())
		return
	}

	a.setState(j, "done")
	a.mu.Lock()
	j.pct = 100
	a.mu.Unlock()
	a.removePending(magnet)
	a.addHistory(HistEntry{
		Name: name /*Dir: catDir,*/, MiB: 0, Done: time.Now().Unix(),
	})
	log.Printf("job %s complete: %q -> Transmission", id, name)
}

func (a *Agent) addHistory(h HistEntry) {
	a.mu.Lock()
	a.cfg.History = append(a.cfg.History, h)
	if len(a.cfg.History) > historyCap {
		a.cfg.History = a.cfg.History[len(a.cfg.History)-historyCap:]
	}
	a.mu.Unlock()
	a.saveConfig()
}

// func (a *Agent) clearHistory() {
// 	a.mu.Lock()
// 	a.cfg.History = nil
// 	a.mu.Unlock()
// 	a.saveConfig()
// }

func (a *Agent) setState(j *Job, s string) {
	a.mu.Lock()
	j.state = s
	a.mu.Unlock()
}

// ---------- status push (content-free) ----------

func (a *Agent) printLoop() {
	for range time.Tick(5 * time.Second) {
		a.mu.Lock()
		jobs := make([]*Job, 0, len(a.jobs))
		for _, j := range a.jobs {
			jobs = append(jobs, j)
		}
		a.mu.Unlock()
		for _, j := range jobs {
			printJob(j)
		}
	}
}

func printJob(j *Job) {
	defer func() { _ = recover() }()
	if j == nil {
		return
	}
	log.Printf("%-11s  %s", j.state, j.name)
}

func (a *Agent) pushStatus() {
	a.mu.Lock()
	jobs := make([]map[string]any, 0, len(a.jobs))
	for _, j := range a.jobs {
		jobs = append(jobs, map[string]any{
			"id": j.id, "pct": j.pct, "state": j.state, "paused": false,
			"speed": int64(0), "err": j.err,
		})
	}
	a.mu.Unlock()
	a.send(map[string]any{"type": "status", "jobs": jobs})
}

func (a *Agent) statusLoop() {
	for range time.Tick(2 * time.Second) {
		a.mu.Lock()
		jobs := make([]map[string]any, 0, len(a.jobs))
		for _, j := range a.jobs {
			jobs = append(jobs, map[string]any{
				"id": j.id, "pct": j.pct, "state": j.state,
				"speed": int64(0), "eta": int64(-1),
				"peers": 0, "seeds": 0, "paused": false,
				"err": j.err,
			})
		}
		a.mu.Unlock()
		a.send(map[string]any{"type": "status", "jobs": jobs})
	}
}

// ---------- main ----------

var version = "dev"

func main() {
	for _, a := range os.Args[1:] {
		// if len(a) > 9 && a[:9] == "--window=" {
		// 	runWindow(a[9:])
		// 	return
		// }
		if a == "--version" || a == "-version" {
			fmt.Println("Lampa Downloader agent", version)
			return
		}
	}

	defWs := "wss://relay.bwa.ad/ws"
	cfgDir, _ := os.UserConfigDir()
	defCfg := filepath.Join(cfgDir, "lampa-downloader", "agent.json")

	wsURL := flag.String("relay", defWs, "relay websocket URL")
	cfgPath := flag.String("config", defCfg, "config file path")
	transmissionURLFlag := flag.String("transmission-url", "", "Transmission RPC URL (overrides config)")
	transmissionUserFlag := flag.String("transmission-user", "", "Transmission RPC user (overrides config)")
	transmissionPassFlag := flag.String("transmission-pass", "", "Transmission RPC password (overrides config)")
	selfTest := flag.String("selftest", "", "send this magnet to Transmission and exit")
	pairFlag := flag.Bool("pair", false, "open pairing window on the running agent for 10 minutes")
	codeFlag := flag.Bool("code", false, "print the running agent's pairing code")
	statusFlag := flag.Bool("status", false, "print a JSON status of the running agent")
	quitFlag := flag.Bool("quit", false, "ask the running agent to shut down")
	flag.Parse()

	// Client subcommands: talk to the running agent, then exit. These work
	// whether or not the agent is running; if it isn't, they report so.
	if *pairFlag || *codeFlag || *statusFlag || *quitFlag {
		switch {
		case *pairFlag:
			os.Exit(controlClient("pair"))
		case *codeFlag:
			os.Exit(controlClient("code"))
		case *statusFlag:
			os.Exit(controlClient("status"))
		case *quitFlag:
			os.Exit(controlClient("quit"))
		}
	}
	os.MkdirAll(filepath.Dir(*cfgPath), 0700)
	cfg, err := loadOrInitConfig(*cfgPath)
	if err != nil {
		log.Fatal(err)
	}
	logPath := setupLogging(*cfgPath)
	if *transmissionURLFlag != "" {
		cfg.TransmissionURL = *transmissionURLFlag
	}
	if *transmissionUserFlag != "" {
		cfg.TransmissionUser = *transmissionUserFlag
	}
	if *transmissionPassFlag != "" {
		cfg.TransmissionPass = *transmissionPassFlag
	}

	var pub, priv [32]byte
	copy(pub[:], unb64(cfg.Pub))
	copy(priv[:], unb64(cfg.Priv))

	a := &Agent{
		cfgPath: *cfgPath,
		logPath: logPath,
		started: time.Now(),
		cfg:     cfg,
		priv:    &priv,
		pub:     &pub,
		code:    deriveCode(pub[:]),
		jobs:    make(map[string]*Job),
		devices: make(map[string]*Device),
		outCh:   make(chan map[string]any, 32),
	}
	for i := range cfg.Devices {
		d := cfg.Devices[i]
		a.devices[d.Pub] = &d
	}
	a.saveConfig()

	if len(a.devices) == 0 {
		a.openPairWindow(pairFirstRunDur)
	}

	// uiAddr := *uiAddrFlag
	//	uiURL := "http://127.0.0.1" + uiAddr[strings.LastIndex(uiAddr, ":"):]

	if *selfTest == "" {
		lock, lerr := net.Listen("tcp", controlAddr)
		if lerr != nil {
			// Another instance is already running on this host. We only reach
			// here if the user ran us without a client subcommand; just report.
			fmt.Fprintf(os.Stderr, "agent already running on %s; use -pair, -code, -status, or -quit\n", controlAddr)
			os.Exit(1)
		}
		go a.controlServer(lock)
		defer lock.Close()
	}

	fmt.Println("============================================")
	fmt.Printf("  Lampa Downloader agent %s\n", version)
	fmt.Printf("  Pairing code:  %s\n", fmtCode(a.code))
	fmt.Printf("  Transmission:  %s\n", cfg.TransmissionURL)
	fmt.Println("  Enter the code in Lampa to link this PC.")
	fmt.Println("============================================")

	if *selfTest != "" {
		a.runSelfTest(*selfTest)
		return
	}

	go a.statusLoop()
	go a.printLoop()

	// if err := setAutostart(a.cfg.Autostart); err != nil {
	// 	log.Printf("autostart: %v", err)
	// }
	// if *uiToken == "" {
	// 	*uiToken = os.Getenv("UI_TOKEN")
	// }
	// if !loopbackBind(uiAddr) && *uiToken == "" {
	// 	log.Fatalf("панель на внешнем адресе (%s) требует токен: задайте -ui-token или переменную окружения UI_TOKEN", uiAddr)
	// }
	// a.uiToken = *uiToken
	// a.startUI(uiAddr)

	// retry hand-offs that were still pending when we last exited
	a.mu.Lock()
	resume := append([]PendingJob(nil), a.cfg.Pending...)
	a.mu.Unlock()
	for _, p := range resume {
		id := p.ID
		if id == "" {
			id = randID()
		}
		log.Printf("resuming: %q", p.Name)
		go a.startDownload(id, p.Magnet /*p.Dir,*/, p.Name)
	}

	go a.connectLoop(*wsURL)
	log.Printf("running headless; control via %s (-pair/-code/-status/-quit)", controlAddr)
	select {}
	// runAgentGUI(a, uiURL)
}

// runSelfTest sends a magnet to Transmission directly (no relay, no crypto),
// to confirm the RPC path works here.
func (a *Agent) runSelfTest(arg string) {
	if !validMagnet(arg) {
		log.Fatal("selftest: not a magnet URI")
	}
	if err := a.transmissionAdd(arg); err != nil {
		log.Fatalf("selftest: transmission: %v", err)
	}
	fmt.Println("selftest: DONE — magnet accepted by Transmission")
}

func fmtCode(c string) string {
	if len(c) == 6 {
		return c[:3] + " " + c[3:]
	}
	return c
}
