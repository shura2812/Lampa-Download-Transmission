package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

// controlAddr is the loopback address used both as the single-instance lock
// and as the control channel for a running agent.
const controlAddr = "127.0.0.1:47800"

// controlServer listens on controlAddr and answers one-line commands from a
// second invocation of the binary (./agent -pair, -code, -status, -quit).
// It is also what keeps the single-instance behavior: if the port is taken,
// a second launch talks to the first instead of starting a competing engine.
func (a *Agent) controlServer(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			c.SetDeadline(time.Now().Add(5 * time.Second))
			r := bufio.NewReader(c)
			line, err := r.ReadString('\n')
			if err != nil && line == "" {
				return
			}
			cmd := strings.TrimSpace(line)
			switch cmd {
			case "pair":
				a.openPairWindow(pairWindowDur)
				fmt.Fprintf(c, "ok: pairing window open for %s\n", pairWindowDur)
			case "code":
				fmt.Fprintf(c, "%s\n", fmtCode(a.code))
			case "status":
				b, _ := json.MarshalIndent(a.controlStatus(), "", "  ")
				c.Write(b)
				c.Write([]byte("\n"))
			case "quit":
				fmt.Fprintln(c, "ok: shutting down")
				go osExit()
			default:
				fmt.Fprintf(c, "error: unknown command %q\n", cmd)
			}
		}(conn)
	}
}

// controlStatus is the JSON shape returned by "-status".
type controlStatus struct {
	Version      string `json:"version"`
	Uptime       string `json:"uptime"`
	Code         string `json:"code"`
	Relay        bool   `json:"relay_up"`
	Transmission string `json:"transmission_url"`
	Devices      int    `json:"devices"`
	Pending      int    `json:"pending"`
	History      int    `json:"history"`
	PairSec      int    `json:"pair_sec"`
	PairLeft     int    `json:"pair_left"`
	LogPath      string `json:"log_path"`
}

func (a *Agent) controlStatus() controlStatus {
	a.mu.Lock()
	defer a.mu.Unlock()
	pairSec := 0
	if a.pairLeft > 0 {
		if v := int(time.Until(a.pairUntil).Seconds()); v > 0 {
			pairSec = v
		}
	}
	return controlStatus{
		Version:      version,
		Uptime:       time.Since(a.started).Round(time.Second).String(),
		Code:         fmtCode(a.code),
		Relay:        a.relayUp,
		Transmission: a.cfg.TransmissionURL,
		Devices:      len(a.devices),
		Pending:      len(a.cfg.Pending),
		History:      len(a.cfg.History),
		PairSec:      pairSec,
		PairLeft:     a.pairLeft,
		LogPath:      a.logPath,
	}
}

// controlClient sends one command to an already-running agent and prints the
// reply. Returns exit code (0 = ok, 1 = no running agent / error).
func controlClient(cmd string) int {
	conn, err := net.DialTimeout("tcp", controlAddr, 3*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "no running agent on %s: %v\n", controlAddr, err)
		return 1
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(conn, "%s\n", cmd)
	//	reply, _ := bufio.NewReader(conn).ReadString('\n')
	reply, _ := io.ReadAll(conn)
	fmt.Print(string(reply))
	// if !strings.HasPrefix(strings.TrimSpace(string(reply)), "ok") {
	// 	// status/code return non-"ok" payloads; treat unknown/error as failure.
	// 	if strings.HasPrefix(string(reply), "error:") || string(reply) == "" {
	// 		return 1
	// 	}
	// }
	return 0
}
