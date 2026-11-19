//go:build linux

package cfprobe

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestLinuxTrafficAgentReportUsesCommittedOriginAndNativeMonthly(t *testing.T) {
	reports := make(chan map[string]any, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Metrics map[string]any `json:"metrics"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		reports <- payload.Metrics
		_, _ = w.Write([]byte("OK"))
	}))
	defer server.Close()
	nextReport := func() map[string]any {
		select {
		case report := <-reports:
			return report
		case <-time.After(5 * time.Second):
			t.Fatal("Agent did not send the expected report")
			return nil
		}
	}
	cfg := linuxTrafficConfig()
	cfg.ServerID, cfg.WorkerURL, cfg.ConnectionMode = "fixture", server.URL, connectionModeHTTP
	dir := t.TempDir()
	configFile := filepath.Join(dir, "config.conf")
	writeConfig(configFile, cfg)
	p := testTrafficPolicy(t, cfg)
	samples, err := readTrafficInterfaces(p)
	if err != nil {
		t.Fatal(err)
	}
	st := trafficLedger{Version: 1, trafficTotals: trafficTotals{NetBytes{100, 200}, NetBytes{100, 200}, NetBytes{100, 200}}, NativeInterface: "original", Policy: p.signature(), ReportMode: "raw", LastCheck: time.Now().Unix(), Interfaces: map[string]trafficInterfaceState{}}
	for name, sample := range samples {
		st.Interfaces[name] = trafficInterfaceState{trafficInterfaceSample: sample}
	}
	if err := writeTrafficLedger(trafficLedgerPath(configFile), st); err != nil {
		t.Fatal(err)
	}
	nativePath := filepath.Join(dir, "traffic.dat")
	native := trafficState{RXPrev: 100, TXPrev: 200, RXPeriod: 400, TXPeriod: 500, LastCheck: time.Now().Unix(), PeriodStart: periodStartTS(time.Now(), 1), Interface: "original"}
	writeTrafficState(nativePath, native)
	accountant, err := openTrafficAccountant(runtimePaths("", configFile), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer accountant.close()
	a := Agent{cfg: cfg, paths: Paths{ConfigFile: configFile, TrafficFile: nativePath}, traffic: accountant, log: newLogger(false)}
	if err := a.tick(); err != nil {
		t.Fatal(err)
	}
	m := nextReport()
	rx, err := strconv.ParseUint(m["net_rx"].(string), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := strconv.ParseUint(m["net_tx"].(string), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	if m["net_rx_monthly"] != strconv.FormatUint(400+rx-100, 10) || m["net_tx_monthly"] != strconv.FormatUint(500+tx-200, 10) {
		t.Fatalf("native origin mapping: %+v", m)
	}
	before := readTrafficState(nativePath)
	// 在原生全量上报缓存窗口内触发第二次上报。
	a.lastPost = time.Time{}
	a.lastPostAttempt = time.Time{}
	if err := a.tick(); err != nil {
		t.Fatal(err)
	}
	cached := nextReport()
	if cached["net_rx_monthly"] != m["net_rx_monthly"] || cached["net_tx_monthly"] != m["net_tx_monthly"] || readTrafficState(nativePath) != before {
		t.Fatal("extension bypassed native monthly cache")
	}
}

func TestLinuxTrafficFullNameSelectionAndMissing(t *testing.T) {
	cfg := accountingConfig()
	cfg.Interface = "eth0,sit0,relay0"
	cfg.TrafficExclude = "relay0"
	cfg.TrafficWeights = ""
	p := testTrafficPolicy(t, cfg)
	line := func(name string, rx, tx uint64) string {
		return fmt.Sprintf("%s: %d 0 0 0 0 0 0 0 %d 0 0 0 0 0 0 0\n", name, rx, tx)
	}
	data := line("eth0", 10, 20) + line("sit0", 30, 40) + line("relay0", 999, 999) + line("docker0", 999, 999)
	values, err := parseTrafficNetDev(data, p)
	if err != nil || len(values) != 2 || values["sit0"] != (NetBytes{30, 40}) {
		t.Fatalf("exact include/exclude: %+v %v", values, err)
	}
	if _, err := parseTrafficNetDev(line("eth0", 10, 20), p); err == nil || !strings.Contains(err.Error(), "sit0") {
		t.Fatal("missing selected interface did not fail strictly")
	}
	if _, err := parseTrafficNetDev(data+"eth0: invalid\n", p); err == nil {
		t.Fatal("malformed counters accepted")
	}
	if _, err := parseTrafficNetDev(data+line("eth0", 1, 2), p); err == nil {
		t.Fatal("duplicate source accepted")
	}
}

func linuxTrafficConfig() Config {
	cfg := defaultConfig()
	cfg.Interface = "lo"
	cfg.TrafficReport = "raw"
	return cfg
}

func TestLinuxTrafficCheckIsReadOnlyAndStrict(t *testing.T) {
	cfg := linuxTrafficConfig()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.conf")
	if err := writeConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := executeTrafficCommand("traffic-check", []string{"-config=" + path}, &out); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatal("offline check initialized state/lock")
	}
	if !strings.Contains(out.String(), `"lo"`) || !strings.Contains(out.String(), `"ok":true`) {
		t.Fatal(out.String())
	}
	cfg.Interface = "cfsm_missing_for_test"
	writeConfig(path, cfg)
	out.Reset()
	if err := executeTrafficCommand("traffic-check", []string{"-config=" + path}, &out); err == nil || !strings.Contains(out.String(), `"ok":false`) {
		t.Fatal("missing interface diagnostic not actionable")
	}
}

func TestLinuxTrafficLedgerLockSeedAndMigration(t *testing.T) {
	cfg := linuxTrafficConfig()
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)
	path := filepath.Join(dir, "config.conf")
	if err := writeConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	paths := runtimePaths("example", path)
	nativePath := filepath.Join(dir, "traffic.dat")
	native := trafficState{RXPrev: 100, TXPrev: 200, RXPeriod: 400, TXPeriod: 500, LastCheck: time.Now().Unix(), PeriodStart: periodStartTS(time.Now(), 1), Interface: ""}
	if err := writeTrafficState(nativePath, native); err != nil {
		t.Fatal(err)
	}
	original, _ := os.ReadFile(nativePath)
	if a, err := openTrafficAccountant(paths, cfg); err == nil {
		a.close()
		t.Fatal("existing native state silently reinitialized")
	}
	seedPath := filepath.Join(dir, "seed.json")
	seed := `{"raw_total_bytes":{"rx":100,"tx":200},"billing_total_bytes":{"rx":100,"tx":200},"reported_total_bytes":{"rx":100,"tx":200}}`
	if err := os.WriteFile(seedPath, []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	args := []string{"-instance=example", "-config=" + path, "-seed=" + seedPath}
	release, err := acquireInstanceLock(paths)
	if err != nil {
		t.Fatal(err)
	}
	seedErr := executeTrafficCommand("traffic-seed", args, &out)
	release()
	if seedErr == nil {
		t.Fatal("seed bypassed the running named instance's native lock")
	}
	if err := executeTrafficCommand("traffic-seed", args, &out); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(nativePath)
	if !bytes.Equal(original, after) {
		t.Fatal("seed changed native monthly history")
	}
	a, err := openTrafficAccountant(paths, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if a.state.NativeInterface != "" || a.state.ReportedTotal != (NetBytes{100, 200}) {
		t.Fatal("native counter origin lost")
	}
	if second, err := openTrafficAccountant(paths, cfg); err == nil {
		second.close()
		t.Fatal("two instances acquired same ledger")
	}
	if err := executeTrafficCommand("traffic-seed", args, &out); err == nil {
		t.Fatal("seed overwrote running state")
	}
	if err := a.close(); err != nil {
		t.Fatal(err)
	}
	if err := executeTrafficCommand("traffic-seed", args, &out); err == nil {
		t.Fatal("seed overwrote existing ledger")
	}
	if err := os.WriteFile(trafficLedgerPath(path), []byte("broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if a, err := openTrafficAccountant(paths, cfg); err == nil {
		a.close()
		t.Fatal("corrupt ledger silently reset")
	}
}

func TestLinuxTrafficCheckpointVisibilityFailureAndRecovery(t *testing.T) {
	cfg := linuxTrafficConfig()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.conf")
	writeConfig(path, cfg)
	a, err := openTrafficAccountant(runtimePaths("", path), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer a.unlock()
	now := time.Now()
	if _, _, _, err = a.sample(cfg, now, false); err != nil {
		t.Fatal(err)
	}
	committed := a.committed.ReportedTotal
	// 模拟已有累计增量、尚未到达落盘时间的采样区间。
	a.state.ReportedTotal.RX += 10
	total, _, _, err := a.sample(cfg, now.Add(time.Second), false)
	if err != nil || total != committed {
		t.Fatal("uncommitted total escaped into wire metrics")
	}
	total, _, _, err = a.sample(cfg, now.Add(31*time.Second), false)
	if err != nil || total.RX < committed.RX+10 {
		t.Fatal("committed interval did not become visible")
	}
	cfg.Interface = "cfsm_missing_for_test"
	totalBefore := a.state.ReportedTotal
	_, rxSpeed, txSpeed, err := a.sample(cfg, now.Add(32*time.Second), false)
	var readErr *trafficReadError
	if !errors.As(err, &readErr) || rxSpeed != 0 || txSpeed != 0 || a.state.Interfaces["lo"].BaselineValid || a.state.ReportedTotal != totalBefore {
		t.Fatal("read failure committed fake counters")
	}
	checkpoint, err := readTrafficLedger(a.path)
	if err != nil || checkpoint.Interfaces["lo"].BaselineValid || checkpoint.ReportedTotal != totalBefore {
		t.Fatalf("restart would bridge the missing interval: %+v, %v", checkpoint, err)
	}
	cfg = linuxTrafficConfig()
	if _, rx, tx, err := a.sample(cfg, now.Add(33*time.Second), false); err != nil || rx != 0 || tx != 0 {
		t.Fatalf("recovery did not rebaseline: %d/%d %v", rx, tx, err)
	}
	a.path = filepath.Join(dir, "absent", "ledger")
	a.checkpointAt = time.Time{}
	committed = a.committed.ReportedTotal
	if _, _, _, err := a.sample(cfg, now.Add(34*time.Second), false); err == nil {
		t.Fatal("write failure swallowed")
	}
	if a.committed.ReportedTotal != committed {
		t.Fatal("failed write committed visible totals")
	}
}

func TestLinuxTrafficSeedRejectsWrongOriginAndPartialTotals(t *testing.T) {
	cfg := linuxTrafficConfig()
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)
	path := filepath.Join(dir, "config.conf")
	writeConfig(path, cfg)
	writeTrafficState(filepath.Join(dir, "traffic.dat"), trafficState{RXPrev: 100, TXPrev: 200, LastCheck: time.Now().Unix()})
	seedPath := filepath.Join(dir, "seed.json")
	for _, seed := range []string{
		`{"raw_total_bytes":{"rx":100,"tx":200},"billing_total_bytes":{"rx":100,"tx":200},"reported_total_bytes":{"rx":101,"tx":200}}`,
		`{"raw_total_bytes":{"rx":100},"billing_total_bytes":{"rx":100,"tx":200},"reported_total_bytes":{"rx":100,"tx":200}}`,
		`{}`,
	} {
		os.WriteFile(seedPath, []byte(seed), 0o600)
		if err := executeTrafficCommand("traffic-seed", []string{"-config=" + path, "-seed=" + seedPath}, &bytes.Buffer{}); err == nil {
			t.Fatal("invalid seed accepted")
		}
		if _, err := os.Stat(trafficLedgerPath(path)); !os.IsNotExist(err) {
			t.Fatal("invalid seed created state")
		}
	}
	os.WriteFile(filepath.Join(dir, "traffic.dat"), []byte("TX_PREV=1\n"), 0o600)
	if _, _, err := readNativeTrafficBaseline(filepath.Join(dir, "traffic.dat")); err == nil {
		t.Fatal("corrupt native state silently accepted")
	}
}
