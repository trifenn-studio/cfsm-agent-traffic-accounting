package cfprobe

import (
	"bytes"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func accountingConfig() Config {
	cfg := defaultConfig()
	cfg.Interface, cfg.TrafficReport, cfg.ResetDay = "eth0,relay0", "billing", 1
	cfg.TrafficWeights = "eth0:1000000:0:0:1000000;relay0:0:0:1000000:2000000"
	return cfg
}

func testTrafficPolicy(t *testing.T, cfg Config) trafficPolicy {
	t.Helper()
	p, err := trafficPolicyForConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func testTrafficSamples(rx, tx uint64) map[string]trafficInterfaceSample {
	return map[string]trafficInterfaceSample{
		"eth0":   {Identity: "boot/index/physical", Counters: NetBytes{rx, tx}},
		"relay0": {Identity: "boot/index/relay", Counters: NetBytes{rx, tx}},
	}
}

func advanceTraffic(t *testing.T, st trafficLedger, p trafficPolicy, at time.Time, samples map[string]trafficInterfaceSample) trafficLedger {
	t.Helper()
	next, _, err := st.advance(p, "billing", at, samples)
	if err != nil {
		t.Fatal(err)
	}
	return next
}

func TestTrafficDirectionMappingAndSegmentEquivalence(t *testing.T) {
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	cfg := accountingConfig()
	p := testTrafficPolicy(t, cfg)
	baseline := advanceTraffic(t, trafficLedger{}, p, now, testTrafficSamples(10000, 20000))
	whole := advanceTraffic(t, baseline, p, now.Add(time.Second), testTrafficSamples(10100, 20200))
	if whole.RawTotal != (NetBytes{200, 400}) || whole.BillingTotal != (NetBytes{100, 700}) {
		t.Fatalf("four-direction mapping: %+v", whole.trafficTotals)
	}
	cfg.TrafficWeights = "eth0:500000:0:500000:1000000;relay0:0:500000:1000000:500000"
	p = testTrafficPolicy(t, cfg)
	baseline = advanceTraffic(t, trafficLedger{}, p, now, testTrafficSamples(10000, 20000))
	whole = advanceTraffic(t, baseline, p, now.Add(time.Second), testTrafficSamples(10101, 20203))
	segmented := baseline
	for i := uint64(1); i <= 101; i++ {
		segmented = advanceTraffic(t, segmented, p, now.Add(time.Duration(i)*time.Second), testTrafficSamples(10000+i, 20000+2*i))
	}
	segmented = advanceTraffic(t, segmented, p, now.Add(102*time.Second), testTrafficSamples(10101, 20203))
	if !reflect.DeepEqual(segmented.trafficTotals, whole.trafficTotals) || !reflect.DeepEqual(segmented.Interfaces, whole.Interfaces) {
		t.Fatalf("segmented accounting differs: %+v / %+v", segmented, whole)
	}
	if whole.BillingTotal != (NetBytes{151, 455}) {
		t.Fatalf("50%% mapping: %+v", whole.BillingTotal)
	}
}

func TestTrafficRestartPolicyAndIdentityContinuity(t *testing.T) {
	cfg := accountingConfig()
	p := testTrafficPolicy(t, cfg)
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	cfg.TrafficWeights = "eth0:500000:0:0:500000;relay0:0:0:0:0"
	p = testTrafficPolicy(t, cfg)
	st := advanceTraffic(t, trafficLedger{}, p, now, testTrafficSamples(100, 100))
	st = advanceTraffic(t, st, p, now.Add(time.Second), testTrafficSamples(101, 101))
	path := filepath.Join(t.TempDir(), "traffic-accounting.dat")
	if err := writeTrafficLedger(path, st); err != nil {
		t.Fatal(err)
	}
	loaded, err := readTrafficLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(loaded, st) {
		t.Fatal("checkpoint lost baseline/remainders")
	}
	st = advanceTraffic(t, loaded, p, now.Add(2*time.Second), testTrafficSamples(102, 102))
	if st.BillingTotal != (NetBytes{1, 1}) {
		t.Fatalf("restart fractional loss: %+v", st)
	}
	// 单方向重置时，另一方向的真实增量仍需计入。
	st = advanceTraffic(t, st, p, now.Add(3*time.Second), testTrafficSamples(0, 104))
	if st.RawTotal != (NetBytes{4, 8}) || st.BillingTotal != (NetBytes{1, 2}) {
		t.Fatalf("reset accounting: %+v", st.trafficTotals)
	}
	before := st.trafficTotals
	samples := testTrafficSamples(999999, 999999)
	v := samples["eth0"]
	v.Identity = "new-boot-or-ifindex"
	samples["eth0"] = v
	v = samples["relay0"]
	v.Identity = "renamed-or-recreated"
	samples["relay0"] = v
	st = advanceTraffic(t, st, p, now.Add(4*time.Second), samples)
	if st.trafficTotals != before {
		t.Fatal("identity change counted historical traffic")
	}
	cfg.TrafficWeights = "eth0:2000000:0:0:2000000;relay0:0:0:0:0"
	p = testTrafficPolicy(t, cfg)
	st = advanceTraffic(t, st, p, now.Add(5*time.Second), testTrafficSamples(9999999, 9999999))
	if st.trafficTotals != before {
		t.Fatal("weight change recalculated history")
	}
	st = advanceTraffic(t, st, p, now.Add(6*time.Second), testTrafficSamples(10000000, 10000000))
	if st.BillingTotal != (NetBytes{before.BillingTotal.RX + 2, before.BillingTotal.TX + 2}) {
		t.Fatal("new weights not applied to future increments")
	}
}

func TestTrafficFeedsOriginalMonthlyStateAcrossPolicyChanges(t *testing.T) {
	cfg := accountingConfig()
	p := testTrafficPolicy(t, cfg)
	now := time.Now()
	nativePath := filepath.Join(t.TempDir(), "traffic.dat")
	native := trafficState{RXPrev: 1000, TXPrev: 2000, RXPeriod: 400, TXPeriod: 500, LastCheck: now.Unix(), PeriodStart: periodStartTS(now, 1), Interface: "old-native-selector"}
	if err := writeTrafficState(nativePath, native); err != nil {
		t.Fatal(err)
	}
	st := trafficLedger{trafficTotals: trafficTotals{RawTotal: NetBytes{1000, 2000}, BillingTotal: NetBytes{1000, 2000}, ReportedTotal: NetBytes{1000, 2000}}, NativeInterface: native.Interface}
	st = advanceTraffic(t, st, p, now, testTrafficSamples(100, 200))
	st = advanceTraffic(t, st, p, now.Add(time.Second), testTrafficSamples(110, 220))
	rx, tx, err := calcMonthlyTraffic(nativePath, st.ReportedTotal, 1, st.NativeInterface)
	if err != nil || rx != 410 || tx != 570 {
		t.Fatalf("existing monthly totals lost: %d/%d %v", rx, tx, err)
	}
	before := st.ReportedTotal
	// 上报模式变化只影响后续增量。原生起点、本月累计和历史累计保持不变。
	st, _, err = st.advance(p, "raw", now.Add(2*time.Second), testTrafficSamples(99999, 99999))
	if err != nil || st.ReportedTotal != before {
		t.Fatalf("mode change jumped: %+v %v", st, err)
	}
	st, _, err = st.advance(p, "raw", now.Add(3*time.Second), testTrafficSamples(100000, 100000))
	if err != nil || st.ReportedTotal != (NetBytes{before.RX + 2, before.TX + 2}) {
		t.Fatalf("raw mode did not increment: %+v %v", st, err)
	}
	rx, tx, err = calcMonthlyTraffic(nativePath, st.ReportedTotal, 1, st.NativeInterface)
	if err != nil || rx != 412 || tx != 572 {
		t.Fatalf("native month after mode change: %d/%d %v", rx, tx, err)
	}
	// 网卡筛选范围变化时保留 traffic.dat 原有的筛选键。
	delete(p.Weights, "relay0")
	p.Include = []string{"eth0"}
	samples := testTrafficSamples(100001, 100001)
	delete(samples, "relay0")
	st, _, err = st.advance(p, "raw", now.Add(4*time.Second), samples)
	if err != nil || st.NativeInterface != native.Interface {
		t.Fatal("scope changed native month key")
	}
	if rx, tx, err = calcMonthlyTraffic(nativePath, st.ReportedTotal, 1, st.NativeInterface); err != nil || rx != 412 || tx != 572 {
		t.Fatal("scope reset native monthly totals")
	}
}

func TestTrafficOverflowDoesNotCommitPartialState(t *testing.T) {
	p := testTrafficPolicy(t, accountingConfig())
	now := time.Now()
	st := advanceTraffic(t, trafficLedger{}, p, now, testTrafficSamples(0, 0))
	st.RawTotal.RX = math.MaxUint64
	original, _ := json.Marshal(st)
	if _, _, err := st.advance(p, "billing", now.Add(time.Second), testTrafficSamples(1, 1)); err == nil {
		t.Fatal("sum overflow accepted")
	}
	after, _ := json.Marshal(st)
	if !bytes.Equal(original, after) {
		t.Fatal("overflow mutated original state")
	}
	p.Weights["eth0"] = trafficWeights{math.MaxUint64, 0, 0, 0}
	st = advanceTraffic(t, trafficLedger{}, p, now, testTrafficSamples(0, 0))
	if _, _, err := st.advance(p, "billing", now.Add(time.Second), testTrafficSamples(math.MaxUint64, 0)); err == nil {
		t.Fatal("weighted overflow accepted")
	}
	if q, r, err := weightedTraffic(math.MaxUint64, trafficPPM, 0); err != nil || q != math.MaxUint64 || r != 0 {
		t.Fatalf("128-bit exact unity failed: %d %d %v", q, r, err)
	}
}

func TestTrafficPolicyValidationAndExcludePriority(t *testing.T) {
	cfg := accountingConfig()
	cfg.TrafficExclude = "relay0"
	p := testTrafficPolicy(t, cfg)
	if len(p.Weights) != 1 {
		t.Fatal("exclude did not win over explicit weights/include")
	}
	cases := []Config{}
	for _, weight := range []string{"NaN", "-1", "0.5", "18446744073709551616", "+1"} {
		c := accountingConfig()
		c.TrafficWeights = "eth0:" + weight + ":0:0:0"
		cases = append(cases, c)
	}
	for _, name := range []string{"", "eth*", "eth[0]", "eth0,../x"} {
		c := accountingConfig()
		c.Interface = name
		cases = append(cases, c)
	}
	c := accountingConfig()
	c.TrafficWeights = "unknown:0:0:0:0"
	cases = append(cases, c)
	c = accountingConfig()
	c.TrafficWeights = "eth0:0:0:0:0;eth0:1:1:1:1"
	cases = append(cases, c)
	c = accountingConfig()
	c.TrafficReport = ""
	cases = append(cases, c)
	for i, c := range cases {
		if _, err := trafficPolicyForConfig(c); err == nil {
			t.Fatalf("invalid policy accepted %d: %+v", i, c)
		}
	}
	if _, err := trafficPolicyForConfig(defaultConfig()); err != nil {
		t.Fatalf("legacy config rejected: %v", err)
	}
}

func TestTrafficStateCorruptionAndAtomicFailure(t *testing.T) {
	p := testTrafficPolicy(t, accountingConfig())
	st := advanceTraffic(t, trafficLedger{}, p, time.Now(), testTrafficSamples(100, 200))
	dir := t.TempDir()
	path := filepath.Join(dir, "ledger")
	if err := writeTrafficLedger(path, st); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("unsafe mode: %v", info.Mode())
	}
	valid, _ := os.ReadFile(path)
	var object map[string]json.RawMessage
	json.Unmarshal(valid, &object)
	delete(object, "raw_total_bytes")
	missing, _ := json.Marshal(object)
	for _, bad := range [][]byte{
		[]byte("{"), []byte("{}"), append(append([]byte{}, valid...), []byte("{}")...), missing,
		bytes.Replace(valid, []byte(`"version": 1`), []byte(`"version": 2`), 1),
		bytes.Replace(valid, []byte(`"rx": 100`), []byte(`"rx": -1`), 1),
		bytes.Replace(valid, []byte("\"remainder_ppm\": [\n        0,"), []byte("\"remainder_ppm\": [\n        null,"), 1),
	} {
		if err := os.WriteFile(path, bad, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readTrafficLedger(path); err == nil {
			t.Fatalf("corrupt ledger accepted: %s", bad)
		}
	}
	if err := os.WriteFile(path, valid, 0o600); err != nil {
		t.Fatal(err)
	}
	// 目标为目录时重命名失败，读端仍看不到半写的文件。
	target := filepath.Join(dir, "directory")
	os.Mkdir(target, 0o700)
	if err := writeTrafficLedger(target, st); err == nil {
		t.Fatal("checkpoint failure swallowed")
	}
	got, _ := os.ReadFile(path)
	if !bytes.Equal(got, valid) {
		t.Fatal("failed checkpoint changed previous ledger")
	}
	leftovers, _ := filepath.Glob(filepath.Join(dir, ".traffic-*"))
	if len(leftovers) != 0 {
		t.Fatal("temporary ledger leaked")
	}
}

func TestTrafficConfigRoundTripRemoteAndLegacyCorrections(t *testing.T) {
	cfg := accountingConfig()
	path := filepath.Join(t.TempDir(), "config.conf")
	if err := writeConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	loaded, err := readConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.TrafficReport != cfg.TrafficReport || loaded.TrafficWeights != cfg.TrafficWeights || loaded.Interface != cfg.Interface {
		t.Fatal("local policy lost")
	}
	a := Agent{cfg: loaded, paths: Paths{ConfigFile: path}, log: newLogger(false)}
	headers := http.Header{"X-Agent-Config-Md5": []string{strings.Repeat("b", 32)}}
	body := []byte("collect_interval=0&report_interval=60&reset_day=1&schema_version=7&interface=eth99&connection_mode=http&ping_mode=tcp")
	if err := a.applyRemoteConfig(body, headers); err != nil {
		t.Fatal(err)
	}
	loaded, err = readConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.TrafficWeights != cfg.TrafficWeights || loaded.Interface != cfg.Interface || loaded.TrafficReport != cfg.TrafficReport {
		t.Fatal("remote config cleared local traffic policy")
	}
	a.fullAt = time.Unix(12, 0)
	if err := a.applyRemoteConfigWithOptions(body, http.Header{}, true); err != nil {
		t.Fatal(err)
	}
	if !a.fullAt.Equal(time.Unix(12, 0)) {
		t.Fatal("identical WSS config refreshed the pinned local policy")
	}
	if err := a.applyRemoteConfig([]byte("rx_correction=12"), http.Header{}); err == nil {
		t.Fatal("legacy correction modified extended accounting")
	}
	if _, err := prepareInstallTrafficCorrection(InstallOptions{}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareInstallTrafficCorrection(InstallOptions{Config: cfg, RXCorrectionGB: "12"}, nil); err == nil {
		t.Fatal("install correction bypassed the ledger")
	}
}

func TestTrafficDefaultPathsAndWorkerSelector(t *testing.T) {
	if got, want := runtimePaths("", ""), defaultPaths(); got != want {
		t.Fatalf("default paths changed: %+v != %+v", got, want)
	}
	if got, want := runtimePaths("example", ""), pathsForInstance("example"); got != want {
		t.Fatalf("named paths changed: %+v != %+v", got, want)
	}
	path := filepath.Join(t.TempDir(), "custom.conf")
	paths := runtimePaths("example", path)
	if paths.Instance != "example" || paths.ConfigFile != path || paths.TrafficFile != filepath.Join(filepath.Dir(path), "traffic.dat") {
		t.Fatalf("custom paths: %+v", paths)
	}
	a := Agent{cfg: defaultConfig(), paths: paths, log: newLogger(false)}
	body := []byte("collect_interval=0&report_interval=60&reset_day=1&schema_version=" + configSchemaVersion + "&interface=eth*&connection_mode=http&ping_mode=tcp")
	if err := a.applyRemoteConfigWithOptions(body, nil, true); err != nil {
		t.Fatal(err)
	}
	values, err := parseKVFile(path)
	if err != nil || values["INTERFACE"] != "eth*" || a.traffic != nil {
		t.Fatalf("default path stopped using the Worker selector: %v, %v", values, err)
	}
	if _, ok := values["TRAFFIC_REPORT"]; ok {
		t.Fatal("default configuration acquired a traffic accounting policy")
	}
}

func TestTrafficContinuousAcrossRepeatedWorkerConfig(t *testing.T) {
	reports := make(chan map[string]any, 2)
	worker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Metrics map[string]any `json:"metrics"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		reports <- payload.Metrics
		_, _ = w.Write([]byte("OK"))
	}))
	defer worker.Close()

	cfg := accountingConfig()
	cfg.ServerID, cfg.WorkerURL, cfg.ConnectionMode = "fixture", worker.URL, connectionModeHTTP
	cfg.TrafficExclude = "relay0"
	cfg.TrafficWeights = "eth0:500000:0:0:2000000"
	paths := runtimePaths("example", filepath.Join(t.TempDir(), "config.conf"))
	if err := writeConfig(paths.ConfigFile, cfg); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	native := trafficState{RXPrev: 100, TXPrev: 200, RXPeriod: 400, TXPeriod: 500, LastCheck: now.Unix(), PeriodStart: periodStartTS(now, 1), Interface: "original"}
	if err := writeTrafficState(paths.TrafficFile, native); err != nil {
		t.Fatal(err)
	}
	counter := uint64(1000)
	st := trafficLedger{NativeInterface: native.Interface, trafficTotals: trafficTotals{ReportedTotal: NetBytes{100, 200}}}
	acc := &trafficAccountant{
		path: trafficLedgerPath(paths.ConfigFile), state: st, committed: st,
		read: func(policy trafficPolicy) (map[string]trafficInterfaceSample, error) {
			if weights, ok := policy.Weights["eth0"]; !ok || len(policy.Weights) != 1 || weights != (trafficWeights{500000, 0, 0, 2000000}) {
				t.Fatalf("Worker changed local sampling policy: %+v", policy)
			}
			return map[string]trafficInterfaceSample{"eth0": {Identity: "fixture", Counters: NetBytes{counter, counter}}}, nil
		},
	}
	a := Agent{cfg: cfg, paths: paths, traffic: acc, log: newLogger(false)}
	if err := a.tick(); err != nil {
		t.Fatal(err)
	}
	body := []byte("collect_interval=0&report_interval=30&reset_day=1&schema_version=" + configSchemaVersion + "&interface=eth99&connection_mode=http&ping_mode=tcp")
	md5 := http.Header{"X-Agent-Config-Md5": {strings.Repeat("b", 32)}}
	for _, headers := range []http.Header{nil, md5} {
		// 首次下发可能改变上报间隔或 MD5，重复下发时保持现有状态。
		if err := a.applyRemoteConfigWithOptions(body, headers, headers == nil); err != nil {
			t.Fatal(err)
		}
		a.fullAt = now
		for range 3 {
			if err := a.applyRemoteConfigWithOptions(body, headers, headers == nil); err != nil {
				t.Fatal(err)
			}
			if a.fullAt != now || a.monthlyRX != 400 || a.monthlyTX != 500 {
				t.Fatal("repeated Worker push refreshed the monthly cache")
			}
		}
		counter++
		if _, rxSpeed, txSpeed, err := acc.sample(a.configSnapshot(), acc.sampleAt.Add(time.Second), false); err != nil || rxSpeed != 1 || txSpeed != 1 {
			t.Fatalf("unweighted speed across a Worker push = %d/%d, %v", rxSpeed, txSpeed, err)
		}
	}
	loaded, err := readConfig(paths.ConfigFile)
	if err != nil || loaded.Interface != cfg.Interface || loaded.TrafficReport != cfg.TrafficReport || loaded.TrafficExclude != cfg.TrafficExclude || loaded.TrafficWeights != cfg.TrafficWeights || loaded.ReportInterval != 30 || loaded.ConfigMD5 != md5.Get("X-Agent-Config-Md5") {
		t.Fatalf("unexpected persisted config after pushes: %+v, %v", loaded, err)
	}
	if acc.state.RawTotal != (NetBytes{2, 2}) || acc.state.BillingTotal != (NetBytes{1, 4}) {
		t.Fatalf("counter or fraction lost: %+v", acc.state.trafficTotals)
	}
	a.fullAt = time.Time{}
	if err := a.tick(); err != nil {
		t.Fatal(err)
	}
	for _, want := range []map[string]string{
		{"net_rx": "100", "net_tx": "200", "net_rx_monthly": "400", "net_tx_monthly": "500"},
		{"net_rx": "101", "net_tx": "204", "net_rx_monthly": "401", "net_tx_monthly": "504"},
	} {
		select {
		case metrics := <-reports:
			for key, value := range want {
				if metrics[key] != value {
					t.Fatalf("wire %s = %v, want %s", key, metrics[key], value)
				}
			}
		case <-time.After(time.Second):
			t.Fatal("Agent did not send a report to the local Worker")
		}
	}
	ledger, err := readTrafficLedger(acc.path)
	if err != nil || ledger.ReportedTotal != (NetBytes{101, 204}) || readTrafficState(paths.TrafficFile).Interface != native.Interface {
		t.Fatalf("native checkpoint did not use the persisted origin: %+v, %v", ledger, err)
	}
}

func TestTrafficOfflineStatusDoesNotWriteOrExposeSecrets(t *testing.T) {
	cfg := accountingConfig()
	cfg.Secret = "never-show-this"
	cfg.WorkerURL = "https://invalid.example"
	dir := t.TempDir()
	path := filepath.Join(dir, "config.conf")
	writeConfig(path, cfg)
	p := testTrafficPolicy(t, cfg)
	st := advanceTraffic(t, trafficLedger{}, p, time.Now(), testTrafficSamples(1, 2))
	writeTrafficLedger(trafficLedgerPath(path), st)
	before, _ := os.ReadDir(dir)
	var out bytes.Buffer
	if err := executeTrafficCommand("traffic-status", []string{"-config=" + path}, &out); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadDir(dir)
	if len(before) != len(after) || strings.Contains(out.String(), cfg.Secret) || strings.Contains(out.String(), cfg.WorkerURL) {
		t.Fatal("offline command wrote files or disclosed credentials")
	}
	var report map[string]any
	if err := json.Unmarshal(out.Bytes(), &report); err != nil || report["unit"] != "bytes" {
		t.Fatalf("invalid output schema: %s %v", out.String(), err)
	}
	metrics := metricsToMap((&Agent{}).buildMetrics(cfg, "0", NetBytes{12, 34}, 56, 78, 90, 123, DiskIOStats{}))
	for key, want := range map[string]string{"net_rx": "12", "net_tx": "34", "net_rx_monthly": "90", "net_tx_monthly": "123", "net_in_speed": "56", "net_out_speed": "78"} {
		if metrics[key] != want {
			t.Fatalf("wire %s=%v", key, metrics[key])
		}
	}
}

func TestTrafficFractionSurvivesRepeatedMissingExcludeAndRestart(t *testing.T) {
	cfg := accountingConfig()
	cfg.TrafficWeights = "eth0:500000:0:0:500000;relay0:0:0:0:0"
	full := testTrafficPolicy(t, cfg)
	cfg.TrafficExclude = "eth0"
	excluded := testTrafficPolicy(t, cfg)
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	st := advanceTraffic(t, trafficLedger{}, full, now, testTrafficSamples(0, 0))
	path := filepath.Join(t.TempDir(), "ledger")
	var value uint64
	var earned uint64
	for cycle := 0; cycle < 6; cycle++ {
		value++
		earned++
		st = advanceTraffic(t, st, full, now.Add(time.Duration(cycle*10+1)*time.Second), testTrafficSamples(value, value))
		// 读取失败使基线失效，保留已累计的余数。
		committed := st
		st.invalidateBaselines()
		if !committed.Interfaces["eth0"].BaselineValid {
			t.Fatal("invalidation mutated committed snapshot")
		}
		if err := writeTrafficLedger(path, st); err != nil {
			t.Fatal(err)
		}
		var err error
		st, err = readTrafficLedger(path)
		if err != nil {
			t.Fatal(err)
		}
		value += 1000 // unknown interval: recovery may not import these counters
		st = advanceTraffic(t, st, full, now.Add(time.Duration(cycle*10+2)*time.Second), testTrafficSamples(value, value))
		value++
		earned++
		st = advanceTraffic(t, st, full, now.Add(time.Duration(cycle*10+3)*time.Second), testTrafficSamples(value, value))
		// 再累计半个字节，然后暂时排除该接口。
		value++
		earned++
		st = advanceTraffic(t, st, full, now.Add(time.Duration(cycle*10+4)*time.Second), testTrafficSamples(value, value))
		samples := testTrafficSamples(value, value)
		delete(samples, "eth0")
		st = advanceTraffic(t, st, excluded, now.Add(time.Duration(cycle*10+5)*time.Second), samples)
		if st.Interfaces["eth0"].BaselineValid {
			t.Fatal("excluded interface baseline stayed valid")
		}
		if err := writeTrafficLedger(path, st); err != nil {
			t.Fatal(err)
		}
		st, err = readTrafficLedger(path)
		if err != nil {
			t.Fatal(err)
		}
		value += 1000
		st = advanceTraffic(t, st, full, now.Add(time.Duration(cycle*10+6)*time.Second), testTrafficSamples(value, value))
		want := earned / 2
		if st.BillingTotal != (NetBytes{want, want}) || st.ReportedTotal != st.BillingTotal || st.Interfaces["eth0"].Remainder[0] != (earned%2)*500000 {
			t.Fatalf("cycle %d lost an earned fraction or charged unknown counters: %+v remainder=%v", cycle, st.trafficTotals, st.Interfaces["eth0"].Remainder)
		}
	}
	whole := advanceTraffic(t, trafficLedger{}, full, now, testTrafficSamples(0, 0))
	whole = advanceTraffic(t, whole, full, now.Add(time.Second), testTrafficSamples(earned, earned))
	if st.BillingTotal != whole.BillingTotal || st.Interfaces["eth0"].Remainder != whole.Interfaces["eth0"].Remainder {
		t.Fatal("interrupted fractional sampling differs from the same known increments sampled together")
	}
}
