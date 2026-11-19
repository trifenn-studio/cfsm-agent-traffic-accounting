package cfprobe

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"
)

// 只读命令无需获取或创建锁，也无需写文件或初始化 Agent。
// 上报、身份生成和自动发现仅由正式运行的 Agent 执行。
func executeTrafficCommand(command string, args []string, out io.Writer) error {
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var instance, configFile, seedFile string
	fs.StringVar(&instance, "instance", "", "")
	fs.StringVar(&configFile, "config", "", "")
	if command == "traffic-seed" {
		fs.StringVar(&seedFile, "seed", "", "")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected traffic command arguments")
	}
	instance, err := normalizeInstanceName(instance)
	if err != nil {
		return err
	}
	paths := runtimePaths(instance, configFile)
	cfg, err := readConfig(paths.ConfigFile)
	if err != nil {
		return err
	}
	if cfg.TrafficReport == "" {
		return errors.New("traffic accounting disabled; set TRAFFIC_REPORT=raw|billing")
	}
	p, err := trafficPolicyForConfig(cfg)
	if err != nil {
		return err
	}
	path := trafficLedgerPath(paths.ConfigFile)
	if command == "traffic-seed" {
		return seedTrafficLedger(paths, seedFile, cfg, p, out)
	}
	result := map[string]any{"version": 1, "report": cfg.TrafficReport, "policy": p, "policy_sha256": p.signature(), "state_file": path, "unit": "bytes", "speed_unit": "bytes/second", "reset_day": cfg.ResetDay, "update_protection": true}
	if command == "traffic-check" {
		samples, sampleErr := readTrafficInterfaces(p)
		result["interfaces"], result["ok"] = samples, sampleErr == nil
		if sampleErr != nil {
			result["error"] = sampleErr.Error()
		}
		if err := json.NewEncoder(out).Encode(result); err != nil {
			return err
		}
		return sampleErr
	}
	st, err := readTrafficLedger(path)
	if err != nil {
		return err
	}
	result["state"], result["policy_matches"] = st, st.Policy == p.signature() && st.ReportMode == cfg.TrafficReport
	return json.NewEncoder(out).Encode(result)
}

func seedTrafficLedger(paths Paths, seedFile string, cfg Config, p trafficPolicy, out io.Writer) error {
	if seedFile == "" {
		return errors.New("traffic-seed requires -seed=FILE (three explicit continuous byte totals)")
	}
	// 切换流量计量时也要排除仍在运行的原生 Agent。
	release, err := acquireInstanceLock(paths)
	if err != nil {
		return err
	}
	defer release()

	path := trafficLedgerPath(paths.ConfigFile)
	unlock, err := lockTrafficLedger(path)
	if err != nil {
		return err
	}
	defer unlock()
	if _, err := os.Lstat(path); err == nil {
		return errors.New("traffic-seed requires an absent ledger; existing state is never overwritten")
	} else if !os.IsNotExist(err) {
		return err
	}
	data, err := os.ReadFile(seedFile)
	if err != nil {
		return err
	}
	var seed trafficTotals
	if err := strictTrafficJSON(data, &seed); err != nil {
		return err
	}
	if err := validateTrafficTotalsJSON(data); err != nil {
		return err
	}
	now := time.Now()
	samples, err := readTrafficInterfaces(p)
	if err != nil {
		return err
	}
	st := trafficLedger{
		Version: 1, trafficTotals: seed, NativeInterface: cfg.Interface,
		Policy: p.signature(), ReportMode: cfg.TrafficReport, LastCheck: now.Unix(),
		Interfaces: make(map[string]trafficInterfaceState, len(samples)),
	}
	// 原样保留 traffic.dat，包括周期累计和筛选键。
	// 以最近一次连续累计输入作为交接起点。
	baseline, key, err := readNativeTrafficBaseline(paths.TrafficFile)
	if err == nil {
		if st.ReportedTotal != baseline {
			return errors.New("reported_total_bytes must equal existing traffic.dat RX_PREV/TX_PREV; native monthly state is preserved")
		}
		st.NativeInterface = key
	} else if !os.IsNotExist(err) {
		return err
	}
	for name, sample := range samples {
		st.Interfaces[name] = trafficInterfaceState{trafficInterfaceSample: sample, BaselineValid: true}
	}
	if err := writeTrafficLedger(path, st); err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "traffic ledger seeded: %s\n", path)
	return err
}
