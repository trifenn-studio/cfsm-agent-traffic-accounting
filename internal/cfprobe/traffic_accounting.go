package cfprobe

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const trafficPPM uint64 = 1000000
const trafficCheckpointInterval = 30 * time.Second

type trafficReadError struct{ error }

func (e *trafficReadError) Unwrap() error { return e.error }

// 顺序为 RX 到入站、TX 到入站、RX 到出站、TX 到出站，权重使用整数 ppm。
type trafficWeights [4]uint64

type trafficPolicy struct {
	Include []string                  `json:"include"`
	Exclude []string                  `json:"exclude"`
	Weights map[string]trafficWeights `json:"weights_ppm"`
}

func exactTrafficNames(raw string) ([]string, error) {
	normalized, err := normalizeInterfaceList(raw)
	if err != nil {
		return nil, err
	}
	names := []string{}
	for _, name := range strings.Split(normalized, ",") {
		if name == "" {
			continue
		}
		if strings.ContainsAny(name, "*?[]:") {
			return nil, fmt.Errorf("traffic interface requires a complete Linux name: %q", name)
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

func trafficPolicyForConfig(cfg Config) (trafficPolicy, error) {
	p := trafficPolicy{Weights: map[string]trafficWeights{}}
	if cfg.TrafficReport == "" {
		if cfg.TrafficExclude != "" || cfg.TrafficWeights != "" {
			return p, errors.New("TRAFFIC_REPORT=raw|billing is required for traffic policy")
		}
		return p, nil
	}
	if cfg.TrafficReport != "raw" && cfg.TrafficReport != "billing" {
		return p, errors.New("TRAFFIC_REPORT must be raw or billing")
	}
	var err error
	p.Include, err = exactTrafficNames(cfg.Interface)
	if err != nil {
		return p, err
	}
	if len(p.Include) == 0 {
		return p, errors.New("traffic accounting requires explicit INTERFACE names")
	}
	p.Exclude, err = exactTrafficNames(cfg.TrafficExclude)
	if err != nil {
		return p, err
	}
	included, excluded := splitInterfaceSet(cfg.Interface), splitInterfaceSet(cfg.TrafficExclude)
	for _, name := range p.Include {
		if !excluded[name] {
			p.Weights[name] = trafficWeights{trafficPPM, 0, 0, trafficPPM}
		}
	}
	if len(p.Weights) == 0 {
		return p, errors.New("traffic policy excludes every included interface")
	}
	if cfg.TrafficWeights != "" {
		seen := map[string]bool{}
		for _, entry := range strings.Split(cfg.TrafficWeights, ";") {
			parts := strings.Split(entry, ":")
			if len(parts) != 5 || !included[parts[0]] || seen[parts[0]] {
				return p, fmt.Errorf("invalid TRAFFIC_WEIGHTS entry %q; expected included-name:rx_in:tx_in:rx_out:tx_out", entry)
			}
			seen[parts[0]] = true
			var w trafficWeights
			for i, value := range parts[1:] {
				n, err := strconv.ParseUint(value, 10, 64)
				if err != nil || strings.HasPrefix(value, "+") {
					return p, fmt.Errorf("invalid nonnegative integer ppm %q", value)
				}
				w[i] = n
			}
			if !excluded[parts[0]] {
				p.Weights[parts[0]] = w
			}
		}
	}
	return p, nil
}

func (p trafficPolicy) signature() string {
	data, _ := json.Marshal(p)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

type trafficInterfaceSample struct {
	Identity string   `json:"identity"`
	Counters NetBytes `json:"counters_bytes"`
}

type trafficInterfaceState struct {
	trafficInterfaceSample
	BaselineValid bool           `json:"baseline_valid"`
	Remainder     trafficWeights `json:"remainder_ppm"`
}

type trafficTotals struct {
	RawTotal      NetBytes `json:"raw_total_bytes"`
	BillingTotal  NetBytes `json:"billing_total_bytes"`
	ReportedTotal NetBytes `json:"reported_total_bytes"`
}

type trafficLedger struct {
	Version int `json:"version"`
	trafficTotals
	// 本地策略变化时保留 traffic.go 原有的筛选键。
	NativeInterface string                           `json:"native_interface"`
	ReportMode      string                           `json:"report_mode"`
	LastCheck       int64                            `json:"last_check"`
	Policy          string                           `json:"policy_sha256"`
	Interfaces      map[string]trafficInterfaceState `json:"interfaces"`
}

func strictTrafficJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("trailing traffic JSON data")
	}
	return nil
}

func requireTrafficFields(data []byte, fields ...string) (map[string]json.RawMessage, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		return nil, err
	}
	for _, field := range fields {
		if value, ok := object[field]; !ok || string(value) == "null" {
			return nil, fmt.Errorf("missing traffic field %s", field)
		}
	}
	return object, nil
}

func validateTrafficTotalsJSON(data []byte) error {
	fields := []string{"raw_total_bytes", "billing_total_bytes", "reported_total_bytes"}
	object, err := requireTrafficFields(data, fields...)
	if err != nil {
		return err
	}
	for _, field := range fields {
		if _, err := requireTrafficFields(object[field], "rx", "tx"); err != nil {
			return err
		}
	}
	return nil
}

func readTrafficLedger(path string) (trafficLedger, error) {
	var st trafficLedger
	data, err := os.ReadFile(path)
	if err != nil {
		return st, err
	}
	if err := strictTrafficJSON(data, &st); err != nil {
		return st, fmt.Errorf("corrupt traffic ledger: %w", err)
	}
	if err := validateTrafficTotalsJSON(data); err != nil {
		return st, err
	}
	object, err := requireTrafficFields(data, "version", "native_interface", "report_mode", "last_check", "policy_sha256", "interfaces")
	if err != nil {
		return st, err
	}
	var interfaceObjects map[string]json.RawMessage
	if err := json.Unmarshal(object["interfaces"], &interfaceObjects); err != nil {
		return st, err
	}
	for _, raw := range interfaceObjects {
		fields, err := requireTrafficFields(raw, "identity", "counters_bytes", "baseline_valid", "remainder_ppm")
		if err != nil {
			return st, err
		}
		if _, err := requireTrafficFields(fields["counters_bytes"], "rx", "tx"); err != nil {
			return st, err
		}
		var values []*uint64
		if err := json.Unmarshal(fields["remainder_ppm"], &values); err != nil || len(values) != len(trafficWeights{}) {
			return st, errors.New("invalid traffic remainder array")
		}
		for _, value := range values {
			if value == nil || *value >= trafficPPM {
				return st, errors.New("invalid traffic remainder")
			}
		}
	}
	if st.Version != 1 || st.Interfaces == nil || !validSHA256Hex(st.Policy) || st.LastCheck <= 0 || (st.ReportMode != "raw" && st.ReportMode != "billing") {
		return st, errors.New("invalid traffic ledger schema/header")
	}
	for name, iface := range st.Interfaces {
		if iface.Identity == "" {
			return st, fmt.Errorf("missing identity for %s", name)
		}
	}
	return st, nil
}

// 使用独立临时文件、文件同步、重命名和目录同步，只暴露完整检查点。
// 调用方在账本使用期间持有同目录的 flock 锁。
func writeTrafficLedger(path string, st trafficLedger) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".traffic-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0o600); err == nil {
		_, err = f.Write(append(data, '\n'))
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func addTraffic(dst *uint64, value uint64) error {
	sum, carry := bits.Add64(*dst, value, 0)
	if carry != 0 {
		return errors.New("traffic counter overflow")
	}
	*dst = sum
	return nil
}

func weightedTraffic(value, weight, remainder uint64) (uint64, uint64, error) {
	hi, lo := bits.Mul64(value, weight)
	var carry uint64
	lo, carry = bits.Add64(lo, remainder, 0)
	hi, carry = bits.Add64(hi, 0, carry)
	if carry != 0 || hi >= trafficPPM {
		return 0, 0, errors.New("traffic multiplication overflow")
	}
	q, r := bits.Div64(hi, lo, trafficPPM)
	return q, r, nil
}

func weightTraffic(delta NetBytes, w trafficWeights, rem *trafficWeights) (NetBytes, error) {
	var result NetBytes
	values := [4]uint64{delta.RX, delta.TX, delta.RX, delta.TX}
	for i := range w {
		q, r, err := weightedTraffic(values[i], w[i], rem[i])
		if err != nil {
			return result, err
		}
		rem[i] = r
		dst := &result.RX
		if i >= 2 {
			dst = &result.TX
		}
		if err = addTraffic(dst, q); err != nil {
			return result, err
		}
	}
	return result, nil
}

func addNetTraffic(dst *NetBytes, value NetBytes) error {
	if err := addTraffic(&dst.RX, value.RX); err != nil {
		return err
	}
	return addTraffic(&dst.TX, value.TX)
}

// 保留已累计的余数，未知区间从新基线开始。
// 复制映射，保持上一次已提交的快照不变。
func (st *trafficLedger) invalidateBaselines() (changed bool) {
	invalid := make(map[string]trafficInterfaceState, len(st.Interfaces))
	for name, previous := range st.Interfaces {
		changed = changed || previous.BaselineValid
		previous.BaselineValid = false
		invalid[name] = previous
	}
	st.Interfaces = invalid
	return changed
}

// advance 在计算失败时保留所有累计和基线。
// 重置只影响对应的来源方向，新接口身份使用新基线。
func (st trafficLedger) advance(p trafficPolicy, mode string, now time.Time, samples map[string]trafficInterfaceSample) (trafficLedger, NetBytes, error) {
	next := st
	next.invalidateBaselines()
	signature := p.signature()
	samePolicy := signature == st.Policy && st.ReportMode == mode
	var rawDelta, billingDelta NetBytes
	for name, sample := range samples {
		w, selected := p.Weights[name]
		if !selected {
			return st, NetBytes{}, fmt.Errorf("unselected traffic interface %s", name)
		}
		previous, exists := st.Interfaces[name]
		current := trafficInterfaceState{trafficInterfaceSample: sample, BaselineValid: true}
		if exists {
			current.Remainder = previous.Remainder
		}
		if exists && previous.BaselineValid && samePolicy && sample.Identity == previous.Identity {
			delta := NetBytes{}
			if sample.Counters.RX >= previous.Counters.RX {
				delta.RX = sample.Counters.RX - previous.Counters.RX
			}
			if sample.Counters.TX >= previous.Counters.TX {
				delta.TX = sample.Counters.TX - previous.Counters.TX
			}
			if err := addNetTraffic(&rawDelta, delta); err != nil {
				return st, NetBytes{}, err
			}
			billed, err := weightTraffic(delta, w, &current.Remainder)
			if err != nil {
				return st, NetBytes{}, err
			}
			if err = addNetTraffic(&billingDelta, billed); err != nil {
				return st, NetBytes{}, err
			}
		}
		next.Interfaces[name] = current
	}
	if len(samples) != len(p.Weights) {
		return st, NetBytes{}, errors.New("incomplete traffic sample")
	}
	if err := addNetTraffic(&next.RawTotal, rawDelta); err != nil {
		return st, NetBytes{}, err
	}
	if err := addNetTraffic(&next.BillingTotal, billingDelta); err != nil {
		return st, NetBytes{}, err
	}
	reportedDelta := rawDelta
	if mode == "billing" {
		reportedDelta = billingDelta
	}
	if err := addNetTraffic(&next.ReportedTotal, reportedDelta); err != nil {
		return st, NetBytes{}, err
	}
	next.Version, next.Policy, next.ReportMode, next.LastCheck = 1, signature, mode, now.Unix()
	return next, rawDelta, nil
}

type trafficAccountant struct {
	path         string
	read         func(trafficPolicy) (map[string]trafficInterfaceSample, error)
	state        trafficLedger
	committed    trafficLedger
	checkpointAt time.Time
	sampleAt     time.Time
	unlock       func()
}

func trafficLedgerPath(configFile string) string {
	return filepath.Join(filepath.Dir(configFile), "traffic-accounting.dat")
}

func readNativeTrafficBaseline(path string) (NetBytes, string, error) {
	values, err := parseKVFile(path)
	if err != nil {
		return NetBytes{}, "", err
	}
	for _, key := range []string{"RX_PREV", "TX_PREV", "RX_PERIOD", "TX_PERIOD", "LAST_CHECK"} {
		if _, err := strconv.ParseUint(values[key], 10, 64); err != nil {
			return NetBytes{}, "", fmt.Errorf("invalid native traffic.dat %s: %w", key, err)
		}
	}
	if values["LAST_CHECK"] == "0" {
		return NetBytes{}, "", errors.New("uninitialized native traffic.dat")
	}
	if _, ok := values["INTERFACE"]; !ok {
		return NetBytes{}, "", errors.New("missing native traffic.dat INTERFACE")
	}
	if value, ok := values["PERIOD_START"]; ok {
		if _, err := strconv.ParseInt(value, 10, 64); err != nil {
			return NetBytes{}, "", fmt.Errorf("invalid native traffic.dat PERIOD_START: %w", err)
		}
	}
	rx, _ := strconv.ParseUint(values["RX_PREV"], 10, 64)
	tx, _ := strconv.ParseUint(values["TX_PREV"], 10, 64)
	return NetBytes{RX: rx, TX: tx}, values["INTERFACE"], nil
}

func checkNativeTrafficBaseline(path string, st trafficLedger) error {
	baseline, key, err := readNativeTrafficBaseline(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if key != st.NativeInterface || baseline.RX > st.ReportedTotal.RX || baseline.TX > st.ReportedTotal.TX {
		return errors.New("native traffic.dat does not match continuous ledger origin")
	}
	return nil
}

func openTrafficAccountant(paths Paths, cfg Config) (*trafficAccountant, error) {
	path := trafficLedgerPath(paths.ConfigFile)
	unlock, err := lockTrafficLedger(path)
	if err != nil {
		return nil, err
	}
	opened := false
	defer func() {
		if !opened {
			unlock()
		}
	}()
	st, err := readTrafficLedger(path)
	if os.IsNotExist(err) {
		// 原有的月度状态只有本期小计。已有实例切换前需要显式指定连续累计初值。
		if _, nativeErr := os.Stat(paths.TrafficFile); nativeErr == nil {
			return nil, errors.New("existing traffic.dat: create an explicit traffic-seed before enabling accounting")
		} else if !os.IsNotExist(nativeErr) {
			return nil, nativeErr
		}
		p, policyErr := trafficPolicyForConfig(cfg)
		if policyErr != nil {
			return nil, policyErr
		}
		st = trafficLedger{Version: 1, NativeInterface: cfg.Interface, Policy: p.signature(), ReportMode: cfg.TrafficReport, Interfaces: map[string]trafficInterfaceState{}}
		err = nil
	}
	if err != nil {
		return nil, err
	}
	if err := checkNativeTrafficBaseline(paths.TrafficFile, st); err != nil {
		return nil, err
	}
	opened = true
	return &trafficAccountant{path: path, read: readTrafficInterfaces, state: st, committed: st, unlock: unlock}, nil
}

func (a *trafficAccountant) checkpoint(now time.Time) error {
	if a.state.LastCheck == 0 {
		return nil
	}
	if err := writeTrafficLedger(a.path, a.state); err != nil {
		return fmt.Errorf("checkpoint traffic ledger %s: %w", a.path, err)
	}
	a.committed, a.checkpointAt = a.state, now
	return nil
}

func (a *trafficAccountant) close() error {
	defer a.unlock()
	return a.checkpoint(time.Now())
}

func (a *trafficAccountant) sample(cfg Config, now time.Time, fullReport bool) (NetBytes, uint64, uint64, error) {
	p, err := trafficPolicyForConfig(cfg)
	if err != nil {
		return NetBytes{}, 0, 0, err
	}
	samples, readErr := a.read(p)
	needsCheckpoint := false
	var speed NetBytes
	if readErr != nil {
		// 恢复时从新基线继续，包含进程重启的情况，避免计入未知区间。
		needsCheckpoint = a.state.invalidateBaselines()
		a.sampleAt = time.Time{}
	} else {
		next, delta, err := a.state.advance(p, cfg.TrafficReport, now, samples)
		if err != nil {
			return NetBytes{}, 0, 0, err
		}
		if elapsed := now.Sub(a.sampleAt).Seconds(); !a.sampleAt.IsZero() && elapsed > 0 {
			speed.RX = uint64(float64(delta.RX) / elapsed)
			speed.TX = uint64(float64(delta.TX) / elapsed)
		}
		a.state, a.sampleAt = next, now
		// 先落盘，再让 traffic.dat 引用新的累计值。
		needsCheckpoint = fullReport
	}
	if needsCheckpoint || a.checkpointAt.IsZero() || now.Sub(a.checkpointAt) >= trafficCheckpointInterval {
		if err = a.checkpoint(now); err != nil {
			return NetBytes{}, 0, 0, err
		}
	}
	total := a.committed.ReportedTotal
	if readErr != nil {
		return total, speed.RX, speed.TX, &trafficReadError{readErr}
	}
	return total, speed.RX, speed.TX, nil
}
