//go:build linux

package cfprobe

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func lockTrafficLedger(path string) (func(), error) {
	f, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	if err = f.Chmod(0o600); err == nil {
		err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	}
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("traffic ledger is locked or unavailable: %w", err)
	}
	return func() { _ = unix.Flock(int(f.Fd()), unix.LOCK_UN); _ = f.Close() }, nil
}

func parseTrafficNetDev(data string, p trafficPolicy) (map[string]NetBytes, error) {
	result := map[string]NetBytes{}
	for _, line := range strings.Split(data, "\n") {
		name, rest, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		if _, selected := p.Weights[name]; !selected {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) < 16 {
			return nil, fmt.Errorf("invalid network counters for %s", name)
		}
		rx, rxErr := strconv.ParseUint(fields[0], 10, 64)
		tx, txErr := strconv.ParseUint(fields[8], 10, 64)
		if rxErr != nil || txErr != nil {
			return nil, fmt.Errorf("invalid network counters for %s", name)
		}
		if _, duplicate := result[name]; duplicate {
			return nil, fmt.Errorf("duplicate interface %s", name)
		}
		result[name] = NetBytes{RX: rx, TX: tx}
	}
	missing := []string{}
	for _, name := range p.Include {
		if _, selected := p.Weights[name]; !selected {
			continue
		}
		if _, found := result[name]; !found {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("missing traffic interfaces: %s (no fallback)", strings.Join(missing, ","))
	}
	return result, nil
}

func readTrafficIdentity(name, bootID, namespace string) (string, error) {
	dir := filepath.Join("/sys/class/net", name)
	info, err := os.Stat(dir)
	if err != nil {
		return "", err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", errors.New("network identity stat unavailable")
	}
	identity := fmt.Sprintf("%s/%s/%d", bootID, namespace, stat.Ino)
	for _, field := range []string{"ifindex", "iflink", "address", "type"} {
		data, err := os.ReadFile(filepath.Join(dir, field))
		if err != nil {
			return "", err
		}
		value := strings.TrimSpace(string(data))
		if value == "" {
			return "", fmt.Errorf("empty network identity %s/%s", name, field)
		}
		identity += "/" + value
	}
	return identity, nil
}

func readTrafficInterfaces(p trafficPolicy) (map[string]trafficInterfaceSample, error) {
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || strings.TrimSpace(string(boot)) == "" {
		return nil, errors.New("boot identity unavailable")
	}
	namespace, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return nil, err
	}
	identities := map[string]string{}
	for name := range p.Weights {
		id, err := readTrafficIdentity(name, strings.TrimSpace(string(boot)), namespace)
		if err != nil {
			return nil, fmt.Errorf("traffic interface %s: %w", name, err)
		}
		identities[name] = id
	}
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return nil, err
	}
	counters, err := parseTrafficNetDev(string(data), p)
	if err != nil {
		return nil, err
	}
	result := map[string]trafficInterfaceSample{}
	for name, value := range counters {
		identity, err := readTrafficIdentity(name, strings.TrimSpace(string(boot)), namespace)
		if err != nil {
			return nil, err
		}
		if identity != identities[name] {
			return nil, fmt.Errorf("interface identity changed while reading %s", name)
		}
		result[name] = trafficInterfaceSample{Identity: identity, Counters: value}
	}
	return result, nil
}
