//go:build !linux

package cfprobe

import "errors"

func lockTrafficLedger(string) (func(), error) {
	return nil, errors.New("traffic accounting is supported on Linux only")
}

func readTrafficInterfaces(trafficPolicy) (map[string]trafficInterfaceSample, error) {
	return nil, errors.New("traffic interface diagnostics are supported on Linux only")
}
