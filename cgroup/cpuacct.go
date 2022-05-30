package cgroup

import (
	"bufio"
	"bytes"
	"github.com/pkg/errors"
	"io"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	// "github.com/prometheus/common/log"
)

// CPUAcct stores one core's worth of CPU usage for a control group
// (aka cgroup) of tasks (e.g. both processes and threads).
// Equivalent to cpuacct.usage_percpu_user and cpuacct.usage_percpu_system
type CPUAcct struct {
	TotalMicrosec  uint64
	SystemMicrosec uint64
	UserMicrosec   uint64
}

// NewCPUAcct will locate and read the kernel's cpu accounting info for
// the provided systemd cgroup subpath.
func NewCPUAcct(cgSubpath string) (*CPUAcct, error) {
	fs, err := NewDefaultFS()
	if err != nil {
		return nil, err
	}
	return fs.NewCPUAcct(cgSubpath)
}

// ReadFileNoStat uses ioutil.ReadAll to read contents of entire file.
// This is similar to ioutil.ReadFile but without the call to os.Stat, because
// many files in /proc and /sys report incorrect file sizes (either 0 or 4096).
// Reads a max file size of 512kB.  For files larger than this, a scanner
// should be used.
// COPIED FROM prometheus/procfs WHICH ALSO USES APACHE 2.0
func ReadFileNoStat(filename string) ([]byte, error) {
	const maxBufferSize = 1024 * 512

	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	reader := io.LimitReader(f, maxBufferSize)
	return ioutil.ReadAll(reader)
}

// NewCPUAcct will locate and read the kernel's cpu accounting info for
// the provided systemd cgroup subpath.
func (fs FS) NewCPUAcct(cgSubpath string) (*CPUAcct, error) {
	var cpuAcct CPUAcct
	var readTotal, readUser, readSystem bool

	cgPath, err := fs.cgGetPath("cpu", cgSubpath, "cpu.stat")
	if err != nil {
		return nil, errors.Wrapf(err, "unable to get cpu controller path")
	}

	// Example cpuacct.usage_all
	// cpu user system
	// 0 21165924 0
	// 1 13334251 0
	b, err := ReadFileNoStat(cgPath)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to read file %s", cgPath)
	}

	scanner := bufio.NewScanner(bytes.NewReader(b))
	for scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return nil, errors.Wrapf(err, "unable to scan file %s", cgPath)
		}
		text := scanner.Text()
		vals := strings.Split(text, " ")
		if len(vals) != 2 {
			return nil, errors.Errorf("unable to parse contents of file %s", cgPath)
		}
		header := vals[0]
		value, err := strconv.ParseUint(vals[1], 10, 64)
		if err != nil {
			return nil, errors.Wrapf(err, "unable to parse %s as uint64 (from %s)", vals[1], cgPath)
		}
		// log.Infoln("parsed", header, value)
		switch header {
		case "usage_usec":
			cpuAcct.TotalMicrosec = value
			readTotal = true
		case "user_usec":
			cpuAcct.UserMicrosec = value
			readUser = true
		case "system_usec":
			cpuAcct.SystemMicrosec = value
			readSystem = true
		}
	}
	if !(readTotal && readUser && readSystem) {
		return nil, errors.Errorf("no / incomplete info extracted from %s", cgPath)
	}

	return &cpuAcct, nil
}
