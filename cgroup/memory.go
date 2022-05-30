package cgroup

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/pkg/errors"
	"io"
	"strconv"
	"strings"
)

// MemStat represents the memory.stat file provided in a v2 cgroup.
// See https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html
type MemStat struct {
	// Amount of memory used in anonymous mappings such as brk(),
	// sbrk(), and mmap(MAP_ANONYMOUS)
	AnonBytes uint64

	// Amount of memory used to cache filesystem data, including
	// tmpfs and shared memory.
	FileBytes uint64

	// Amount of memory allocated to kernel stacks.
	KernelStackBytes uint64

	// Amount of memory allocated for page tables.
	PageTablesBytes uint64

	// Amount of memory used for storing per-cpu kernel data
	// structures.
	PerCPUBytes uint64

	// Amount of memory used in network transmission buffers
	SockBytes uint64

	// Amount of cached filesystem data that is swap-backed, such
	// as tmpfs, shm segments, shared anonymous mmap()s
	ShmemBytes uint64

	// Amount of cached filesystem data mapped with mmap()
	FileMappedBytes uint64

	// Amount of cached filesystem data that was modified but not
	// yet written back to disk
	FileDirtyBytes uint64

	// Amount of cached filesystem data that was modified and is
	// currently being written back to disk
	FileWritebackBytes uint64

	// Amount of swap cached in memory. The swapcache is accounted
	// against both memory and swap usage.
	SwapcachedBytes uint64

	// Amount of memory used in anonymous mappings backed by
	// transparent hugepages
	AnonTHPBytes uint64

	// Amount of cached filesystem data backed by transparent
	// hugepages
	FileTHPBytes uint64

	// Amount of shm, tmpfs, shared anonymous mmap()s backed by
	// transparent hugepages
	ShmemTHPBytes uint64

	// Amount of memory, swap-backed and filesystem-backed, on the
	// internal memory management lists used by the page reclaim
	// algorithm. As these represent internal list state
	// (eg. shmem pages are on anon memory management lists),
	// inactive_foo + active_foo may not be equal to the value for
	// the foo counter, since the foo counter is type-based, not
	// list-based.
	InactiveAnonBytes, ActiveAnonBytes, InactiveFileBytes, ActiveFileBytes, UnevictableBytes uint64

	// Part of “slab” that might be reclaimed, such as dentries
	// and inodes.
	SlabReclaimableBytes uint64

	// Part of “slab” that cannot be reclaimed on memory pressure.
	SlabUnreclaimableBytes uint64

	// Amount of memory used for storing in-kernel data
	// structures.
	SlabBytes uint64

	// Number of refaults of previously evicted anonymous pages.
	WorkingsetRefaultAnonBytes uint64

	// Number of refaults of previously evicted file pages.
	WorkingsetRefaultFileBytes uint64

	// Number of refaulted anonymous pages that were immediately
	// activated.
	WorkingsetActivateAnonBytes uint64

	// Number of refaulted file pages that were immediately
	// activated.
	WorkingsetActivateFileBytes uint64

	// Number of restored anonymous pages which have been detected
	// as an active workingset before they got reclaimed.
	WorkingsetRestoreAnonBytes uint64

	// Number of restored file pages which have been detected as
	// an active workingset before they got reclaimed.
	WorkingsetRestoreFileBytes uint64

	// Number of times a shadow node has been reclaimed
	WorkingsetNodeReclaimBytes uint64

	// Total number of page faults incurred
	PgFaultBytes uint64

	// Number of major page faults incurred
	PgMajFaultBytes uint64

	// Amount of scanned pages (in an active LRU list)
	PgRefillBytes uint64

	// Amount of scanned pages (in an inactive LRU list)
	PgScanBytes uint64

	// Amount of reclaimed pages
	PgStealBytes uint64

	// Amount of pages moved to the active LRU list
	PgActivateBytes uint64

	// Amount of pages moved to the inactive LRU list
	PgDeactivateBytes uint64

	// Amount of pages postponed to be freed under memory pressure
	PgLazyFreeBytes uint64

	// Amount of reclaimed lazyfree pages
	PgLazyFreedBytes uint64

	// Number of transparent hugepages which were allocated to
	// satisfy a page fault. This counter is not present when
	// CONFIG_TRANSPARENT_HUGEPAGE is not set.
	THPFaultAllocBytes uint64

	// Number of transparent hugepages which were allocated to
	// allow collapsing an existing range of pages. This counter
	// is not present when CONFIG_TRANSPARENT_HUGEPAGE is not set.
	THPCollapseAllocBytes uint64
}

func parseMemStat(r io.Reader) (*MemStat, error) {
	var m MemStat
	s := bufio.NewScanner(r)
	for s.Scan() {
		// Each line has at least a name and value
		fields := strings.Fields(s.Text())
		if len(fields) < 2 {
			return nil, fmt.Errorf("malformed memory.stat line: %q", s.Text())
		}

		v, err := strconv.ParseUint(fields[1], 0, 64)
		if err != nil {
			return nil, err
		}

		switch fields[0] {
		case "anon":
			m.AnonBytes = v
		case "file":
			m.FileBytes = v
		case "kernel_stack":
			m.KernelStackBytes = v
		case "pagetables":
			m.PageTablesBytes = v
		case "percpu":
			m.PerCPUBytes = v
		case "sock":
			m.SockBytes = v
		case "shmem":
			m.ShmemBytes = v
		case "file_mapped":
			m.FileMappedBytes = v
		case "file_dirty":
			m.FileDirtyBytes = v
		case "file_writeback":
			m.FileWritebackBytes = v
		case "swapcached":
			m.SwapcachedBytes = v
		case "anon_thp":
			m.AnonTHPBytes = v
		case "file_thp":
			m.FileTHPBytes = v
		case "shmem_thp":
			m.ShmemTHPBytes = v
		case "inactive_anon":
			m.InactiveAnonBytes = v
		case "active_anon":
			m.ActiveAnonBytes = v
		case "inactive_file":
			m.InactiveFileBytes = v
		case "active_file":
			m.ActiveFileBytes = v
		case "unevictable":
			m.UnevictableBytes = v
		case "slab_reclaimable":
			m.SlabReclaimableBytes = v
		case "slab_unreclaimable":
			m.SlabUnreclaimableBytes = v
		case "slab":
			m.SlabBytes = v
		case "workingset_refault_anon":
			m.WorkingsetRefaultAnonBytes = v
		case "workingsetRefault_file":
			m.WorkingsetRefaultFileBytes = v
		case "workingset_activate_anon":
			m.WorkingsetActivateAnonBytes = v
		case "workingset_activate_file":
			m.WorkingsetActivateFileBytes = v
		case "workingset_restore_anon":
			m.WorkingsetRestoreAnonBytes = v
		case "workingset_restore_file":
			m.WorkingsetRestoreFileBytes = v
		case "workingset_nodereclaim":
			m.WorkingsetNodeReclaimBytes = v
		case "pgfault":
			m.PgFaultBytes = v
		case "pgmajfault":
			m.PgMajFaultBytes = v
		case "pgrefill":
			m.PgRefillBytes = v
		case "pgscan":
			m.PgScanBytes = v
		case "pgsteal":
			m.PgStealBytes = v
		case "pgactivate":
			m.PgActivateBytes = v
		case "pgdeactivate":
			m.PgDeactivateBytes = v
		case "pglazyfree":
			m.PgLazyFreeBytes = v
		case "pglazyfreed":
			m.PgLazyFreedBytes = v
		case "thp_fault_alloc":
			m.THPFaultAllocBytes = v
		case "thp_collapse_alloc":
			m.THPCollapseAllocBytes = v
		}
	}

	return &m, nil
}

// NewMemStat will locate and read the kernel's cpu accounting info for
// the provided systemd cgroup subpath.
func NewMemStat(cgSubpath string) (MemStat, error) {
	fs, err := NewDefaultFS()
	if err != nil {
		return MemStat{}, err
	}
	return fs.NewMemStat(cgSubpath)
}

// NewMemStat returns an information about cgroup memory statistics.
func (fs FS) NewMemStat(cgSubpath string) (MemStat, error) {
	cgPath, err := fs.cgGetPath("memory", cgSubpath, "memory.stat")
	if err != nil {
		return MemStat{}, errors.Wrapf(err, "unable to get memory controller path")
	}

	b, err := ReadFileNoStat(cgPath)
	if err != nil {
		return MemStat{}, err
	}

	m, err := parseMemStat(bytes.NewReader(b))
	if err != nil {
		return MemStat{}, fmt.Errorf("failed to parse meminfo: %v", err)
	}

	return *m, nil
}
