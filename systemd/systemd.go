package systemd

import (
	"fmt"
	"math"
	"os"

	// Register pprof-over-http handlers
	_ "net/http/pprof"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-systemd/dbus"
	"github.com/pkg/errors"
	"github.com/povilasv/systemd_exporter/cgroup"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"
	"github.com/prometheus/procfs"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

const namespace = "systemd"

var (
	unitWhitelist         = kingpin.Flag("collector.unit-whitelist", "Regexp of systemd units to whitelist. Units must both match whitelist and not match blacklist to be included.").Default(".+").String()
	unitBlacklist         = kingpin.Flag("collector.unit-blacklist", "Regexp of systemd units to blacklist. Units must both match whitelist and not match blacklist to be included.").Default(".+\\.(device)").String()
	systemdPrivate        = kingpin.Flag("collector.private", "Establish a private, direct connection to systemd without dbus.").Bool()
	procPath              = kingpin.Flag("path.procfs", "procfs mountpoint.").Default(procfs.DefaultMountPoint).String()
	enableRestartsMetrics = kingpin.Flag("collector.enable-restart-count", "Enables service restart count metrics. This feature only works with systemd 235 and above.").Bool()
	enableFDMetrics       = kingpin.Flag("collector.enable-file-descriptor-size", "Enables file descriptor size metrics. Systemd Exporter needs access to /proc/X/fd for this to work.").Bool()
)

var unitStatesName = []string{"active", "activating", "deactivating", "inactive", "failed"}

var (
	errGetPropertyMsg           = "couldn't get unit's %s property"
	errConvertUint64PropertyMsg = "couldn't convert unit's %s property %v to uint64"
	errConvertUint32PropertyMsg = "couldn't convert unit's %s property %v to uint32"
	errConvertStringPropertyMsg = "couldn't convert unit's %s property %v to string"
	errUnitMetricsMsg           = "couldn't get unit's metrics: %s"
	errControlGroupReadMsg      = "failed to read %s from control group"
	infoUnitNoHandler           = "no unit type handler for %s"
)

type Collector struct {
	logger                        log.Logger
	unitState                     *prometheus.Desc
	unitInfo                      *prometheus.Desc
	unitStartTimeDesc             *prometheus.Desc
	unitTasksCurrentDesc          *prometheus.Desc
	unitTasksMaxDesc              *prometheus.Desc
	nRestartsDesc                 *prometheus.Desc
	timerLastTriggerDesc          *prometheus.Desc
	socketAcceptedConnectionsDesc *prometheus.Desc
	socketCurrentConnectionsDesc  *prometheus.Desc
	socketRefusedConnectionsDesc  *prometheus.Desc
	cpuTotalDesc                  *prometheus.Desc
	unitCPUTotal                  *prometheus.Desc

	unitMemFileCache      *prometheus.Desc
	unitMemAnon           *prometheus.Desc
	unitMemKernelStack    *prometheus.Desc
	unitMemFileCacheDirty *prometheus.Desc
	unitMemFileMapped     *prometheus.Desc

	openFDs  *prometheus.Desc
	maxFDs   *prometheus.Desc
	vsize    *prometheus.Desc
	maxVsize *prometheus.Desc
	rss      *prometheus.Desc

	unitWhitelistPattern *regexp.Regexp
	unitBlacklistPattern *regexp.Regexp
}

// NewCollector returns a new Collector exposing systemd statistics.
func NewCollector(logger log.Logger) (*Collector, error) {
	// Type is labeled twice e.g. name="foo.service" and type="service" to maintain compatibility
	// with users before we started exporting type label
	unitState := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "unit_state"),
		"Systemd unit", []string{"name", "type", "state"}, nil,
	)
	// TODO think about if we want to have 1) one unit_info metric which has all possible labels
	// for all possible unit type variables (at least, the relatively static ones that we care
	// about such as type, generated-vs-real-unit, etc). Cons: a) huge waste since all these labels
	// have to be set to foo="" on non-relevant types. b) accidental overloading (e.g. we have type
	// label, but it means something differnet for a service vs a mount. Right now it's impossible to
	// detangle that.
	// Option 1) is we have service_info, mount_info, target_info, etc. Many more metrics, but far fewer
	// wasted labels and little chance of semantic confusion. Our current codebase is not tuned for this,
	// we would be adding likt 30% more lines of just boilerplate to declare these different metrics
	// w.r.t. cardinality and performance, option 2 is slightly better performance due to smaller scrape payloads
	// but otherwise (1) and (2) seem similar
	unitInfo := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "unit_info"),
		"Mostly-static metadata for all unit types",
		[]string{"name", "type", "mount_type", "service_type"}, nil,
	)
	unitStartTimeDesc := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "unit_start_time_seconds"),
		"Start time of the unit since unix epoch in seconds.",
		[]string{"name", "type"}, nil,
	)
	unitTasksCurrentDesc := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "unit_tasks_current"),
		"Current number of tasks per Systemd unit",
		[]string{"name"}, nil,
	)
	unitTasksMaxDesc := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "unit_tasks_max"),
		"Maximum number of tasks per Systemd unit",
		[]string{"name", "type"}, nil,
	)
	nRestartsDesc := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "service_restart_total"),
		"Service unit count of Restart triggers", []string{"state"}, nil)
	timerLastTriggerDesc := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "timer_last_trigger_seconds"),
		"Seconds since epoch of last trigger.", []string{"name"}, nil)
	socketAcceptedConnectionsDesc := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "socket_accepted_connections_total"),
		"Total number of accepted socket connections", []string{"name"}, nil)
	socketCurrentConnectionsDesc := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "socket_current_connections"),
		"Current number of socket connections", []string{"name"}, nil)
	socketRefusedConnectionsDesc := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "socket_refused_connections_total"),
		"Total number of refused socket connections", []string{"name"}, nil)

	cpuTotalDesc := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "process_cpu_seconds_total"),
		"Total user and system CPU time spent in seconds.",
		[]string{"name"}, nil,
	)
	// We could add a cpu label, but IMO that could cause a cardinality explosion. We already export
	// two modes per unit (user/system), and on a modest 4 core machine adding a cpu label would cause us to export 8 metics
	// e.g. (2 modes * 4 cores) per enabled unit
	unitCPUTotal := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "unit_cpu_seconds_total"),
		"Unit CPU time in seconds",
		[]string{"name", "type", "mode"}, nil,
	)

	unitMemFileCache := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "unit_file_cache_bytes"),
		"Unit bytes used to cache filesystem data, including tmpfs and shared memory",
		[]string{"name", "type"}, nil,
	)
	unitMemAnon := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "unit_anon_bytes"),
		"Unit bytes used in anonymous mappings such as mmap(MAP_ANONYMOUS)",
		[]string{"name", "type"}, nil,
	)
	unitMemKernelStack := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "unit_kernel_stack_bytes"),
		"Unit bytes allocated to kernel stacks",
		[]string{"name", "type"}, nil,
	)
	unitMemFileCacheDirty := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "unit_file_cache_dirty_bytes"),
		"Unit bytes waiting to get written to disk",
		[]string{"name", "type"}, nil,
	)
	unitMemFileMapped := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "unit_file_mapped_bytes"),
		"Unit bytes of cached filesystem data mapped with mmap()",
		[]string{"name", "type"}, nil,
	)

	openFDs := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "process_open_fds"),
		"Number of open file descriptors.",
		[]string{"name"}, nil,
	)

	maxFDs := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "process_max_fds"),
		"Maximum number of open file descriptors.",
		[]string{"name"}, nil,
	)
	vsize := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "process_virtual_memory_bytes"),
		"Virtual memory size in bytes.",
		[]string{"name"}, nil,
	)

	maxVsize := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "process_virtual_memory_max_bytes"),
		"Maximum amount of virtual memory available in bytes.",
		[]string{"name"}, nil,
	)

	rss := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "process_resident_memory_bytes"),
		"Resident memory size in bytes.",
		[]string{"name"}, nil,
	)
	unitWhitelistPattern := regexp.MustCompile(fmt.Sprintf("^(?:%s)$", *unitWhitelist))
	unitBlacklistPattern := regexp.MustCompile(fmt.Sprintf("^(?:%s)$", *unitBlacklist))

	return &Collector{
		logger:                        logger,
		unitState:                     unitState,
		unitInfo:                      unitInfo,
		unitStartTimeDesc:             unitStartTimeDesc,
		unitTasksCurrentDesc:          unitTasksCurrentDesc,
		unitTasksMaxDesc:              unitTasksMaxDesc,
		nRestartsDesc:                 nRestartsDesc,
		timerLastTriggerDesc:          timerLastTriggerDesc,
		socketAcceptedConnectionsDesc: socketAcceptedConnectionsDesc,
		socketCurrentConnectionsDesc:  socketCurrentConnectionsDesc,
		socketRefusedConnectionsDesc:  socketRefusedConnectionsDesc,
		cpuTotalDesc:                  cpuTotalDesc,
		unitCPUTotal:                  unitCPUTotal,
		unitMemFileCache:              unitMemFileCache,
		unitMemAnon:                   unitMemAnon,
		unitMemKernelStack:            unitMemKernelStack,
		unitMemFileCacheDirty:         unitMemFileCacheDirty,
		unitMemFileMapped:             unitMemFileMapped,
		openFDs:                       openFDs,
		maxFDs:                        maxFDs,
		vsize:                         vsize,
		maxVsize:                      maxVsize,
		rss:                           rss,
		unitWhitelistPattern:          unitWhitelistPattern,
		unitBlacklistPattern:          unitBlacklistPattern,
	}, nil
}

// Collect gathers metrics from systemd.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	err := c.collect(ch)
	if err != nil {
		c.logger.Error(err)
	}
}

// Describe gathers descriptions of Metrics
func (c *Collector) Describe(desc chan<- *prometheus.Desc) {
	desc <- c.unitState
	desc <- c.unitInfo
	desc <- c.unitStartTimeDesc
	desc <- c.unitTasksCurrentDesc
	desc <- c.unitTasksMaxDesc
	desc <- c.nRestartsDesc
	desc <- c.timerLastTriggerDesc
	desc <- c.socketAcceptedConnectionsDesc
	desc <- c.socketCurrentConnectionsDesc
	desc <- c.socketRefusedConnectionsDesc
	desc <- c.cpuTotalDesc
	desc <- c.openFDs
	desc <- c.maxFDs
	desc <- c.vsize
	desc <- c.maxVsize
	desc <- c.rss
}

func parseUnitType(unit dbus.UnitStatus) string {
	t := strings.Split(unit.Name, ".")
	return t[len(t)-1]
}

// parseUnitTypeInterface extracts the dbus interface suffix for the interface unique to the passed unit type.
// For example, a systemd "service unit" will be are exposed on dbus as "service objects", and all "service objects"
// implement the org.freedesktop.systemd1.Service interface. This is used as input for dbus.GetUnitTypeProperty
func parseUnitTypeInterface(unit dbus.UnitStatus) string {
	return strings.Title(parseUnitType(unit))
}

func (c *Collector) collect(ch chan<- prometheus.Metric) error {
	begin := time.Now()
	conn, err := c.newDbus()
	if err != nil {
		return errors.Wrapf(err, "couldn't get dbus connection")
	}
	defer conn.Close()

	allUnits, err := conn.ListUnits()
	if err != nil {
		return errors.Wrap(err, "could not get list of systemd units from dbus")
	}

	c.logger.Debugf("systemd ListUnits took %f", time.Since(begin).Seconds())
	begin = time.Now()
	units := filterUnits(allUnits, c.unitWhitelistPattern, c.unitBlacklistPattern)
	c.logger.Debugf("systemd filterUnits took %f", time.Since(begin).Seconds())

	var wg sync.WaitGroup
	wg.Add(len(units))
	for _, unit := range units {
		go func(unit dbus.UnitStatus) {
			err := c.collectUnit(conn, ch, unit)
			if err != nil {
				c.logger.Warnf(errUnitMetricsMsg, err)
			}
			wg.Done()
		}(unit)
	}

	wg.Wait()
	return nil
}

func (c *Collector) collectUnit(conn *dbus.Conn, ch chan<- prometheus.Metric, unit dbus.UnitStatus) error {

	logger := c.logger.With("unit", unit.Name)

	// Collect unit_state for all unit types
	err := c.collectUnitState(conn, ch, unit)
	if err != nil {
		logger.Warnf(errUnitMetricsMsg, err)
		// TODO should we continue processing here?
	}

	// Collect metrics from cgroups
	switch parseUnitType(unit) {
	case "service", "mount", "socket", "swap", "slice":
		cgroupPath, err := c.getControlGroup(conn, unit)
		if err != nil {
			if parseUnitType(unit) == "mount" {
				break
			}
			remainAfterExitProperty, getPropErr := conn.GetUnitTypeProperty(unit.Name, "Service", "RemainAfterExit")
			if getPropErr == nil {
				remainAfterExit, ok := remainAfterExitProperty.Value.Value().(bool)
				if ok && remainAfterExit {
					break
				}
			}
			logger.Warnf(errUnitMetricsMsg, err)
		}
		// Everything below requires a cgroup
		if cgroupPath == nil {
			break
		}
		err = c.collectUnitCPUMetrics(*cgroupPath, conn, ch, unit)
		if err != nil {
			// Most sockets do not have a cpu cgroupfs entry, but a few big ones do (notably docker.socket). Quiet down
			// error reporting if error came from a socket
			if parseUnitType(unit) != "socket" {
				logger.Warnf(errUnitMetricsMsg, err)
			}
		}
		err = c.collectUnitMemMetrics(*cgroupPath, conn, ch, unit)
		if err != nil {
			logger.Warnf(errUnitMetricsMsg, err)
		}
	}

	// Collect metrics from dbus
	switch parseUnitType(unit) {
	case "service":
		err = c.collectServiceMetainfo(conn, ch, unit)
		if err != nil {
			logger.Warnf(errUnitMetricsMsg, err)
		}
		err = c.collectServiceStartTimeMetrics(conn, ch, unit)
		if err != nil {
			logger.Warnf(errUnitMetricsMsg, err)
		}
		if *enableRestartsMetrics {
			err = c.collectServiceRestartCount(conn, ch, unit)
			if err != nil {
				logger.Warnf(errUnitMetricsMsg, err)
			}
		}
		err = c.collectServiceTasksMetrics(conn, ch, unit)
		if err != nil {
			logger.Warnf(errUnitMetricsMsg, err)
		}
		err = c.collectServiceProcessMetrics(conn, ch, unit)
		if err != nil {
			logger.Warnf(errUnitMetricsMsg, err)
		}
	case "mount":
		err = c.collectMountMetainfo(conn, ch, unit)
		if err != nil {
			logger.Warnf(errUnitMetricsMsg, err)
		}
	case "timer":
		err := c.collectTimerTriggerTime(conn, ch, unit)
		if err != nil {
			logger.Warnf(errUnitMetricsMsg, err)
		}
	case "socket":
		err := c.collectSocketConnMetrics(conn, ch, unit)
		if err != nil {
			logger.Warnf(errUnitMetricsMsg, err)
		}
	default:
		c.logger.Debugf(infoUnitNoHandler, unit.Name)
	}

	return nil
}

func (c *Collector) collectUnitState(conn *dbus.Conn, ch chan<- prometheus.Metric, unit dbus.UnitStatus) error {
	//TODO: wrap GetUnitTypePropertyString(
	// serviceTypeProperty, err := conn.GetUnitTypeProperty(unit.Name, "Timer", "NextElapseUSecMonotonic")

	for _, stateName := range unitStatesName {
		isActive := 0.0
		if stateName == unit.ActiveState {
			isActive = 1.0
		}
		ch <- prometheus.MustNewConstMetric(
			c.unitState, prometheus.GaugeValue, isActive,
			unit.Name, parseUnitType(unit), stateName)
	}

	return nil
}

// TODO metric is named unit but function is "Mount"
func (c *Collector) collectMountMetainfo(conn *dbus.Conn, ch chan<- prometheus.Metric, unit dbus.UnitStatus) error {
	//TODO: wrap GetUnitTypePropertyString(
	serviceTypeProperty, err := conn.GetUnitTypeProperty(unit.Name, "Mount", "Type")
	if err != nil {
		return errors.Wrapf(err, errGetPropertyMsg, "Type")
	}

	serviceType, ok := serviceTypeProperty.Value.Value().(string)
	if !ok {
		return errors.Errorf(errConvertStringPropertyMsg, "Type", serviceTypeProperty.Value.Value())
	}

	ch <- prometheus.MustNewConstMetric(
		c.unitInfo, prometheus.GaugeValue, 1.0,
		unit.Name, parseUnitType(unit), serviceType, "")

	return nil
}

// TODO the metric is named unit_info but function is named "Service"
func (c *Collector) collectServiceMetainfo(conn *dbus.Conn, ch chan<- prometheus.Metric, unit dbus.UnitStatus) error {
	serviceTypeProperty, err := conn.GetUnitTypeProperty(unit.Name, "Service", "Type")
	if err != nil {
		return errors.Wrapf(err, errGetPropertyMsg, "Type")
	}
	serviceType, ok := serviceTypeProperty.Value.Value().(string)
	if !ok {
		return errors.Errorf(errConvertStringPropertyMsg, "Type", serviceTypeProperty.Value.Value())
	}

	ch <- prometheus.MustNewConstMetric(
		c.unitInfo, prometheus.GaugeValue, 1.0,
		unit.Name, parseUnitType(unit), "", serviceType)
	return nil
}

func (c *Collector) collectServiceRestartCount(conn *dbus.Conn, ch chan<- prometheus.Metric, unit dbus.UnitStatus) error {
	restartsCount, err := conn.GetUnitTypeProperty(unit.Name, "Service", "NRestarts")
	if err != nil {
		return errors.Wrapf(err, errGetPropertyMsg, "NRestarts")
	}
	val, ok := restartsCount.Value.Value().(uint32)
	if !ok {
		return errors.Errorf(errConvertUint32PropertyMsg, "NRestarts", restartsCount.Value.Value())
	}
	ch <- prometheus.MustNewConstMetric(
		c.nRestartsDesc, prometheus.CounterValue,
		float64(val), unit.Name)
	return nil
}

// TODO metric is named unit but function is "Service"
func (c *Collector) collectServiceStartTimeMetrics(conn *dbus.Conn, ch chan<- prometheus.Metric, unit dbus.UnitStatus) error {
	var startTimeUsec uint64

	switch unit.ActiveState {
	case "active":
		timestampValue, err := conn.GetUnitProperty(unit.Name, "ActiveEnterTimestamp")
		if err != nil {
			return errors.Wrapf(err, errGetPropertyMsg, "ActiveEnterTimestamp")
		}
		startTime, ok := timestampValue.Value.Value().(uint64)
		if !ok {
			return errors.Errorf(errConvertUint64PropertyMsg, "ActiveEnterTimestamp", timestampValue.Value.Value())
		}
		startTimeUsec = startTime

	default:
		startTimeUsec = 0
	}

	ch <- prometheus.MustNewConstMetric(
		c.unitStartTimeDesc, prometheus.GaugeValue,
		float64(startTimeUsec)/1e6, unit.Name, parseUnitType(unit))

	return nil
}

func (c *Collector) collectServiceProcessMetrics(conn *dbus.Conn, ch chan<- prometheus.Metric, unit dbus.UnitStatus) error {
	// TODO: ExecStart type property, has a slice with process information.
	// When systemd manages multiple processes, maybe we should add them all?

	mainPID, err := conn.GetUnitTypeProperty(unit.Name, "Service", "MainPID")
	if err != nil {
		return errors.Wrapf(err, errGetPropertyMsg, "MainPID")
	}

	pid, ok := mainPID.Value.Value().(uint32)
	if !ok {
		return errors.Errorf(errConvertUint32PropertyMsg, "MainPID", mainPID.Value.Value())
	}

	// MainPID 0 when the service currently has no main PID
	if pid == 0 {
		return nil
	}

	fs, err := procfs.NewFS(*procPath)
	if err != nil {
		return err
	}
	p, err := fs.NewProc(int(pid))
	if err != nil {
		return err
	}

	stat, err := p.NewStat()
	if err != nil {
		return err
	}

	ch <- prometheus.MustNewConstMetric(
		c.cpuTotalDesc, prometheus.CounterValue,
		stat.CPUTime(), unit.Name)
	ch <- prometheus.MustNewConstMetric(c.vsize, prometheus.GaugeValue,
		float64(stat.VirtualMemory()), unit.Name)
	ch <- prometheus.MustNewConstMetric(c.rss, prometheus.GaugeValue,
		float64(stat.ResidentMemory()), unit.Name)

	limits, err := p.NewLimits()
	if err != nil {
		return errors.Wrap(err, "couldn't get process limits")
	}
	ch <- prometheus.MustNewConstMetric(c.maxFDs, prometheus.GaugeValue,
		float64(limits.OpenFiles), unit.Name)
	ch <- prometheus.MustNewConstMetric(c.maxVsize, prometheus.GaugeValue,
		float64(limits.AddressSpace), unit.Name)

	if *enableFDMetrics {
		fds, err := p.FileDescriptorsLen()
		if err != nil {
			return errors.Wrap(err, "couldn't get process file descriptor size")
		}
		ch <- prometheus.MustNewConstMetric(c.openFDs, prometheus.GaugeValue,
			float64(fds), unit.Name)
	}

	return nil
}

func (c *Collector) mustGetUnitStringTypeProperty(unitType string,
	propName string, defaultVal string, conn *dbus.Conn, unit dbus.UnitStatus) string {

	prop, err := conn.GetUnitTypeProperty(unit.Name, unitType, propName)
	if err != nil {
		c.logger.Debugf(errGetPropertyMsg, propName)
		return defaultVal
	}
	propVal, ok := prop.Value.Value().(string)
	if !ok {
		c.logger.Debugf(errConvertStringPropertyMsg, propName, prop.Value.Value())
		return defaultVal
	}
	return propVal
}

func (c *Collector) getControlGroup(conn *dbus.Conn, unit dbus.UnitStatus) (*string, error) {
	unitTypeInterface := parseUnitTypeInterface(unit)
	propCGSubpath, err := conn.GetUnitTypeProperty(unit.Name, unitTypeInterface, "ControlGroup")
	if err != nil {
		return nil, errors.Wrapf(err, errGetPropertyMsg, "ControlGroup")
	}
	cgSubpath, ok := propCGSubpath.Value.Value().(string)
	if !ok {
		return nil, errors.Errorf(errConvertStringPropertyMsg, "ControlGroup", propCGSubpath.Value.Value())
	}

	switch {
	case cgSubpath == "" && unit.ActiveState == "inactive",
		cgSubpath == "" && unit.ActiveState == "failed":
		// Expected condition, systemd has cleaned up and
		// we have nothing to record
		return nil, nil
	case cgSubpath == "" && unit.ActiveState == "active":
		// Unexpected. Why is there no cgroup on an active unit?
		subType := c.mustGetUnitStringTypeProperty(unitTypeInterface, "Type", "unknown", conn, unit)
		slice := c.mustGetUnitStringTypeProperty(unitTypeInterface, "Slice", "unknown", conn, unit)
		return nil, errors.Errorf("got 'no cgroup' from systemd for active unit (state=%s subtype=%s slice=%s)", unit.ActiveState, subType, slice)
	case cgSubpath == "":
		// We are likely reading a unit that is currently changing state, so
		// we record this and bail
		subType := c.mustGetUnitStringTypeProperty(unitTypeInterface, "Type", "unknown", conn, unit)
		slice := c.mustGetUnitStringTypeProperty(unitTypeInterface, "Slice", "unknown", conn, unit)
		log.Debugf("Read 'no cgroup' from unit (name=%s state=%s subtype=%s slice=%s) ", unit.Name, unit.ActiveState, subType, slice)
		return nil, nil
	default:
		return &cgSubpath, nil
	}
}

// A number of unit types support the 'ControlGroup' property needed to allow us to directly read their
// resource usage from the kernel's cgroupfs cpu hierarchy. The only change is which dbus item we are querying
func (c *Collector) collectUnitCPUMetrics(cgSubpath string, conn *dbus.Conn, ch chan<- prometheus.Metric, unit dbus.UnitStatus) error {
	// Don't bother reading CPUAccounting prop. It's faster to attempt a file read than to query dbus, and it works
	// in more situations as well
	cpuUsage, err := cgroup.NewCPUAcct(cgSubpath)
	if err != nil {
		if perr, ok := err.(*os.PathError); ok && perr.Op == "open" {
			return nil
		}
		return errors.Wrapf(err, errControlGroupReadMsg, "CPU usage")
	}

	userSeconds := float64(cpuUsage.UserMicrosec) / 1_000_000.0
	sysSeconds := float64(cpuUsage.SystemMicrosec) / 1_000_000.0

	ch <- prometheus.MustNewConstMetric(
		c.unitCPUTotal, prometheus.CounterValue,
		userSeconds, unit.Name, parseUnitType(unit), "user")
	ch <- prometheus.MustNewConstMetric(
		c.unitCPUTotal, prometheus.CounterValue,
		sysSeconds, unit.Name, parseUnitType(unit), "system")

	return nil
}

func (c *Collector) collectUnitMemMetrics(cgSubpath string, conn *dbus.Conn, ch chan<- prometheus.Metric, unit dbus.UnitStatus) error {
	// Don't bother reading MemoryAccounting prop. It's faster to attempt a file read than to query dbus, and it works
	// in more situations as well. For ex: case where
	// such as kernel cmdline has cgroups_enabled=memory but systemd still has DefaultMemoryAccounting=no. All cgroups
	// will have a memory.stat file, but systemd will still report MemoryAccounting=false for most units
	memStat, err := cgroup.NewMemStat(cgSubpath)
	if err != nil {
		if perr, ok := err.(*os.PathError); ok && perr.Op == "open" {
			return nil
		}
		return errors.Wrapf(err, errControlGroupReadMsg, "Memory stat")
	}

	unitType := parseUnitType(unit)
	ch <- prometheus.MustNewConstMetric(
		c.unitMemFileCache, prometheus.GaugeValue,
		float64(memStat.FileBytes), unit.Name, unitType)
	ch <- prometheus.MustNewConstMetric(
		c.unitMemAnon, prometheus.GaugeValue,
		float64(memStat.AnonBytes), unit.Name, unitType)
	ch <- prometheus.MustNewConstMetric(
		c.unitMemKernelStack, prometheus.GaugeValue,
		float64(memStat.KernelStackBytes), unit.Name, unitType)
	ch <- prometheus.MustNewConstMetric(
		c.unitMemFileCacheDirty, prometheus.GaugeValue,
		float64(memStat.FileDirtyBytes), unit.Name, unitType)
	ch <- prometheus.MustNewConstMetric(
		c.unitMemFileMapped, prometheus.GaugeValue,
		float64(memStat.FileMappedBytes), unit.Name, unitType)

	return nil
}

func (c *Collector) collectSocketConnMetrics(conn *dbus.Conn, ch chan<- prometheus.Metric, unit dbus.UnitStatus) error {
	acceptedConnectionCount, err := conn.GetUnitTypeProperty(unit.Name, "Socket", "NAccepted")
	if err != nil {
		return errors.Wrapf(err, errGetPropertyMsg, "NAccepted")
	}

	ch <- prometheus.MustNewConstMetric(
		c.socketAcceptedConnectionsDesc, prometheus.CounterValue,
		float64(acceptedConnectionCount.Value.Value().(uint32)), unit.Name)

	currentConnectionCount, err := conn.GetUnitTypeProperty(unit.Name, "Socket", "NConnections")
	if err != nil {
		return errors.Wrapf(err, errGetPropertyMsg, "NConnections")
	}
	ch <- prometheus.MustNewConstMetric(
		c.socketCurrentConnectionsDesc, prometheus.GaugeValue,
		float64(currentConnectionCount.Value.Value().(uint32)), unit.Name)

	// NRefused wasn't added until systemd 239.
	refusedConnectionCount, err := conn.GetUnitTypeProperty(unit.Name, "Socket", "NRefused")
	if err != nil {
		return errors.Wrapf(err, errGetPropertyMsg, "NRefused")
	}
	ch <- prometheus.MustNewConstMetric(
		c.socketRefusedConnectionsDesc, prometheus.CounterValue,
		float64(refusedConnectionCount.Value.Value().(uint32)), unit.Name)

	return nil
}

// TODO either the unit should be called service_tasks, or it should work for all
// units. It's currently named unit_task
func (c *Collector) collectServiceTasksMetrics(conn *dbus.Conn, ch chan<- prometheus.Metric, unit dbus.UnitStatus) error {
	tasksCurrentCount, err := conn.GetUnitTypeProperty(unit.Name, "Service", "TasksCurrent")
	if err != nil {
		return errors.Wrapf(err, errGetPropertyMsg, "TasksCurrent")
	}

	currentCount, ok := tasksCurrentCount.Value.Value().(uint64)
	if !ok {
		return errors.Errorf(errConvertUint64PropertyMsg, "TasksCurrent", tasksCurrentCount.Value.Value())
	}

	// Don't set if tasksCurrent if dbus reports MaxUint64.
	if currentCount != math.MaxUint64 {
		ch <- prometheus.MustNewConstMetric(
			c.unitTasksCurrentDesc, prometheus.GaugeValue,
			float64(currentCount), unit.Name)
	}

	tasksMaxCount, err := conn.GetUnitTypeProperty(unit.Name, "Service", "TasksMax")
	if err != nil {
		return errors.Wrapf(err, errGetPropertyMsg, "TasksMax")
	}

	maxCount, ok := tasksMaxCount.Value.Value().(uint64)
	if !ok {
		return errors.Errorf(errConvertUint64PropertyMsg, "TasksMax", tasksMaxCount.Value.Value())
	}
	// Don't set if tasksMax if dbus reports MaxUint64.
	if maxCount != math.MaxUint64 {
		ch <- prometheus.MustNewConstMetric(
			c.unitTasksMaxDesc, prometheus.GaugeValue,
			float64(maxCount), unit.Name, parseUnitType(unit))
	}

	return nil
}

func (c *Collector) collectTimerTriggerTime(conn *dbus.Conn, ch chan<- prometheus.Metric, unit dbus.UnitStatus) error {
	lastTriggerValue, err := conn.GetUnitTypeProperty(unit.Name, "Timer", "LastTriggerUSec")
	if err != nil {
		return errors.Wrapf(err, errGetPropertyMsg, "LastTriggerUSec")
	}
	val, ok := lastTriggerValue.Value.Value().(uint64)
	if !ok {
		return errors.Errorf(errConvertUint64PropertyMsg, "LastTriggerUSec", lastTriggerValue.Value.Value())
	}
	ch <- prometheus.MustNewConstMetric(
		c.timerLastTriggerDesc, prometheus.GaugeValue,
		float64(val)/1e6, unit.Name)
	return nil
}

func (c *Collector) newDbus() (*dbus.Conn, error) {
	if *systemdPrivate {
		return dbus.NewSystemdConnection()
	}
	return dbus.New()
}

func filterUnits(units []dbus.UnitStatus, whitelistPattern, blacklistPattern *regexp.Regexp) []dbus.UnitStatus {
	filtered := make([]dbus.UnitStatus, 0, len(units))
	for _, unit := range units {
		if whitelistPattern.MatchString(unit.Name) &&
			!blacklistPattern.MatchString(unit.Name) &&
			unit.LoadState == "loaded" {

			log.Debugf("Adding unit: %s", unit.Name)
			filtered = append(filtered, unit)
		} else {
			log.Debugf("Ignoring unit: %s", unit.Name)
		}
	}

	return filtered
}
