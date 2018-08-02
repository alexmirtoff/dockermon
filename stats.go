/*

(c) 2018 Alex Mirtoff
mailto: alex@mirtoff.ru

*/
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	. "github.com/adubkov/go-zabbix"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/julienschmidt/httprouter"
	"github.com/zpatrick/go-config"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// Logging var declare
var (
	Log *log.Logger
)

const (

	PVersion = "0.1-RELEASE"

)


// Docker API STAT JSON Struct
type ContainerStats struct {
	Read      time.Time `json:"read"`
	Preread   time.Time `json:"preread"`
	PidsStats struct {
		Current int `json:"current"`
	} `json:"pids_stats"`
	BlkioStats struct {
		IoServiceBytesRecursive []interface{} `json:"io_service_bytes_recursive"`
		IoServicedRecursive     []interface{} `json:"io_serviced_recursive"`
		IoQueueRecursive        []interface{} `json:"io_queue_recursive"`
		IoServiceTimeRecursive  []interface{} `json:"io_service_time_recursive"`
		IoWaitTimeRecursive     []interface{} `json:"io_wait_time_recursive"`
		IoMergedRecursive       []interface{} `json:"io_merged_recursive"`
		IoTimeRecursive         []interface{} `json:"io_time_recursive"`
		SectorsRecursive        []interface{} `json:"sectors_recursive"`
	} `json:"blkio_stats"`
	NumProcs     int `json:"num_procs"`
	StorageStats struct {
	} `json:"storage_stats"`
	CPUStats struct {
		CPUUsage struct {
			TotalUsage        int   `json:"total_usage"`
			PercpuUsage       []int `json:"percpu_usage"`
			UsageInKernelmode int   `json:"usage_in_kernelmode"`
			UsageInUsermode   int   `json:"usage_in_usermode"`
		} `json:"cpu_usage"`
		SystemCPUUsage int64 `json:"system_cpu_usage"`
		ThrottlingData struct {
			Periods          int `json:"periods"`
			ThrottledPeriods int `json:"throttled_periods"`
			ThrottledTime    int `json:"throttled_time"`
		} `json:"throttling_data"`
	} `json:"cpu_stats"`
	PrecpuStats struct {
		CPUUsage struct {
			TotalUsage        int   `json:"total_usage"`
			PercpuUsage       []int `json:"percpu_usage"`
			UsageInKernelmode int   `json:"usage_in_kernelmode"`
			UsageInUsermode   int   `json:"usage_in_usermode"`
		} `json:"cpu_usage"`
		SystemCPUUsage int64 `json:"system_cpu_usage"`
		ThrottlingData struct {
			Periods          int `json:"periods"`
			ThrottledPeriods int `json:"throttled_periods"`
			ThrottledTime    int `json:"throttled_time"`
		} `json:"throttling_data"`
	} `json:"precpu_stats"`
	MemoryStats struct {
		Usage    int `json:"usage"`
		MaxUsage int `json:"max_usage"`
		Stats    struct {
			ActiveAnon              int   `json:"active_anon"`
			ActiveFile              int   `json:"active_file"`
			Cache                   int   `json:"cache"`
			HierarchicalMemoryLimit int64 `json:"hierarchical_memory_limit"`
			HierarchicalMemswLimit  int64 `json:"hierarchical_memsw_limit"`
			InactiveAnon            int   `json:"inactive_anon"`
			InactiveFile            int   `json:"inactive_file"`
			MappedFile              int   `json:"mapped_file"`
			Pgfault                 int   `json:"pgfault"`
			Pgmajfault              int   `json:"pgmajfault"`
			Pgpgin                  int   `json:"pgpgin"`
			Pgpgout                 int   `json:"pgpgout"`
			Rss                     int   `json:"rss"`
			RssHuge                 int   `json:"rss_huge"`
			Swap                    int   `json:"swap"`
			TotalActiveAnon         int   `json:"total_active_anon"`
			TotalActiveFile         int   `json:"total_active_file"`
			TotalCache              int   `json:"total_cache"`
			TotalInactiveAnon       int   `json:"total_inactive_anon"`
			TotalInactiveFile       int   `json:"total_inactive_file"`
			TotalMappedFile         int   `json:"total_mapped_file"`
			TotalPgfault            int   `json:"total_pgfault"`
			TotalPgmajfault         int   `json:"total_pgmajfault"`
			TotalPgpgin             int   `json:"total_pgpgin"`
			TotalPgpgout            int   `json:"total_pgpgout"`
			TotalRss                int   `json:"total_rss"`
			TotalRssHuge            int   `json:"total_rss_huge"`
			TotalSwap               int   `json:"total_swap"`
			TotalUnevictable        int   `json:"total_unevictable"`
			Unevictable             int   `json:"unevictable"`
		} `json:"stats"`
		Limit int `json:"limit"`
	} `json:"memory_stats"`
	Name     string `json:"name"`
	ID       string `json:"id"`
	Networks struct {
		Eth0 struct {
			RxBytes   int `json:"rx_bytes"`
			RxPackets int `json:"rx_packets"`
			RxErrors  int `json:"rx_errors"`
			RxDropped int `json:"rx_dropped"`
			TxBytes   int `json:"tx_bytes"`
			TxPackets int `json:"tx_packets"`
			TxErrors  int `json:"tx_errors"`
			TxDropped int `json:"tx_dropped"`
		} `json:"eth0"`
	} `json:"networks"`
}

// Slice of maps type, lol
type M map[string]string

// Start here
func main() {

	// Init config
	iniFile := config.NewINIFile("config.ini")
	cfg := config.NewConfig([]config.Provider{iniFile})

	if err := cfg.Load(); err != nil {
		log.Fatal(err)
	}

	// Global vars from config.ini here
	logfile, err := cfg.String("common.logfile")
	getStatsTimer, err := cfg.Int("timers.getstats")
	zabbixServer, err := cfg.String("zabbix.server")
	zabbixPort, err := cfg.Int("zabbix.port")
	zabbixHost, err := cfg.String("zabbix.hostname")
	webPort, err := cfg.String("web.port")

	// New client
	cli, err := client.NewEnvClient()
	if err != nil {
		panic(err)
	}

	// Logging:
	f, err := os.OpenFile(logfile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer f.Close()
	log.SetOutput(f)

	// Starting goroutines in channel here
	done := make(chan bool)
	log.Println("Starting...")
	go startHttp(cli, webPort)
	go startDockerReqAgent(cli, getStatsTimer, zabbixServer, zabbixPort, zabbixHost)
	<-done
}

func getVersion() {
	fmt.Printf("Version %v\n", PVersion)
	fmt.Println("© 2018 Alex Mirtoff, mailto: alex@mirtoff.ru\n")

}


// HTTP Server goroutine
func startHttp(cli *client.Client, webPort string) {

	r := httprouter.New()
	r.GET("/zabbix/containers/list", getIndexWithSettings(cli))
	webPort = fmt.Sprintf(":%s", webPort)
	http.ListenAndServe(webPort, r)

}

// Construct JSON reply for Zabbix discovery (containers list)
func zabbixDiscoveryGenJSON(cli *client.Client) string {
	var myMapSlice []M // use this for slicing the maps
	for _, cnt := range getContainers(cli) {
		tmpMap := make(map[string]string)
		for id, name := range cnt {
			//fmt.Println(name)
			tmpMap["{#CONTNAME}"] = name
			tmpMap["{#CONTID}"] = id
			myMapSlice = append(myMapSlice, tmpMap)
		}

	}
	contJSON, _ := json.Marshal(myMapSlice)
	contStr := string(contJSON)
	return fmt.Sprintf("{\"data\":%s}", contStr)
}

// HTTP Handler
func getIndexWithSettings(cli *client.Client) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		w.Header().Set("Content-Type", "application/json")
		message := r.URL.Path
		message = strings.TrimPrefix(message, "/")
		message = zabbixDiscoveryGenJSON(cli)
		w.Write([]byte(message))
	}
}

// Docker Request info goroutine
func startDockerReqAgent(cli *client.Client, getStatsTimer int, zabbixServer string, zabbixPort int, zabbixHost string) {
	for {
		statsMap := make(map[string][]string)
		c := getContainers(cli)
		for _, cnt := range c {
			for k, _ := range cnt {
				st := jsonMapGen(getStat(cli, k, false))
				for l := range st {
					log.Printf("GET: %v", st)
					if checkStatus(cli, st[l].ID[:10]) {
						statsMap[st[l].ID[:10]] = append(statsMap[st[l].ID[:10]], st[l].Name, strconv.Itoa(st[l].PidsStats.Current), strconv.Itoa(st[l].CPUStats.CPUUsage.TotalUsage),
							strconv.FormatInt(st[l].CPUStats.SystemCPUUsage, 10), strconv.Itoa(st[l].MemoryStats.Usage), strconv.Itoa(st[l].MemoryStats.MaxUsage),
							strconv.Itoa(st[l].MemoryStats.Stats.ActiveAnon), strconv.Itoa(st[l].MemoryStats.Stats.Cache), strconv.Itoa(st[l].MemoryStats.Stats.InactiveAnon),
							strconv.Itoa(st[l].MemoryStats.Stats.Rss), strconv.Itoa(st[l].MemoryStats.Stats.Swap), strconv.Itoa(st[l].MemoryStats.Stats.TotalActiveAnon),
							strconv.Itoa(st[l].MemoryStats.Stats.TotalInactiveAnon), strconv.Itoa(st[l].MemoryStats.Stats.TotalRss), strconv.Itoa(st[l].MemoryStats.Limit),
							strconv.Itoa(st[l].Networks.Eth0.RxBytes), strconv.Itoa(st[l].Networks.Eth0.RxPackets), strconv.Itoa(st[l].Networks.Eth0.RxErrors),
							strconv.Itoa(st[l].Networks.Eth0.RxDropped), strconv.Itoa(st[l].Networks.Eth0.TxBytes), strconv.Itoa(st[l].Networks.Eth0.TxPackets),
							strconv.Itoa(st[l].Networks.Eth0.TxErrors), strconv.Itoa(st[l].Networks.Eth0.TxDropped))
					}
				}
			}
		}
		// Send to Zabbix
		zabbixSend(statsMap, zabbixServer, zabbixPort, zabbixHost)
		time.Sleep(time.Duration(getStatsTimer) * time.Second)
	}

}

// Get container's stat
func getStat(cli *client.Client, cnt string, stream bool) string {
	out, err := cli.ContainerStats(context.Background(), cnt, stream)
	if err != nil {
		panic(err)
	}

	buf := new(bytes.Buffer)
	buf.ReadFrom(out.Body)

	return buf.String()
}

// Get containters list
func getContainers(cli *client.Client) map[int]map[string]string {

	containers, err := cli.ContainerList(context.Background(), types.ContainerListOptions{})
	if err != nil {
		panic(err)
	}

	var data = map[int]map[string]string{}
	for id, cnt := range containers {
		data[id] = make(map[string]string)
		name := strings.Replace(cnt.Names[0], "/", "", -1)
		data[id][cnt.ID[:10]] = name
	}

	return data
}

// Check container status
func checkStatus(cli *client.Client, cntId string) bool {
	st, _, err := cli.ContainerInspectWithRaw(context.Background(), cntId, false)
	if err != nil {
		panic(err)
	}
	return st.ContainerJSONBase.State.Running
}

// Contructing JSON for zabbix
func jsonMapGen(data string) []ContainerStats {
	data = fmt.Sprintf("[%s]", data)
	bytes := []byte(data)

	var stats []ContainerStats
	json.Unmarshal(bytes, &stats)

	return stats
}

// ** Zabbix Sender Section

func zabbixSend(data map[string][]string, zabbixServer string, zabbixPort int, zabbixHost string) {
	var metrics []*Metric
	for id, v := range data {
		name := strings.Replace(v[0], "/", "", -1)
		// Basic metrics
		metrics = append(metrics, NewMetric(zabbixHost, fmt.Sprintf("docker.id[%v,%v]", id, name), id, time.Now().Unix()))
		metrics = append(metrics, NewMetric(zabbixHost, fmt.Sprintf("docker.name[%v,%v]", id, name), name, time.Now().Unix()))
		metrics = append(metrics, NewMetric(zabbixHost, fmt.Sprintf("docker.hostmachine[%s,%s]", id, name), zabbixHost, time.Now().Unix()))
		// CPU metrics
		metrics = append(metrics, NewMetric(zabbixHost, fmt.Sprintf("docker.pidstats.current[%s,%s]", id, name), v[1], time.Now().Unix()))
		metrics = append(metrics, NewMetric(zabbixHost, fmt.Sprintf("docker.cpustats.usage.total[%s,%s]", id, name), v[2], time.Now().Unix()))
		metrics = append(metrics, NewMetric(zabbixHost, fmt.Sprintf("docker.cpustats.system[%s,%s]", id, name), v[3], time.Now().Unix()))

		// Memory metrics
		metrics = append(metrics, NewMetric(zabbixHost, fmt.Sprintf("docker.memorystats.usage[%s,%s]", id, name), v[4], time.Now().Unix()))
		metrics = append(metrics, NewMetric(zabbixHost, fmt.Sprintf("docker.memorystats.maxusage[%s,%s]", id, name), v[5], time.Now().Unix()))
		metrics = append(metrics, NewMetric(zabbixHost, fmt.Sprintf("docker.memorystats.stats.active[%s,%s]", id, name), v[6], time.Now().Unix()))
		metrics = append(metrics, NewMetric(zabbixHost, fmt.Sprintf("docker.memorystats.stats.cache[%s,%s]", id, name), v[7], time.Now().Unix()))
		metrics = append(metrics, NewMetric(zabbixHost, fmt.Sprintf("docker.memorystats.stats.inactive[%s,%s]", id, name), v[8], time.Now().Unix()))
		metrics = append(metrics, NewMetric(zabbixHost, fmt.Sprintf("docker.memorystats.stats.rss[%s,%s]", id, name), v[9], time.Now().Unix()))
		metrics = append(metrics, NewMetric(zabbixHost, fmt.Sprintf("docker.memorystats.stats.swap[%s,%s]", id, name), v[10], time.Now().Unix()))
		metrics = append(metrics, NewMetric(zabbixHost, fmt.Sprintf("docker.memorystats.stats.totalactive[%s,%s]", id, name), v[11], time.Now().Unix()))
		metrics = append(metrics, NewMetric(zabbixHost, fmt.Sprintf("docker.memorystats.stats.totalinactive[%s,%s]", id, name), v[12], time.Now().Unix()))
		metrics = append(metrics, NewMetric(zabbixHost, fmt.Sprintf("docker.memorystats.stats.totalrss[%s,%s]", id, name), v[13], time.Now().Unix()))
		metrics = append(metrics, NewMetric(zabbixHost, fmt.Sprintf("docker.memorystats.limit[%s,%s]", id, name), v[14], time.Now().Unix()))

		// Network metrics rx
		metrics = append(metrics, NewMetric(zabbixHost, fmt.Sprintf("docker.networks.eth0.rxbytes[%s,%s]", id, name), v[15], time.Now().Unix()))
		metrics = append(metrics, NewMetric(zabbixHost, fmt.Sprintf("docker.networks.eth0.rxpackets[%s,%s]", id, name), v[16], time.Now().Unix()))
		metrics = append(metrics, NewMetric(zabbixHost, fmt.Sprintf("docker.networks.eth0.rxerrors[%s,%s]", id, name), v[17], time.Now().Unix()))
		metrics = append(metrics, NewMetric(zabbixHost, fmt.Sprintf("docker.newtorks.eth0.rxdropped[%s,%s]", id, name), v[18], time.Now().Unix()))

		// Network metrics tx
		metrics = append(metrics, NewMetric(zabbixHost, fmt.Sprintf("docker.networks.eth0.txbytes[%s,%s]", id, name), v[19], time.Now().Unix()))
		metrics = append(metrics, NewMetric(zabbixHost, fmt.Sprintf("docker.networks.eth0.txpackets[%s,%s]", id, name), v[20], time.Now().Unix()))
		metrics = append(metrics, NewMetric(zabbixHost, fmt.Sprintf("docker.networks.eth0.txerrors[%s,%s]", id, name), v[21], time.Now().Unix()))
		metrics = append(metrics, NewMetric(zabbixHost, fmt.Sprintf("docker.networks.eth0.txdropped[%s,%s]", id, name), v[22], time.Now().Unix()))
		
	}

	packet := NewPacket(metrics)
	z := NewSender(zabbixServer, zabbixPort)
	z.Send(packet)
	log.Println("SEND: packet sent zo zabbix")
}