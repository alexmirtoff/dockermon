/*

(c) 2018 Alex Mirtoff
mailto: alex@mirtoff.ru, amirtov@alfabank.ru

*/
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	//"reflect"
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
	// Networks struct {
	// 	Eth0 struct {
	// 		RxBytes   int `json:"rx_bytes"`
	// 		RxPackets int `json:"rx_packets"`
	// 		RxErrors  int `json:"rx_errors"`
	// 		RxDropped int `json:"rx_dropped"`
	// 		TxBytes   int `json:"tx_bytes"`
	// 		TxPackets int `json:"tx_packets"`
	// 		TxErrors  int `json:"tx_errors"`
	// 		TxDropped int `json:"tx_dropped"`
	// 	} `json:"eth0"`
	// } `json:"networks"`
	// Описываем динамический механимз получения интерфейсов
	Networks map[string]map[string]int64
}

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
	cli, err := client.NewClientWithOpts(client.WithVersion("1.37"))
	if err != nil {
		log.Println(err)
		os.Exit(1)
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
	go startOverview(cli,getStatsTimer, zabbixServer, zabbixPort, zabbixHost)
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
	// тут странно, тру и фолс наоборот :)
	r.GET("/zabbix/containers/list", getIndexWithSettings(cli, false))
	r.GET("/zabbix/containers/listall", getIndexWithSettings(cli, true))
	r.GET("/zabbix/containers/networks", getEthernetWithSettings(cli, false))
	webPort = fmt.Sprintf(":%s", webPort)
	http.ListenAndServe(webPort, r)

}

type M map[string]string

// Construct JSON reply for Zabbix discovery (containers list)
func zabbixDiscoveryGenJSON(cli *client.Client, ifRun bool) string {
	var myMapSlice []M // use this for slicing the maps
	for _, cnt := range getContainers(cli, ifRun) {
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

type S map[string]map[string]string

// Construct JSON reply for Zabbix discovery (ethernet interfaces)
func zabbixDiscoveryGenJSONEthernet(cli *client.Client, ifRun bool) string {
	var count int = 1
	var stroka string
	for _, cnt := range getContainers(cli, ifRun) {
		tmpMap := make(map[string]string)
		for topId, _ := range cnt {
			st := jsonMapGen(getStat(cli, topId, false))
			for idMid, values := range st {
				cntName := strings.Replace(st[idMid].Name, "/", "", -1)
				
				tmpMap["{#CONTNAME}"] = cntName
				tmpMap["{#CONTID}"] = topId

				for intName, _ := range values.Networks {
					if count == 0 {
						stroka = stroka + ","
					}
					count = 0
					tmpMap["{#INTERFACE}"] = intName
					stroka += fmt.Sprintf("{\"{#CONTID}\":\"%s\",\"{#CONTNAME}\":\"%s\",\"{#INTERFACE}\":\"%s\"}", topId, cntName, intName)
				}
			} 
		}
	}
	return fmt.Sprintf("{\"data\":[%s]}", stroka)
}

// HTTP Handlers (list, listall)
func getIndexWithSettings(cli *client.Client, ifRun bool) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		w.Header().Set("Content-Type", "application/json")
		message := r.URL.Path
		message = strings.TrimPrefix(message, "/")
		message = zabbixDiscoveryGenJSON(cli, ifRun)
		w.Write([]byte(message))
	}
}

// HTTP Handlers (Ethernet interfaces)
func getEthernetWithSettings(cli *client.Client, ifRun bool) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		w.Header().Set("Content-Type", "application/json")
		message := r.URL.Path
		message = strings.TrimPrefix(message, "/")
		message = zabbixDiscoveryGenJSONEthernet(cli, ifRun)
		w.Write([]byte(message))
	}
}
// start overviev data sender
func startOverview(cli *client.Client, getStatsTimer int, zabbixServer string, zabbixPort int, zabbixHost string) {	
	for {
		var metrics []*Metric

		cAll := getContainers(cli, true)
		var ifRun int
		for _, cMap := range cAll {
			for id, name := range cMap {
				if checkStatus(cli, id) {
					ifRun = 1
				} else {
					ifRun = 0
				}
				// fmt.Printf("docker.table[%v,%v]", id, name)
				// fmt.Println(ifRun)
				metrics = append(metrics, NewMetric(zabbixHost, fmt.Sprintf("docker.table[%v,%v]", id, name), strconv.Itoa(ifRun), time.Now().Unix()))
			}
		}
		packet := NewPacket(metrics)
		z := NewSender(zabbixServer, zabbixPort)
		z.Send(packet)
		// fmt.Println(metrics)
		log.Println("SEND: packet sent zo zabbix")
		time.Sleep(time.Duration(getStatsTimer) * time.Second)
	}
}

type prSl map[string]int

// Docker Request info goroutine
func startDockerReqAgent(cli *client.Client, getStatsTimer int, zabbixServer string, zabbixPort int, zabbixHost string) {
	for {
		// Инициализация карты массивов строк для заполнения параметрами для Zabbix
		// statsMap := make(map[string][]string)
		statsMap := make(map[string][]map[string]string)
		statsNetworkMap := make(map[string][]map[string]map[string]string)

		// Список всех контейнеров
		cAll := getContainers(cli, true)
		cCountAll := len(cAll)

		// Список запущенных контейнеров
		cRun := getContainers(cli, false)
		cCountRun := len(cRun)

		// Основной цикл среди запущенных контейнеров
		for _, cnt := range cRun {
			for k, _ := range cnt {
				st := jsonMapGen(getStat(cli, k, false))
				for l := range st {
					log.Printf("GET: %v", st)
					if checkStatus(cli, st[l].ID[:10]) {
						// temporary maps
						tmpStats := make(map[string]string)
						ethTmpValues := make(map[string]string)
						ethIntTmpNames := make(map[string]map[string]string)
						// statsMap[st[l].ID[:10]] = append(statsMap[st[l].ID[:10]], st[l].Name)
						tmpStats["ID"] = st[l].ID[:10]
						tmpStats["Name"] = st[l].Name
						tmpStats["PidsStatsCurrent"] = strconv.Itoa(st[l].PidsStats.Current)
						tmpStats["CPUStatsCPUUsageTotalUsage"] = strconv.Itoa(st[l].CPUStats.CPUUsage.TotalUsage)
						tmpStats["CPUStatsSystemCPUUsage"] = strconv.FormatInt(st[l].CPUStats.SystemCPUUsage, 10)
						tmpStats["MemoryStatsUsage"] = strconv.Itoa(st[l].MemoryStats.Usage)
						tmpStats["MemoryStatsMaxUsage"] = strconv.Itoa(st[l].MemoryStats.MaxUsage)
						tmpStats["MemoryStatsActiveAnon"] = strconv.Itoa(st[l].MemoryStats.Stats.ActiveAnon)
						tmpStats["MemoryStatsStatsCache"] = strconv.Itoa(st[l].MemoryStats.Stats.Cache)
						tmpStats["MemoryStatsStatsInactiveAnon"] = strconv.Itoa(st[l].MemoryStats.Stats.InactiveAnon)
						tmpStats["MemoryStatsStatsRss"] = strconv.Itoa(st[l].MemoryStats.Stats.Rss)
						tmpStats["MemoryStatsStatsSwap"] = strconv.Itoa(st[l].MemoryStats.Stats.Swap)
						tmpStats["MemoryStatsStatsTotalActiveAnon"] = strconv.Itoa(st[l].MemoryStats.Stats.TotalActiveAnon)
						tmpStats["MemoryStatsStatsTotalInactiveAnon"] = strconv.Itoa(st[l].MemoryStats.Stats.TotalInactiveAnon)
						tmpStats["MemoryStatsStatsTotalRss"] = strconv.Itoa(st[l].MemoryStats.Stats.TotalRss)
						tmpStats["MemoryStatsLimit"] = strconv.Itoa(st[l].MemoryStats.Limit)
						tmpStats["CPUPercentage"] = FloatToString(calcCPUPercent(st[l].CPUStats.CPUUsage.TotalUsage,
													 st[l].CPUStats.SystemCPUUsage, st[l].PrecpuStats.CPUUsage.TotalUsage,
													 st[l].PrecpuStats.SystemCPUUsage, st[l].CPUStats.CPUUsage.PercpuUsage))
						tmpStats["ContainerStatus"] = strconv.FormatBool(checkStatus(cli, st[l].ID[:10]))
						// Network dynamic interfaces
						for ethIntName, ethIntField := range st[l].Networks {
							// rx
							ethTmpValues["rx_bytes"] = strconv.FormatInt(ethIntField["rx_bytes"], 10)
							ethTmpValues["rx_packets"] = strconv.FormatInt(ethIntField["rx_packets"], 10)
							ethTmpValues["rx_errors"] = strconv.FormatInt(ethIntField["rx_errors"], 10)
							ethTmpValues["rx_dropped"] = strconv.FormatInt(ethIntField["rx_dropped"], 10)
							// tx
							ethTmpValues["tx_bytes"] = strconv.FormatInt(ethIntField["tx_bytes"], 10)
							ethTmpValues["tx_packets"] = strconv.FormatInt(ethIntField["tx_packets"], 10)
							ethTmpValues["tx_errors"] = strconv.FormatInt(ethIntField["tx_errors"], 10)
							ethTmpValues["tx_dropped"] = strconv.FormatInt(ethIntField["tx_dropped"], 10)

							ethTmpValues["name"] = strings.Replace(st[l].Name, "/", "", -1)
							
							ethIntTmpNames[ethIntName] = ethTmpValues
						}
						// put network interfaces data into slice of networks maps (top level)
						statsNetworkMap[st[l].ID[:10]] = append(statsNetworkMap[st[l].ID[:10]], ethIntTmpNames)
						// put temporary map into slice of maps (top level)
						statsMap[st[l].ID[:10]] = append(statsMap[st[l].ID[:10]], tmpStats)
					}		
				}
			}
		}
		// getNetInterfaces(cli)
		zabbixSend(statsMap, statsNetworkMap, cCountAll, cCountRun, zabbixServer, zabbixPort, zabbixHost)
		time.Sleep(time.Duration(getStatsTimer) * time.Second)
	}
}

// Network interfaces discovery
// Для сетей требуется отдельный механизм, так как это динамичные данные
func getNetInterfaces(cli *client.Client) {
	cRun := getContainers(cli, false)
	for _, cnt := range cRun {
		for k, _ := range cnt {
			st := jsonMapGen(getStat(cli, k, false))
			for a, b := range st {
				cntName := strings.Replace(st[a].Name, "/", "", -1)
				fmt.Println(k, cntName, b.Networks)
			}
		} 
	}
}

func FloatToString(input_num float64) string {
	return strconv.FormatFloat(input_num, 'f', 6, 64)
}

// Calculate CPU percentage
func calcCPUPercent(currTotUserCPU int, currTotSysCPU int64, prevTotUserCPU int, prevTotSysCPU int64, percpuUsage []int) float64 {
	//	fmt.Println(currTotUserCPU, currTotSysCPU, prevTotUserCPU, prevTotSysCPU, percpuUsage)

	var (
		cpuPercent  = 0.0
		cpuDelta    = float64(currTotUserCPU) - float64(prevTotUserCPU)
		systemDelta = float64(currTotSysCPU) - float64(prevTotSysCPU)
	)

	if systemDelta > 0.0 && cpuDelta > 0.0 {
		cpuPercent = (cpuDelta / systemDelta) * float64(len(percpuUsage)) * 100.0
	}
	return cpuPercent
}

// Get container's stat
func getStat(cli *client.Client, cnt string, stream bool) string {
	out, err := cli.ContainerStats(context.Background(), cnt, stream)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	buf := new(bytes.Buffer)
	buf.ReadFrom(out.Body)

	return buf.String()
}

// Get containters list
func getContainers(cli *client.Client, all bool) map[int]map[string]string {
	var tList types.ContainerListOptions
	if all {
		tList = types.ContainerListOptions{All: true}
	} else {
		tList = types.ContainerListOptions{}
	}

	containers, err := cli.ContainerList(context.Background(), tList)
	ifErr(err)
	var data = map[int]map[string]string{}
	for id, cnt := range containers {
		data[id] = make(map[string]string)
		name := strings.Replace(cnt.Names[0], "/", "", -1)
		data[id][cnt.ID[:10]] = name
	}
	//fmt.Println(data)
	return data
}

// err
func ifErr(err error) {
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
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

func zabbixSend(data map[string][]map[string]string, netData map[string][]map[string]map[string]string, cCountAll int, cCountRun int, zabbixServer string, zabbixPort int, zabbixHost string) {

	var metrics []*Metric

	for containerID, mapValues := range data {
		for _, values := range mapValues {
			// need to correct name
			containerName := strings.Replace(values["Name"], "/", "", -1)

			// Basic metrics
			metrics = append(metrics, NewMetric(zabbixHost, fmt.Sprintf("docker.id[%v,%v]", containerID, containerName), containerID, time.Now().Unix()))
			metrics = append(metrics, NewMetric(zabbixHost, fmt.Sprintf("docker.name[%v,%v]", containerID, containerName), containerName, time.Now().Unix()))
			metrics = append(metrics, NewMetric(zabbixHost, fmt.Sprintf("docker.hostmachine[%s,%s]", containerID, containerName), zabbixHost, time.Now().Unix()))
			
			// CPU metrics
			metrics = append(metrics, NewMetric(zabbixHost, fmt.Sprintf("docker.pidstats.current[%s,%s]", containerID, containerName), values["PidsStatsCurrent"], time.Now().Unix()))
			metrics = append(metrics, NewMetric(zabbixHost, fmt.Sprintf("docker.cpustats.usage.total[%s,%s]", containerID, containerName), values["CPUStatsCPUUsageTotalUsage"], time.Now().Unix()))      
			metrics = append(metrics, NewMetric(zabbixHost, fmt.Sprintf("docker.cpustats.system[%s,%s]", containerID, containerName), values["CPUStatsSystemCPUUsage"], time.Now().Unix()))
			metrics = append(metrics, NewMetric(zabbixHost, fmt.Sprintf("docker.cpustats.percent[%s,%s]", containerID, containerName), values["CPUPercentage"], time.Now().Unix()))

			// // Memory metrics
			metrics = append(metrics, NewMetric(zabbixHost, fmt.Sprintf("docker.memorystats.usage[%s,%s]", containerID, containerName), values["MemoryStatsUsage"], time.Now().Unix()))
			metrics = append(metrics, NewMetric(zabbixHost, fmt.Sprintf("docker.memorystats.maxusage[%s,%s]", containerID, containerName), values["MemoryStatsMaxUsage"], time.Now().Unix()))
			metrics = append(metrics, NewMetric(zabbixHost, fmt.Sprintf("docker.memorystats.stats.active[%s,%s]", containerID, containerName), values["MemoryStatsActiveAnon"], time.Now().Unix()))
			metrics = append(metrics, NewMetric(zabbixHost, fmt.Sprintf("docker.memorystats.stats.cache[%s,%s]", containerID, containerName), values["MemoryStatsStatsCache"], time.Now().Unix()))
			metrics = append(metrics, NewMetric(zabbixHost, fmt.Sprintf("docker.memorystats.stats.inactive[%s,%s]", containerID, containerName), values["MemoryStatsStatsInactiveAnon"], time.Now().Unix()))
			metrics = append(metrics, NewMetric(zabbixHost, fmt.Sprintf("docker.memorystats.stats.rss[%s,%s]", containerID, containerName), values["MemoryStatsStatsRss"], time.Now().Unix()))
			metrics = append(metrics, NewMetric(zabbixHost, fmt.Sprintf("docker.memorystats.stats.swap[%s,%s]", containerID, containerName), values["MemoryStatsStatsSwap"], time.Now().Unix()))
			metrics = append(metrics, NewMetric(zabbixHost, fmt.Sprintf("docker.memorystats.stats.totalactive[%s,%s]", containerID, containerName), values["MemoryStatsStatsTotalActiveAnon"], time.Now().Unix()))
			metrics = append(metrics, NewMetric(zabbixHost, fmt.Sprintf("docker.memorystats.stats.totalinactive[%s,%s]", containerID, containerName), values["MemoryStatsStatsTotalInactiveAnon"], time.Now().Unix()))
			metrics = append(metrics, NewMetric(zabbixHost, fmt.Sprintf("docker.memorystats.stats.totalrss[%s,%s]", containerID, containerName), values["MemoryStatsStatsTotalRss"], time.Now().Unix()))
			metrics = append(metrics, NewMetric(zabbixHost, fmt.Sprintf("docker.memorystats.limit[%s,%s]", containerID, containerName), values["MemoryStatsLimit"], time.Now().Unix()))

		}
	}

	// Iterate ethernet interfaces
	for containerID, valsTop := range netData {
		for _, valsMid  := range valsTop {
			for ethName, value := range valsMid {	
			// Network metrics rx
			metrics = append(metrics, NewMetric(zabbixHost, fmt.Sprintf("docker.networks.rxbytes[%s,%s,%s]", containerID, value["name"], ethName), value["rx_bytes"], time.Now().Unix()))
			metrics = append(metrics, NewMetric(zabbixHost, fmt.Sprintf("docker.networks.rxpackets[%s,%s,%s]", containerID, value["name"], ethName), value["rx_packets"], time.Now().Unix()))
			metrics = append(metrics, NewMetric(zabbixHost, fmt.Sprintf("docker.networks.rxerrors[%s,%s,%s]", containerID, value["name"], ethName), value["rx_errors"], time.Now().Unix()))
			metrics = append(metrics, NewMetric(zabbixHost, fmt.Sprintf("docker.newtorks.rxdropped[%s,%s,%s]", containerID, value["name"], ethName), value["rx_dropped"], time.Now().Unix()))

			// Network metrics tx
			metrics = append(metrics, NewMetric(zabbixHost, fmt.Sprintf("docker.networks.txbytes[%s,%s,%s]", containerID, value["name"], ethName), value["tx_bytes"], time.Now().Unix()))
			metrics = append(metrics, NewMetric(zabbixHost, fmt.Sprintf("docker.networks.txpackets[%s,%s,%s]", containerID, value["name"], ethName), value["tx_packets"], time.Now().Unix()))
			metrics = append(metrics, NewMetric(zabbixHost, fmt.Sprintf("docker.networks.txerrors[%s,%s,%s]", containerID, value["name"], ethName), value["tx_errors"], time.Now().Unix()))
			metrics = append(metrics, NewMetric(zabbixHost, fmt.Sprintf("docker.networks.txdropped[%s,%s,%s]", containerID, value["name"], ethName), value["tx_dropped"], time.Now().Unix()))
			}
		}
	}

	packet := NewPacket(metrics)
	z := NewSender(zabbixServer, zabbixPort)
	z.Send(packet)
	log.Println("SEND: packet sent zo zabbix")
}
