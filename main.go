package main

import (
    "time"
    "net"
    "strings"
    //"github.com/google/go-cmp/cmp"
    //"strconv"
    "runtime"
    "enforta/tzspanalyser"
    "github.com/sirupsen/logrus"
    "github.com/shirou/gopsutil/load"
    //"github.com/shirou/gopsutil/cpu"
    "github.com/shirou/gopsutil/mem"
    "encoding/json"
    "net/http"
    "bytes"
    //"sync"
    "sync/atomic"
   // "reflect"
   "fmt"
)


var (
    mac_to_post = make(chan captured_MAC,44000) // for POSTs to localdb
    mac_to_produce = make(chan captured_MAC,44000) // or kafka producer
    //mutex = &sync.Mutex{}    
    
    //ouiDBrenew_hours time.Duration  = 1 // when file expire hours
    //FilterByVendor bool = false
    //check_all_macs bool = false

    //802.11 frame types to ignore
    ignore_frames = map[string]bool{
        "MgmtBeacon": true,
        "MgmtProbeResp": true,
    }    

    //vendors to ignore
    ignore_vendors = map[string]bool{
        "InfiNet LLC" : true,
        "D-LINK SYSTEMS, INC." : true,
        "D-Link International" : true,
        "Juniper Networks" : true,
        "Cisco Systems, Inc" : true,
        "TP-LINK TECHNOLOGIES CO.,LTD." : true,
        "Zyxel Communications Corporation" : true,
        "Cambium Networks Limited": true,
        "Ruckus Wireless": true,
        "Routerboard.com": true,
        "Ubiquiti Networks Inc.": true,
        "unknown": true,
        "unavailable": true,
    }

    // 802.11 flags to ignore
    ignore_flags = map[string]bool{
        "FROM-DS": true,
    }

)     

func main() {
    quit := make(chan struct{})
    Init()

    err := MakeOuidb(ouiFileName)
    ErrorAndExit("Can't init OUI Database",err)

    ServerAddr,err := net.ResolveUDPAddr(proto_db,port_db)
    ErrorAndExit("can't resolve udp",err)    
    conn, err := net.ListenUDP("udp", ServerAddr)
    ErrorAndExit("Can't listen UDP port",err)

    log.Info("Waiting for TZSP flows...")
    
    for i := 0; i < runtime.NumCPU(); i++ {
        go handlePacket(conn, quit)
    }

    go runWebServer(httpserver_ip_port)

    go print_stats()
    //go cache_handler()
    go OuidbUpdater()

    go Kafka()
    go MACpostman()


    <-quit // hang until an error
    log.Info("Exit")
}

/*
the goriutines for handling with TZSP packets from mikrotik routers 
sorry about the spagetti-length ;-)
*/
func handlePacket(conn *net.UDPConn , quit chan struct{}) {
    buf := make([]byte, 1024)
    l, udp, err_ := 0, new(net.UDPAddr), error(nil)


    for err_ == nil {
        l, udp, err_ = conn.ReadFromUDP(buf)
        //start_ := time.Now()
        atomic.AddInt64(&packets_count, 1)

        if SnifIsBad(udp.IP.String()) { continue }

        tzsp,err := tzspanalyser.Parse(buf[:l])
        if err != nil {
            log.Error(udp.IP.String(),": Recieved data from snif which is bad: ",err)
            CacheBadSnif(udp.IP.String())
            continue
        }
        
        if !snif_counters(tzsp["sensor_id"].(string),udp.IP.String()) { continue }

        Raw_fr := tzsp["dot11header"].([]byte)
        Dot11,err := tzspanalyser.ParseDot11(Raw_fr)
        if err != nil {log.Trace("warning while parsing 802.11 layer:  ",err)}

        log.WithFields(logrus.Fields{
            "sensor_id": tzsp["sensor_id"], "sensor_ip": udp.IP,
            "Type" :    Dot11.Type, "Flags" :  Dot11.Flags,
            "mac1": Dot11.Address1, "mac2": Dot11.Address2,
            "mac3": Dot11.Address3, "mac4": Dot11.Address4,
            "RSSI" :  tzsp["RSSI"], "RawRate" :  tzsp["data_rate"].(int64),
            "Raw_channel" : tzsp["rx_channel"].(int64),
            "DurationID": Dot11.DurationID,"SequenceNumber": Dot11.SequenceNumber,
            "FragmentNumber": Dot11.FragmentNumber,"Checksum": Dot11.Checksum,
            "QOS": Dot11.QOS,"HTControl": Dot11.HTControl,
            "DataLayer": Dot11.DataLayer,
            "RawDot11" :    Raw_fr}).Trace(  //Trace
            "the frame from sniffer:" +tzsp["sensor_id"].(string)) 

    	mac := Dot11.Address2
    	if len(mac) != 0 {
    		if MacIsFine(mac) {
    			vendor := VendorName(mac)

                // ignore some frame types, vendors and flags...
                flags := strings.Split(Dot11.Flags.String(), ",")
    			//if !ignore_frames[Dot11.Type.String()] &&

                if !ignore_vendors[vendor] &&
                   !ignore_flags[flags[0]] {

                    log.WithFields(logrus.Fields{
                        "sensor_id": tzsp["sensor_id"], "sensor_ip": udp.IP,
                        "Type" :    Dot11.Type, "Flags" :  Dot11.Flags,
                        "mac1": Dot11.Address1, "mac2": Dot11.Address2,
                        "mac3": Dot11.Address3, "mac4": Dot11.Address4,
                        "vendor" : vendor,
                        "RSSI" :  tzsp["RSSI"]}).Trace("Gotcha: "+mac.String()) 

    			    c := captured_MAC{
    	            Src_ip: udp.IP.String(),
    	            Vendor: vendor,
    	            Sensor_id: tzsp["sensor_id"].(string),
    	            Mac: mac.String(),
                    Channel: tzsp["rx_channel"].(int64),
    	            RSSI_current: tzsp["RSSI"].(int64)}

    	        	go MacHandler(c)
    			}
    		} 
    	}	    	
    }
    log.Error("UDP port listen error:",err_)
    quit <- struct{}{}
}   

/* just make counters for the sniffer */
func snif_counters(mac string,ip string) bool {
    s := captured_snif{Id:mac,Ip:ip}
    s.lock()
    _,err := s.store()
    s.unlock()    
    if err != nil {
        log.Error("Can not save SNIF in cache: ",err)
        return false
    }
    return true
}

/* save/update mac in cache and notify about it if new or from time to time */
func MacHandler(c captured_MAC) {
    c.lock()
    c,err := c.store()
    c.unlock()

    if err != nil { log.Error("Can not save it in cache: ",c,err) }

    if c.send_it {
        msg := fmt.Sprintf("snif: %s mac to send: %s", c.Src_ip,c.Mac)
        log.Debug("[MacHandler] ",msg)

        mac_to_produce <- c // kafka
        mac_to_post <- c // local storage

        c.send_it = false
    }

}

/* returns vendor name by mac according to oui database */
func VendorName(mac net.HardwareAddr) string {
	if len(mac) == 6 {
	    vendor,err := tzspanalyser.VendorByMac(mac)
	    if err != nil {
	        log.Error("error while looking for vendor:",err)
	        return "unavailable"
	    }
	    return vendor
	}
	log.Error("bad mac: ",mac.String())
	return "unavailable"
}

// true -  if mac looks good (unicast and oui unique bits enabled)
func MacIsFine(mac net.HardwareAddr) bool {
    if len(mac) != 0 {
        return tzspanalyser.MacAUIisUnique(mac) && tzspanalyser.MacIsUnicast(mac)
    }
    return false
}

/* the daemon sends some statistics from time to time */
type MainStats struct {
    Version string          `json:"version"`
    NumCPU int              `json:"NumCPU"`
    Snifs int               `json:"snifs"`
    Goroutines int          `json:"goroutines"`
    Pps int64               `json:"pps"`
    Timestamp int64         `json:"ts_last"`
    Mem_usage int           `json:"mem_usage"`
    Load_prcnt int          `json:"load_prcnt"`
    Period int64            `json:"period"`
    Load_1m float64         `json:"load_1m"`
    Load_5m float64         `json:"load_5m"`
    Load_15m float64        `json:"load_15m"`
    Snifs_cached int        `json:"snifs_cached"`
    Macs_discovered int64       `json:"macs_discovered"`
    Macs_discovered_total int64 `json:"macs_discovered_total"`
    Macs_sent int64         `json:"macs_sent"`
    Macs_sent_total int64   `json:"macs_sent_total"`
    Kafka_fail int64         `json:"kafka_fail"`
    Kafka_fail_total int64   `json:"kafka_fail_total"`    
    Post_count int64   `json:"post_count"` 
    Post_count_total int64   `json:"post_count_total"`
    Post_errors_count int64   `json:"post_errors_count"` 
    Post_errors_count_total int64   `json:"post_errors_count_total"` 

    //Uptime int64 `json:"uptime"`
    Uptime int64            `json:"uptime_sec"`
}

type CombinedStats struct {
    Main MainStats `json:"main"`
    Snifs map[string]captured_snif `json:"snifs"`
}

/* build statistics for logs and POST */
func CollectStats(version string) MainStats {
    s := MainStats{}
    load, _ := load.Avg()
    numcpu := runtime.NumCPU()
    time_now := time.Now().Unix()
    v, _ := mem.VirtualMemory()
    st_p := atomic.LoadInt64(&CFG_STATS_PERIOD)

    s.Version = version
    s.NumCPU = numcpu
    s.Snifs = CountSnifs()
    s.Goroutines = runtime.NumGoroutine()
    s.Pps = atomic.LoadInt64(&packets_count) / st_p
    s.Timestamp = time_now
    s.Mem_usage = int(v.UsedPercent)
    s.Load_prcnt = int(load.Load1 * 100 / float64(numcpu))
    s.Period = atomic.LoadInt64(&CFG_STATS_PERIOD)
    s.Load_1m = load.Load1
    s.Load_5m = load.Load5
    s.Load_15m = load.Load15
    s.Macs_discovered = atomic.LoadInt64(&macs_discovered)
    s.Macs_discovered_total = atomic.LoadInt64(&macs_discovered_total)
    // kafka
    s.Macs_sent = atomic.LoadInt64(&macs_notified)
    s.Macs_sent_total = atomic.LoadInt64(&macs_notified_total)
    s.Kafka_fail = atomic.LoadInt64(&kafka_errors_count)
    s.Kafka_fail_total = atomic.LoadInt64(&kafka_errors_count_total)
    // http requests
    s.Post_count = atomic.LoadInt64(&post_count)
    s.Post_count_total = atomic.LoadInt64(&post_count_total)
    s.Post_errors_count = atomic.LoadInt64(&post_errors_count)
    s.Post_errors_count_total = atomic.LoadInt64(&post_errors_count_total)

    //s.Uptime = time.Since(start_time)
    s.Uptime = time_now - start_time.Unix()

    return s

}

/* choose some fields we put in log */
func Logrus_fields(s MainStats) logrus.Fields {
    result := logrus.Fields{
        "snifs"            : s.Snifs,
        "goroutines"       : s.Goroutines,
        "load"             : s.Load_prcnt,
        "mem"              : s.Mem_usage,
        "pps"              : s.Pps,
        "macs_sent"        : s.Macs_sent,
        "send_fail"        : s.Kafka_fail,
        "posts_fail"        : s.Post_errors_count,
        "posts"        : s.Post_count,
        "macs_discovered"  : s.Macs_discovered,
    }
    return result
}


/* POST statiscics and logs from time to time
CFG_STATS_PERIOD var (logtime parameter)
 */
func print_stats() {
    ver := version
    for {
        
        stat := CollectStats(ver)
        // snifs := GetSnifs()
        snif_cache.Lock()
        snifs := snif_cache.snifs
        stat.Snifs_cached = len(snifs)
        data := CombinedStats{ Main : stat, Snifs : snifs, }

        logfields := Logrus_fields(stat)

        log.WithFields(logfields).Info(  //Trace
            "statistics for ",stat.Period," seconds")

        //main_cache.Lock() 
        j, _ := json.Marshal(data)
        snif_cache.Unlock()
        //main_cache.Unlock()

        //reset counters
        atomic.SwapInt64(&macs_discovered, 0)
        atomic.SwapInt64(&packets_count, 0)
        atomic.SwapInt64(&macs_notified, 0)        
        atomic.SwapInt64(&kafka_errors_count, 0)
        atomic.SwapInt64(&post_count, 0)
        atomic.SwapInt64(&post_errors_count, 0)

        PostJson(j,CFG_STATS_URL)
        time.Sleep(time.Duration(stat.Period) * time.Second)
    }

}


/* send json via http using post request */
func PostJson(jsonValue []byte, url string) {
    req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))

    if err != nil {
        log.WithFields(logrus.Fields{
            "error": err, "server url": url}).Error(
            "Can not prepare http request. Bad URL? ")
        return
    }

    //req.Header.Set("X-Custom-Header", "myvalue")
    req.Header.Set("Content-Type", "application/json")
    if CFG_TOKEN != "" {
        req.Header.Add("Authorization", "Bearer " + CFG_TOKEN)
    }

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        log.WithFields(logrus.Fields{
            "error": err, "server url": url}).Error(
            "Can not send request to http server. ")
        return
    }
    defer resp.Body.Close()    
    log.Debug("[PostJson] Response Status:'", resp.Status)

    if resp.StatusCode >= 200 && resp.StatusCode < 300 {
        atomic.AddInt64(&post_count, 1)
        atomic.AddInt64(&post_count_total, 1)
    } else {
        log.Error("[PostJson] Response Status:'", resp.Status)
        atomic.AddInt64(&post_errors_count, 1)
        atomic.AddInt64(&post_errors_count_total, 1)
    }
        
}


/* temp legacy
 the goroutine gets macs from 'ready_to_post'
 channel and sends it by http-post
*/
func MACpostman() {
    duration := atomic.LoadInt64(&CFG_POST_PERIOD)
    max_macs := 42 // max macs in json
    post_time := time.Now().Unix()

    data := []captured_MAC{}

    for {
        ready_to_post := false
        m := <-mac_to_post
        data = append(data,m)
        f := logrus.Fields{"mac-to-send":m.Mac,"len":len(data)}
        log.WithFields(f).Debug("[MACpostman] prepeared mac to send")

        if len(data) > max_macs+1 {
            log.Debug("[MACpostman] sending macs. Len:",len(data))
            ready_to_post = true
        } else {
            if time.Now().Unix() > post_time + duration {
                log.Debug("[MACpostman] sending macs by time. Len:",len(data))
                ready_to_post = true           
            }
        }

        if ready_to_post {
            if !CFG_KAFKA_ENABLED {
                atomic.SwapInt64(&macs_notified, atomic.LoadInt64(&macs_notified)  + int64(len(data)))        
                atomic.SwapInt64(&macs_notified_total, atomic.LoadInt64(&macs_notified_total)  + int64(len(data)))
            }

            json,err := json.Marshal(data)
            if err != nil {
                log.Error("Can't parse data into json: ",err)
            }
            //log.Debug("json: ",string(json))
            go PostJson(json,CFG_NOTIF_URL)
            data = []captured_MAC{} //clear buffer
            post_time = time.Now().Unix()
        }
    }
}
