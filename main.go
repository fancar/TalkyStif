package main

import (
    "os"
    "io"
    "time"
    "net"
    "strings"
    //"github.com/google/go-cmp/cmp"
    "strconv"
    "runtime"
    "enforta/tzspanalyser"
    "github.com/sirupsen/logrus"
    "github.com/shirou/gopsutil/load"
    //"github.com/shirou/gopsutil/cpu"
    "github.com/shirou/gopsutil/mem"
    "encoding/json"
    "net/http"
    "bytes"
    "sync"
    "sync/atomic"
   // "reflect"
   //"fmt"
   
)

const (
    ouiFileName string = "oui.txt"
    httpserver_ip_port string = "0.0.0.0:8087"
)

var (
    mutex = &sync.Mutex{}    
    
    //ouiDBrenew_hours time.Duration  = 1 // when file expire hours
    ouiDBrenew_period time.Duration // when file expire we are going to download newone
    //FilterByVendor bool = false
    check_all_macs bool = false
    
    packets_count int64 // packets have been counted in post_period
    macs_discovered,macs_notified,macs_discovered_total,macs_notified_total int64

    //802.11 frame types to ignore
    ignore_frames = map[string]bool{
        "MgmtBeacon": true,
        "MgmtProbeResp": true,
    }    

    //vendors to ignore
    ignore_vendors = map[string]bool{
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
    log.Info(Version," has just started")
    flags()
    ouiDBrenew_period = time.Duration(oui_period) * time.Hour
    logging(log_file)

    quit := make(chan struct{})
    //goahead := make(chan bool)

    err := MakeOuidb(ouiFileName)
    if err != nil {
        log.Error("You can try to place the file manually: ",ouiFileName)
        os.Exit(1)
    } else { tzspanalyser.OpenOuiDb(ouiFileName)  }
    //log.Info(tzspanalyser.OUI_db)

    ServerAddr,err := net.ResolveUDPAddr(proto_db,port_db)
    ErrorAndExit("can't resolve udp",err)    
    conn, err := net.ListenUDP("udp", ServerAddr)
    ErrorAndExit("Can't listen UDP port",err)
    
    start_time = time.Now()
    start_time_u = time.Now().Unix()

    log.Info("Waiting for TZSP flows...")

    go print_stats()
    go cache_handler()
    go UpdateOuidb()

    for i := 0; i < runtime.NumCPU(); i++ {
        go handlePacket(conn, quit)
    }

    go runWebServer(httpserver_ip_port)

    <-quit // hang until an error
    log.Info("Exit")
}

func runWebServer(a string) {
    r := NewRouter()
    http.Handle("/", r)
    go log.Fatal(http.ListenAndServe(a, nil))    
}
/* download a file from the internet */
func DownloadFile(filepath string, url string) error {
    log.Info("downloading...",url)
    // Get the data
    resp, err := http.Get(url)
    if err != nil { return err }

    defer resp.Body.Close()

    // Create the file
    out, err := os.Create(filepath)
    if err != nil { return err }
    defer out.Close()

    // Write the body to file
    _, err = io.Copy(out, resp.Body)
    return err
}


/* The func desdecides if we need  renew vendor's database */
func WeNeedNewFile(fname string) bool{

    file, err := os.Stat(fname)
    if err != nil {
        log.Error("oui-DB: can not get file params",err)
        return true
    }

    now := time.Now()
    diff := now.Sub(file.ModTime())
    
    if diff > ouiDBrenew_period {      
        log.Info("oui-DB: renew period: ",ouiDBrenew_period,oui_period)
        log.Info("oui-DB: the file is old: ",file.ModTime())
        return true
    } else {
        return false
    }
}


/* The func downloads vendor's database from the internet */
func DownloadOui(fname string) error {

    err := DownloadFile(fname, ouiFileUrl)
    if err == nil {
        log.Info("oui-DB: Adding new OUI database from ",fname)
        tzspanalyser.OpenOuiDb(fname)        
    }
    return err
   
}

func MakeOuidb(fname string) error {

    if _, err_ := os.Stat(fname); os.IsNotExist(err_) {
        //ErrorAndExit("cant find file",err)  
        log.Info("oui-DB: the local file not found")
        err := DownloadOui(fname)
        if  err != nil {
            log.Error("oui-DB: can not download oui database file",err)
            return err
        }
        
    } else {
        if WeNeedNewFile(fname) {
            err := DownloadOui(fname)
            if err != nil {
                log.Error("oui-DB: can not download new oui database file",err)    
            }            
        } 
        }
    return nil
}

/* The go func updates vendors database from the internet */
func UpdateOuidb() { 
    for {
        MakeOuidb(ouiFileName)
        time.Sleep(ouiDBrenew_period)
    }
    //quit <- struct{}{}
}


/* the goriutines for handling with TZSP packets from mikrotik routers */
func handlePacket(conn *net.UDPConn , quit chan struct{}) {

    buf := make([]byte, 1024)

    l, udp, err_ := 0, new(net.UDPAddr), error(nil)

    for err_ == nil {
        l, udp, err_ = conn.ReadFromUDP(buf)
        
        atomic.AddInt64(&packets_count, 1) //packets_count ++

        junk_snif := &BadSnifStruct{ sensor_ip: udp.IP.String() }

        bad_snifs_cache.Lock()

        if junk_snif.cached() {
            log.Trace("DEVICE IS IN <BAD SNIF> CACHE!: ",udp.IP.String() )
            if junk_snif.dobby_is_free() {
                delete(bad_snifs_cache.m, junk_snif.id())
                log.Trace("DEVICE IS REMOVED FROM BAD SNIF CACHE! (TIME IS OUT): ",udp.IP.String() )
            }
            bad_snifs_cache.Unlock()
            continue    
                                  
        }
        bad_snifs_cache.Unlock()
        //tzspanalyser.Parse(buf[:l])
        tzsp,err := tzspanalyser.Parse(buf[:l])
        
        //p, err := tzsp.Parse(b)
        if err != nil {
            log.Error(udp.IP.String()+": error while parsing TZSP: ",err)
            log.Trace("The umber of bad sniffers: ",len(bad_snifs_cache.m))
            //time.Sleep(timewait * time.Second) 
            bad_snifs_cache.Lock()
            CacheBadSnif(junk_snif)
            bad_snifs_cache.Unlock()      
            continue
        }
        
        if !snif_is_active(tzsp["sensor_id"].(string),udp.IP.String()) {
            break
        }

        Raw_fr := tzsp["dot11header"].([]byte)
        Dot11,err := tzspanalyser.ParseDot11(Raw_fr)

        if err != nil {
            log.Trace("Some warning while parsing dot11 layer: ",err)
        }

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

        if Dot11.Type.String() == "MgmtProbeResp" ||
           Dot11.Type.String() == "MgmtBeacon" {
        //if len(Dot11.Address2) != 0 && cmp.Equal(Dot11.Address2, Dot11.Address3) {
    			       
        	APmac := Dot11.Address2
            log.Trace(Dot11.Type.String()," - Looks like AP and will be ignored. detected from: ",APmac," - ",VendorName(APmac))
        	//log.Info("found beacon from ",APmac)
    	    c := captured_AP{
            src_ip: udp.IP.String(),
            vendor: VendorName(APmac),
            sensor_id: tzsp["sensor_id"].(string),
            mac: APmac.String()}
        	CacheAP(c)
        	continue
        }

    	mac := Dot11.Address2
    	if len(mac) != 0 {
    		if MacIsFine(mac) {

    			if ap_cached(tzsp["sensor_id"].(string),mac.String()) { continue }
    			vendor := VendorName(mac)

                // ignore some frame types , vendors and flags...
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
    	            src_ip: udp.IP.String(),
    	            vendor: vendor,
    	            sensor_id: tzsp["sensor_id"].(string),
    	            mac: mac.String(),
                    channel: tzsp["rx_channel"].(int64),
    	            position: 2,
    	            RSSI_current: tzsp["RSSI"].(int64)}

    	        	CacheMac(c)
    			}
    		}
    	}	    	
    	    
    }

    log.Error("UDP port listen error:",err_)
    quit <- struct{}{}
}   

/* just mark the sniffer as active (for counter) */
func snif_is_active(mac string,ip string) bool {
    s := captured_snif{Id:mac,Ip:ip}

    _,err := SaveItInCache(s) 
    if err != nil {
        log.Trace("Error while saving SNIF in cache: ",err)
        return false
    }
    return true
}

func CacheMac(c captured_MAC) {

    it_is_new,err := SaveItInCache(c) 
    if err != nil {log.Trace("Error while saving MAC in cache:",err)}

    if it_is_new {
        
        log.Trace("New mac saved in cache:",c.mac," ",c.vendor)
        atomic.AddInt64(&macs_discovered, 1) // macs_discovered ++
        atomic.AddInt64(&macs_discovered_total, 1) // macs_discovered_total ++
        //log.Trace("cache length:",len(captured_macs_cache))
    }
}

func CacheAP(c captured_AP) {

    _,err := SaveItInCache(c) 
    if err != nil {log.Trace("Error while saving AP in cache:",err)}

}

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

// true -  if mac looks like we need it (unicast and oui unique bits enabled)
func MacIsFine(mac net.HardwareAddr) bool {
    if len(mac) != 0 {
        //first_octet := mac[0]
        //fmt.Printf("% 08b", first_octet)
        //log.Trace("% 08b", first_octet)

        // if both first(from right to left bits are off)
        if tzspanalyser.MacAUIisUnique(mac) && tzspanalyser.MacIsUnicast(mac) {
            //log.Info("the mac is unicast and unique:",mac.String())
            return true
        }
    }
    return false
}

type MainStats struct {
    Version int              `json:"version"`
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
    Load_15m float64            `json:"load_15m"`
    Macs_discovered int64       `json:"macs_discovered"`
    Macs_discovered_total int64 `json:"macs_discovered_total"`
    Macs_sent int64         `json:"macs_sent"`
    Macs_sent_total int64   `json:"macs_sent_total"`
    //Uptime int64 `json:"uptime"`
    Uptime int64            `json:"uptime_sec"`
}

type CombinedStats struct {
    Main MainStats `json:"main"`
    Snifs map[string]captured_snif `json:"snifs"`
}

/* build statistics for logs and POST */
func CollectStats() MainStats {
    s := MainStats{}
    load, _ := load.Avg()
    numcpu := runtime.NumCPU()
    time_now := time.Now().Unix()
    v, _ := mem.VirtualMemory()
    st_p := atomic.LoadInt64(&stats_period)

    //s.Version = 
    s.NumCPU = numcpu
    s.Snifs = CountSnifs()
    s.Goroutines = runtime.NumGoroutine()
    s.Pps = atomic.LoadInt64(&packets_count) / st_p
    s.Timestamp = time_now
    s.Mem_usage = int(v.UsedPercent)
    s.Load_prcnt = int(load.Load1 * 100 / float64(numcpu))
    s.Period = atomic.LoadInt64(&stats_period)
    s.Load_1m = load.Load1
    s.Load_5m = load.Load5
    s.Load_15m = load.Load15
    s.Macs_discovered = atomic.LoadInt64(&macs_discovered)
    s.Macs_discovered_total = atomic.LoadInt64(&macs_discovered_total)
    s.Macs_sent = atomic.LoadInt64(&macs_notified)
    s.Macs_sent_total = atomic.LoadInt64(&macs_notified_total)
    //s.Uptime = time.Since(start_time)
    s.Uptime = time_now - start_time.Unix()

    return s

}

/* choose what fields we put in log */
func Logrus_fields(s MainStats) logrus.Fields {
    result := logrus.Fields{
        "snifs"            : s.Snifs,
        "goroutines"       : s.Goroutines,
        "load"             : s.Load_prcnt,
        "mem"              : s.Mem_usage,
        "pps"              : s.Pps,
        "macs_sent"        : s.Macs_sent,
        "macs_discovered"  : s.Macs_discovered,
    }
    return result
}


/* POST statiscics and log it from time to time
stats_period var (logtime parameter)
 */
func print_stats() {
    for {
        
        stat := CollectStats()
        snifs := GetSnifs()

        data := CombinedStats{ Main : stat, Snifs : snifs, }

        logfields := Logrus_fields(stat)

        log.WithFields(logfields).Info(  //Trace
            "statistics for ",stat.Period," seconds:")

        main_cache.Lock() 
        j, _ := json.Marshal(data)
        main_cache.Unlock()
        PostJson(j,STATS_URL)

        //reset counters
        atomic.SwapInt64(&macs_discovered, 0)
        atomic.SwapInt64(&packets_count, 0)
        atomic.SwapInt64(&macs_notified, 0)        

        time.Sleep(time.Duration(stat.Period) * time.Second)
    }

}


/* periodical check in cache for jobs and remove old notes */
func cache_handler() {

    for {
        //start := time.Now()

        //notif_list := make(map[string][]interface{})
        notif_list := []interface{}{}

        main_cache.Lock()
        cache_map := main_cache.snifs

        for j,sn := range cache_map {
            if sn.Update_time != 0 {
                st_p := atomic.LoadInt64(&post_period)

                sn.Pps = sn.Packets_period / st_p // + 1

                macs_cached := len(sn.macs)

                log.WithFields(logrus.Fields{
                "snifid": sn.Id,
                "snifip": sn.Ip,
                "macs_cached": macs_cached,
                "packets": sn.Packets_period,
                "p_total": sn.Packets_total,
                "pps": sn.Pps,
                }).Debug(  //Trace
                "a sniffer statistics")

                sn.Packets_period = 0
                
                sn.New_macs = 0
                sn.Post_macs = 0
                sn.Macs_cached = macs_cached             

                for i,vi := range sn.macs {

                    if !vi.notified { // vi.notif_time < time.Now().Unix() && !vi.notified
                        // append to notif_list the mac
                        t := strconv.FormatInt(vi.update_time, 10)
                        //t := strconv.FormatInt(vi.update_time/1e9, 10)
                        
                        var rssi_avg int64 = -127
                        if vi.count_as_addr2 > 0 {rssi_avg = vi.RSSI_sum / vi.count_as_addr2}

                        vi.notified_count++

                        log.WithFields(logrus.Fields{
                        "snifid": vi.sensor_id,
                        "snifip": vi.src_ip,
                        "kn_from": vi.first_time,
                        "last_ts": t,
                        "mac": vi.mac,
                        "Ch" : vi.channel,
                        "FrCnt" : vi.count_as_addr2,
                        //"vendor" :  vi.vendor,
                        "Notif" :vi.notified_count,
                        "rssi_avg" :  rssi_avg,
                        "rssi_max" :  vi.RSSI_max}).Debug(  //Trace
                        "the mac is ready to POST")

                        data := map[string]string{
                            "SnifID" : vi.sensor_id,
                            "SnifIP" : vi.src_ip,
                            "MAC" : vi.mac,
                            "Channel" : strconv.FormatInt(vi.channel, 10),
                            "Vendor" : vi.vendor,                        
                            "KnownFrom" : strconv.FormatInt(vi.first_time, 10),
                            "LastSeen" : t,
                            "RSSImax" : strconv.FormatInt(vi.RSSI_max, 10),
                            //"RSSI" : strconv.FormatInt(vi.RSSI_current, 10),
                            "RSSI" : strconv.FormatInt(rssi_avg, 10),
                            "NotifiedCount" : strconv.FormatInt(vi.notified_count, 10),
                            "FramesCount" : strconv.FormatInt(vi.count_as_addr2, 10),
                        }

                        notif_list = append(notif_list,data)
                        sn.Post_macs ++

                        //vi.notif_time = time.Now().Unix() + notification_time
                        vi.notified = true

                        vi.count_as_addr1 = 0
                        vi.count_as_addr2 = 0
                        vi.count_as_addr3 = 0
                        vi.count_as_addr4 = 0
                        vi.RSSI_max = 0
                        vi.RSSI_sum = 0
                        //fmt.Println(vi)
                        sn.macs[i] = vi
                    }

                    if vi.update_time + atomic.LoadInt64(&mac_remember_cache) < time.Now().Unix() {
                        delete(sn.macs, i)

                        log.WithFields(logrus.Fields{
                        "cache" : i,
                        "sensor": vi.sensor_id,
                        "mac": vi.mac,
                        "vendor" :  vi.vendor,
                        "rssi_last" :  vi.RSSI_current,
                        "rssi_max" :  vi.RSSI_max,
                        "first_time" : vi.first_time,
                        "sent" :vi.notified,
                        "sent_count": vi.notified_count,
                        }).Trace("An old MAC has been Removed from cache:")
                    }
                }
                cache_map[j] = sn
            }
        }

        //captured_macs_cache.m = cache_map
        //log.Debug("Cache len %s post_macs took: %s ",len(cache_map), time.Since(start))
        main_cache.Unlock()

        
        if len(notif_list) > 0 { go PostMacList(notif_list) }

        captured_AP_cache.Lock()
        AP_cache := captured_AP_cache.m
        for i,vi := range AP_cache {
            if vi.remove_time != 0 && vi.remove_time < now_u {
            	delete(AP_cache, i)
            	log.Trace("The AP has been REMOVED from cache (timeout):",vi.mac) 
            }
        }

        captured_AP_cache.m = AP_cache
        captured_AP_cache.Unlock()


        time.Sleep(time.Duration(atomic.LoadInt64(&post_period) * 1000) * time.Millisecond)
    }
}

func PostJson(jsonValue []byte, url string) {
    req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))

    if err != nil {
        log.WithFields(logrus.Fields{
            "error": err, "server url": url}).Error(
            "Can not make http request. Bad URL? ")
    }

    //req.Header.Set("X-Custom-Header", "myvalue")
    req.Header.Set("Content-Type", "application/json")
    if TOKEN != "" {
        BEARER_TOKEN := "Bearer " + TOKEN
        req.Header.Add("Authorization", BEARER_TOKEN)
    }

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        log.WithFields(logrus.Fields{
            "error": err, "server url": url}).Error(
            "Can not send request to http server. ")
    } else {
        defer resp.Body.Close()    
        log.Debug("Posted statistics. Response Status:'", resp.Status)
    }         
}


/* post new macs in cache as list */
func PostMacList(list []interface{}) { // map[string][]interface{}

    jsonValue, _ := json.Marshal(list)
    req, err := http.NewRequest("POST", NOTIF_URL, bytes.NewBuffer(jsonValue))

    if err != nil {
        log.WithFields(logrus.Fields{
            "error": err, "server url": NOTIF_URL}).Error(
            "Can not make notif http request. Bad URL? ")
    }

    //req.Header.Set("X-Custom-Header", "myvalue")
    req.Header.Set("Content-Type", "application/json")
    if TOKEN != "" {
        BEARER_TOKEN := "Bearer " + TOKEN
        req.Header.Add("Authorization", BEARER_TOKEN)
    }

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        log.WithFields(logrus.Fields{
            "error": err, "server url": NOTIF_URL}).Error(
            "Can not send request to http server. ")
    } else {
    defer resp.Body.Close()

    atomic.SwapInt64(&macs_notified, atomic.LoadInt64(&macs_notified)  + int64(len(list)))        
    atomic.SwapInt64(&macs_notified_total, atomic.LoadInt64(&macs_notified_total)  + int64(len(list)))

    log.Debug("POST MAC-list. Response Status:'", resp.Status,"'. MACS sent:",len(list))//,
    }
}

