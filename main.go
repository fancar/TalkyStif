package main

import (
    "os"
    "io"
    "time"
    "net"
    //"strings"
    "strconv"
    "runtime"
    "enforta/tzspanalyser"
    "github.com/sirupsen/logrus"
    "encoding/json"
    "net/http"
    "bytes"
    "sync"
    "sync/atomic"
    //"github.com/google/go-cmp/cmp"
   // "reflect"
   // "fmt"    
)

var (
    mutex = &sync.Mutex{}    
    ouiFileName string = "oui.txt"
    //ouiDBrenew_hours time.Duration  = 1 // when file expire hours
    ouiDBrenew_period time.Duration // when file expire we are going to download newone
    //FilterByVendor bool = false
    check_all_macs bool = false
    
    packets_count int64 // packets have been counted in post_period
    macs_discovered,macs_notified,macs_discovered_total,macs_notified_total int64

    //frame types to ignore
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

    //flags to ignore
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

    r := NewRouter()
    http.Handle("/", r)
    log.Fatal(http.ListenAndServe("0.0.0.0:8087", nil))
    
    <-quit // hang until an error
    log.Info("Exit")
}

/* download a file from the internet */
func DownloadFile(filepath string, url string) error {
    log.Info("downloading...",url)
    // Get the data
    resp, err := http.Get(url)
    ErrorAndExit("can't get http url",err)    

    defer resp.Body.Close()

    // Create the file
    out, err := os.Create(filepath)
    if err != nil {
        return err
    }
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
        Dot11,_ := tzspanalyser.ParseDot11(Raw_fr)

        // if err != nil {
        //     log.Trace("Some warning while parsing dot11 layer: ",err)
        // }

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

        // if len(Dot11.Address2) != 0 && cmp.Equal(Dot11.Address2, Dot11.Address3) {
    			 //       // fmt.Println("vendor",vendor)
        // 	APmac := Dot11.Address2
        // 	//log.Info("found beacon from ",APmac)
    	   //  c := captured_AP{
        //     src_ip: udp.IP.String(),
        //     vendor: VendorName(APmac),
        //     sensor_id: tzsp["sensor_id"].(string),
        //     mac: APmac.String()}
        // 	CacheAP(c)
        // 	continue
        // }

        if Dot11.Type.String() == "MgmtProbeReq" {
    	mac := Dot11.Address2
        	if len(mac) != 0 {
        		if MacIsFine(mac) {

        			//if ap_cached(tzsp["sensor_id"].(string),mac.String()) { continue }
        			vendor := VendorName(mac)
        			//fmt.Println("vendor:",vendor)

                    // ignore some frame types , vendors and flags...
                    //flags := strings.Split(Dot11.Flags.String(), ",")
        			// if !ignore_frames[Dot11.Type.String()] && !ignore_vendors[vendor] &&
           //          !ignore_flags[flags[0]] {

                        log.WithFields(logrus.Fields{
                            "sensor_id": tzsp["sensor_id"], "sensor_ip": udp.IP,
                            "Type" :    Dot11.Type, "Flags" :  Dot11.Flags,
                            "mac1": Dot11.Address1, "mac2": Dot11.Address2,
                            "mac3": Dot11.Address3, "mac4": Dot11.Address4,
                            "vendor" : vendor,
                            "RSSI" :  tzsp["RSSI"]}).Trace("active_mac="+mac.String()) 

        			    c := captured_MAC{
        	            src_ip: udp.IP.String(),
        	            vendor: vendor,
        	            sensor_id: tzsp["sensor_id"].(string),
        	            mac: mac.String(),
                        channel: tzsp["rx_channel"].(int64),
        	            position: 2,
        	            RSSI_current: tzsp["RSSI"].(int64)}

        	        	CacheMac(c)
        			//}
        		}
        	}
        }   	
    	    
    }

    log.Error("UDP port listen error:",err_)
    quit <- struct{}{}
}   

/* just mark the sniffer as active (for counter) */
func snif_is_active(mac string,ip string) bool {
    s := captured_snif{id:mac,ip:ip}

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
        
        log.Debug("New mac saved in cache:",c.mac," ",c.vendor)
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

/* put some info in logs from time to time */
func print_stats() {

    for {
        //log.Debug("HERE STATISTICS")

        main_cache.Lock()
        snifs_no := len(main_cache.snifs)
        main_cache.Unlock()

        st_p := atomic.LoadInt64(&stats_period)

        log.WithFields(logrus.Fields{
            "active snifs" : snifs_no,
            "goroutines" : runtime.NumGoroutine(),
            "period_seconds": st_p,
            "period avg pps" : atomic.LoadInt64(&packets_count) / st_p + 1, // atomic.LoadUint64(
            "macs_discovered_period": atomic.LoadInt64(&macs_discovered),
            "macs_sent_period" :  atomic.LoadInt64(&macs_notified),
            "macs_discovered_total" :  atomic.LoadInt64(&macs_discovered_total),
            "macs_sent_total": atomic.LoadInt64(&macs_notified_total),
            //"captured_macs_cache_len": len(captured_macs_cache),
            //"captured_AP_cache_len":len(captured_AP_cache),
            "uptime": time.Since(start_time)}).Info(  //Trace
            "running info")	

        //reset counters
        atomic.SwapInt64(&macs_discovered, 0)
        atomic.SwapInt64(&packets_count, 0)
        atomic.SwapInt64(&macs_notified, 0)

        time.Sleep(time.Duration(st_p * 1000) * time.Millisecond)
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
            if sn.update_time != 0 {
                st_p := atomic.LoadInt64(&post_period)

                sn.pps = sn.packets_period / st_p + 1

                log.WithFields(logrus.Fields{
                "snifid": sn.id,
                "snifip": sn.ip,
                "macs": len(sn.macs),
                "packets": sn.packets_period,
                "p_total": sn.packets_total,
                "pps": sn.pps,
                }).Debug(  //Trace
                "a sniffer statistics")

                sn.packets_period = 0
                
                sn.new_macs = 0
                sn.post_macs = 0                

                for i,vi := range sn.macs {

                    if !vi.notified { // vi.notif_time < time.Now().Unix() && !vi.notified
                        // append to notif_list the mac
                        t := strconv.FormatInt(vi.update_time/1000000000, 10)
                        
                        var rssi_avg int64 = -127
                        if vi.count_as_addr2 > 0 {rssi_avg = vi.RSSI_sum / vi.count_as_addr2}

                        vi.notified_count++

                        log.WithFields(logrus.Fields{
                        "snifid": vi.sensor_id,
                        "snifip": vi.src_ip,
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
                        sn.post_macs ++

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
                        }).Trace("MAC inactive. Removed from cache")
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
            	log.Trace("REMOVED AP from cache:",vi.mac) 
            }
        }

        captured_AP_cache.m = AP_cache
        captured_AP_cache.Unlock()


        time.Sleep(time.Duration(atomic.LoadInt64(&post_period) * 1000) * time.Millisecond)
    }

}


/* post new macs in cache as list */
func PostMacList(list []interface{}) { // map[string][]interface{}

    //log.Trace("Current list to POST: ",list)
    jsonValue, _ := json.Marshal(list)
    req, err := http.NewRequest("POST", NOTIF_URL, bytes.NewBuffer(jsonValue))

    req.Header.Set("X-Custom-Header", "myvalue")
    req.Header.Set("Content-Type", "application/json")

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
    // for _,s := range list {

    //     atomic.SwapInt64(&macs_notified, atomic.LoadInt64(&macs_notified)  + int64(len(s)))
    //     atomic.SwapInt64(&macs_notified_total, atomic.LoadInt64(&macs_notified_total)  + int64(len(s)))
        //macs_notified = macs_notified + int64(len(s))
        //macs_notified_total = macs_notified_total + int64(len(s))
    //}
    //body, _ := ioutil.ReadAll(resp.Body)   // need to uncomment "io/ioutil"
    log.Debug("POST MAC-list. Response Status:'", resp.Status,"'. MACS sent:",len(list))//,
        //" Response Headers:", resp.Header,
        //" Response Body:", string(body))
    }
}

