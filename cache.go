package main

import (
    "github.com/sirupsen/logrus"
    "time"
	"fmt"
    //"reflect"
    "sync"
    "sync/atomic"
    // "runtime"
)

var (

    bad_snifs_cache = struct{
        sync.RWMutex
        m map[string]*BadSnifStruct
    }{m: make(map[string]*BadSnifStruct)}

    snif_cache = struct{
        sync.RWMutex
        snifs map[string]*captured_snif
    }{snifs: make(map[string]*captured_snif)} 

    // mac_cache = struct{
    //     sync.RWMutex
    //     macs map[string]captured_MAC
    // }{macs: make(map[string]captured_MAC)}     

)

// INTERFACES

/* interface for  bad snifs */
type BadSnifIface interface {
    cached() bool
    dobby_is_free() bool
    update()
    save()
    id() string
}


// STRUCTURES

/* structure for MAC's data */
type captured_MAC struct {
    Sensor_id string                `json:"SnifID"`
    Src_ip string                   `json:"SnifIP"`
    Mac string                      `json:"MAC"`
    Channel int64                   `json:"Channel"`
    Vendor string                   `json:"Vendor"`
    First_time int64                `json:"KnownFrom"`
    Update_time int64               `json:"LastSeen"`
    RSSI_max int64                  `json:"RSSImax"`
    RSSI_current int64              `json:"RSSI"`
    Notified_count int64            `json:"NotifiedCount"`
    Frames_count int64              `json:"FramesCount"`
    post_period int64 
    send_it bool
}


/* structure of cache for captured MACs */
type captured_snif struct {
    macs map[string]*captured_MAC    `json:"-"`
    Ip string                       `json:"ip"`
    Id string                       `json:"id"`    
    Packets_period int64            `json:"pct_cnt"`
    First_time int64                `json:"ts_first"`
    Update_time int64               `json:"ts_last"`
    Badsnif bool                    `json:"badsnif"`
    Macs_cached int                 `json:"macs_cached"`        
    Pps int64                       `json:"pps"`

    // Macs_cnt int64                  `json:"macs_cnt"`
    // Packets_total int64             `json:"total_cnt"`    
    // New_macs int64                  `json:"new_macs"` 
    // Post_macs int64                 `json:"post_macs"`
}

//                                   *** BADSNIF CACHE ***

/* returns true if snif in bad cache */
func SnifIsBad(ip string) bool {
    result := false
    junk_snif := &BadSnifStruct{ sensor_ip: ip }

    bad_snifs_cache.Lock()

    if junk_snif.cached() {
        if junk_snif.dobby_is_free() {
            delete(bad_snifs_cache.m, ip)
            log.Trace("The DEVICE IS REMOVED FROM BAD SNIF CACHE! (TIME IS OUT): ",ip )
        } else {
            log.Trace("The DEVICE IS MARKED AS BAD!: ",ip)
            result = true
        }
    }
    bad_snifs_cache.Unlock()
    return result
}

/* save in cache as bad snif */
func CacheBadSnif(ip string) {
    c := &BadSnifStruct{ sensor_ip: ip }
    //time.Sleep(timewait * time.Second) 
    bad_snifs_cache.Lock()

    if c.cached() {
        c.update()
    } else {
        c.save()
    }
    bad_snifs_cache.Unlock()
}

type BadSnifStruct struct {
    // 
    //RSSI_current,RSSI_max,position,
    //notif_time,notified_count int64
    first_time,update_time, remove_time int64
    sensor_ip string
}

func (m *BadSnifStruct) id() string {
    return m.sensor_ip
}

func (m *BadSnifStruct) cached() bool {
    return bad_snifs_cache.m[m.id()] != nil
    // return bad_snifs_cache.m[m.id()].first_time != 0
}

func (m *BadSnifStruct) dobby_is_free() bool {
    return bad_snifs_cache.m[m.id()].remove_time > time.Now().Unix()
}

func (m *BadSnifStruct) update() { // m is the data from packet!
    cached := bad_snifs_cache.m[m.id()]
    cached.update_time = time.Now().UnixNano()
    cached.remove_time = time.Now().Unix() + atomic.LoadInt64(&CFG_CACHE_BADSNIF_TIMEOUT)
    //bad_snifs_cache.m[m.id()] = cached
}

func (m *BadSnifStruct) save() {
    m.first_time = time.Now().Unix()
    bad_snifs_cache.m[m.id()] = m
    m.update()
}

//                                   *** CAPTURED MACS CACHE ***
/*basic interface for data to cache*/


/* store/append mac-cache with data from packet,
returns 'notified' boolean state */
func (m *captured_MAC) store() (captured_MAC, error) {
    snif := snif_cache.snifs[m.Sensor_id]
    cache := snif.macs[m.Mac]
    // cache := mac_cache.macs[m.Mac]

    // if cache.First_time == 0 { // old for non pointer storage
    if cache == nil {
        cache = m
        cache.Notified_count = 1
        atomic.AddInt64(&macs_discovered, 1)
        atomic.AddInt64(&macs_discovered_total, 1)
        // snif.Macs_cnt ++

        cache.post_period = atomic.LoadInt64(&CFG_NOTIF_PERIOD)
        cache.First_time = time.Now().Unix()
        cache.send_it = true // switch on the flag if MAC apears
        log.WithFields(logrus.Fields{"snif":m.Sensor_id,"mac":m.Mac}).Debug("[CACHE] New MAC stored")
    } else {
        cache.send_it = cache.time_to_send()
        //log.Info(cache.Mac," - send_it value: ",cache.send_it)
        if cache.send_it { cache.Notified_count++ }
        cache.Channel = m.Channel
        cache.Src_ip = m.Src_ip
        cache.RSSI_current = m.RSSI_current
    }
    
    cache.Update_time = time.Now().Unix()

    if cache.RSSI_max == 0 { 
        cache.RSSI_max = m.RSSI_current
    } else {
        if cache.RSSI_max < m.RSSI_current { cache.RSSI_max = m.RSSI_current }    
    } 

    cache.Frames_count++
    
    // mac_cache.macs[m.Mac] = cache
    // snif_cache.snifs[m.Sensor_id].macs[m.Mac] = cache
    snif.macs[m.Mac] = cache
    snif_cache.snifs[m.Sensor_id] = snif

    return *cache, nil

}

/* Check if it is time to send */
func (m *captured_MAC) time_to_send() bool {
    return m.Update_time + m.post_period < time.Now().Unix()
}

func (m *captured_MAC) lock() {
    snif_cache.Lock()
}

func (m *captured_MAC) unlock() {
    snif_cache.Unlock()    

}



func (new *captured_snif) store() (*captured_snif, error) { // m is the data from packet!
    //cached := captured_macs_cache[m.id()]
    cache := snif_cache.snifs[new.Id]

    // if cache.First_time == 0 { // if new sniffer in cache
    if cache == nil { // if new sniffer (not in cache yet)
        cache = new
        cache.macs = make(map[string]*captured_MAC)
        cache.First_time = time.Now().Unix()
        log.Trace(cache.Id,": the NEW Snif has been detected with ip: ",cache.Ip)
    }
    if cache.Ip != new.Ip  {
        f := logrus.Fields{"snif":cache.Id,"oldip":cache.Ip,"newip":new.Ip}
        log.WithFields(f).Warning("[CACHE] ip has changed")
        cache.Ip = new.Ip
    }
    // cache.Packets_total ++
    cache.Packets_period ++

    //cache.Update_time = time.Now().UnixNano()
    cache.Update_time = time.Now().Unix()

    snif_cache.snifs[cache.Id] = cache
    return cache, nil

}

func (m *captured_snif) lock() {
    snif_cache.Lock()
}

func (m *captured_snif) unlock() {
    snif_cache.Unlock()    

}

func CountSnifs() int {
    snif_cache.Lock()
    result := len(snif_cache.snifs)
    snif_cache.Unlock()
    return result
}

/* output statistics as json */
func GetSnifs() map[string]*captured_snif {
    snif_cache.Lock()
    result := snif_cache.snifs
    snif_cache.Unlock()
    return result
}



/* periodical check in cache for jobs and remove old notes 
*/
func cache_cleaner() {

    for {
        start := time.Now()
        var macs_total int // total num of macs in cache for all snifs
        var macs_removed int64
        var snifs_removed int64

        snif_cache.Lock()
        cache_map := snif_cache.snifs

        for j,sn := range cache_map {

            if sn.Update_time + atomic.LoadInt64(&CFG_CACHE_SNIF_TIMEOUT) < time.Now().Unix() {
                delete(cache_map, j)
                snifs_removed++
                log.Debug("[CACHE CLEAN] removed inactive sniffer: ",sn.Id,"-",sn.Ip)
                continue
            }

            for i,vi := range sn.macs {

                if vi.Update_time + atomic.LoadInt64(&CFG_CACHE_MAC_TIMEOUT) < time.Now().Unix() {
                    delete(sn.macs, i)
                    macs_removed++

                    log.WithFields(logrus.Fields{
                    "sensor": vi.Sensor_id,
                    "mac": vi.Mac,
                    "vendor" :  vi.Vendor,
                    "rssi_last" :  vi.RSSI_current,
                    "rssi_max" :  vi.RSSI_max,
                    "first_time" : vi.First_time,
                    "sent" :!vi.send_it,
                    "sent_count": vi.Notified_count,
                    }).Trace("[CACHE CLEAN] An old MAC has been Removed")
                }
            }
            st_p := atomic.LoadInt64(&CFG_CACHE_CHECK)
            sn.Pps = sn.Packets_period / st_p

            sn.Macs_cached = len(sn.macs)
            macs_total += sn.Macs_cached

            log.WithFields(logrus.Fields{
            "snifid": sn.Id,
            "snifip": sn.Ip,
            "macs_cached": sn.Macs_cached,
            "pps": sn.Pps,
            "packets": sn.Packets_period,
            // "p_total": sn.Packets_total,
            
            }).Debug(  //Trace
            "snif-statistics for period (seconds):",st_p)

            sn.Packets_period = 0            
            cache_map[j] = sn
        }
        // runtime.GC() //collect garbage и

        s := fmt.Sprintf("[CACHE CLEAN] Cached/Removed_old: snifs: %d/%d, macs: %d/%d. It took: %s ",
            len(cache_map),snifs_removed,macs_total,macs_removed,time.Since(start))
        log.Info(s)
        snif_cache.Unlock()


        time.Sleep(time.Duration(atomic.LoadInt64(&CFG_CACHE_CHECK)) * time.Second)
    }
}