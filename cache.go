package main

import (
    "time"
	//"fmt"
    //"reflect"
    "sync"
    "sync/atomic"
)

var (
    //bad_snifs_cache  = make(map[string]BadSnifStruct)

    // active_sniffers = struct{
    //     sync.RWMutex
    //     m map[string]bool
    // }{m: make(map[string]bool)}

    bad_snifs_cache = struct{
        sync.RWMutex
        m map[string]BadSnifStruct
    }{m: make(map[string]BadSnifStruct)}
	//captured_AP_cache  = make(map[string]captured_AP)//cache for captured APs

    captured_AP_cache = struct{
        sync.RWMutex
        m map[string]captured_AP
    }{m: make(map[string]captured_AP)} 

//    m map[string]captured_MAC
    //cache for captured macs 
	// captured_macs_cache = struct{
 //        sync.RWMutex
 //        m map[string]captured_MAC
 //    }{m: make(map[string]captured_MAC)} 

    main_cache = struct{
        sync.RWMutex
        snifs map[string]captured_snif
    }{snifs: make(map[string]captured_snif)} 

	mac_remember_cache int64 = 300 // The MAC will be erased from cache after the time inactive
    snif_remember_cache int64 = 2592000 // The snif will be erased from cache after the time inactive
    badsnif_remember_cache int64 = 60
)
//                                   *** CAPTURED AP MACS CACHE ***



// cache for bad sniffers
func CacheBadSnif(c BadSnifIface) {
    //bad_snifs_cache.Lock()
    if c.cached() {
        //log.Info("Bad snif is in cache already:",c.showip())
        c.update()
    } else {
        c.save()
        log.Error("Bad snif! (Saved in cache as bad and will be ignored):",c.id())
        //log.Trace("cache length:",len(captured_macs_cache))
    }
    //bad_snifs_cache.Unlock()
}

/* interface for  bad snifs */
type BadSnifIface interface {
    cached() bool
    dobby_is_free() bool
    update()
    save()
    id() string
}

type BadSnifStruct struct {
    // bad snifs to ignore cache struct
    //RSSI_current,RSSI_max,position,
    //notif_time,notified_count int64
    first_time,update_time, remove_time int64
    sensor_ip string
}

func (m *BadSnifStruct) id() string {
    return m.sensor_ip
}

func (m *BadSnifStruct) cached() bool {
    // fmt.Println("ID:",m.id())
    // fmt.Println("CACHE:",bad_snifs_cache[m.id()])
    // fmt.Println("M:",m)
    if bad_snifs_cache.m[m.id()].first_time == 0 {
        //log.Trace("new bad snif: ",m.id())
        return false
    } else {
        //log.Trace("old bad snif: ",m.id())
        return true
    }
}

func (m *BadSnifStruct) dobby_is_free() bool {

    if bad_snifs_cache.m[m.id()].remove_time > time.Now().Unix() {
        return true
    } else {
        return false
    }
}

func (m *BadSnifStruct) update() { // m is the data from packet!
    cached := bad_snifs_cache.m[m.id()]
    cached.update_time = now.UnixNano()
    cached.remove_time = time.Now().Unix() + badsnif_remember_cache 
    //bad_snifs_cache.m[m.id()] = cached
}

func (m *BadSnifStruct) save() {
    m.first_time = time.Now().Unix()
    bad_snifs_cache.m[m.id()] = *m
    m.update()
}

/* Here’s a basic interface for cache handlers. */
type cache_int interface {

    store() (bool, error)
    //get_map() *map[string]captured_MAC
    //get_item() captured_MAC
    lock()
    unlock()

}

/* structure of cache for captured APs */
type captured_AP struct {
    //count_as_addr1,count_as_addr2,count_as_addr3,count_as_addr4 int64
    //RSSI_current,RSSI_max,position,
    //notif_time,notified_count int64
    first_time,update_time, remove_time int64
    src_ip,sensor_id,mac,vendor string
    //notified bool
}

func (m captured_AP) id() string {
    return m.sensor_id+"_"+m.mac
}

func (m captured_AP) name() string {
    return "captured_AP_cache"
}

// func (m captured_AP) get_map() *map[string]captured_AP {
//     return &captured_AP_cache.m
// }

// func (m captured_AP) get_item() captured_AP {
//     return captured_AP_cache.m[m.id()]
// }

func (m captured_AP) lock() {
    captured_AP_cache.Lock()
}

func (m captured_AP) unlock() {
    captured_AP_cache.Unlock()   
}


// func (m *captured_AP) item_exists() bool {
//     // fmt.Println("ID:",m.id())
//     // fmt.Println("CACHE:",captured_macs_cache[m.id()])
//     // fmt.Println("M:",m)
//     return captured_AP_cache[m.id()].first_time != 0
// }

func ap_cached(sensor string,mac string) bool {
    captured_AP_cache.Lock()
	result :=  captured_AP_cache.m[sensor+"_"+mac].first_time != 0
    captured_AP_cache.Unlock()
    return result
}

/* update counters in cache */
// func (m *captured_AP) update_cache() {
//     m.do_update()    
// }

/* save counters in cache (for just captured macs) */
func (m captured_AP) store() (bool, error) {
    result := false

    cache := captured_AP_cache.m[m.id()] // m.get_item()

    if cache.first_time == 0 {
        cache = m
        cache.first_time = time.Now().Unix()
        //log.Trace(cache.name()," - The NEW AP stored: ",cache.id())
        result = true   
    }

    cache.update_time = time.Now().UnixNano()
    cache.remove_time = time.Now().Unix() + atomic.LoadInt64(&mac_remember_cache) 
    captured_AP_cache.m[m.id()] = cache

    return result, nil
}

//												* - *



//                                   *** CAPTURED MACS CACHE ***
/*basic interface for data to cache*/

/* structure of cache for captured MACs */
type captured_MAC struct {
    count_as_addr1,count_as_addr2,count_as_addr3,count_as_addr4 int64
    RSSI_current,RSSI_max,RSSI_sum,
    position,channel,notified_count int64
    first_time,update_time int64
    src_ip,sensor_id,mac,vendor string
    notified bool
}

func (m captured_MAC) store() (bool, error) { // m is the data from packet!
    //cached := captured_macs_cache[m.id()]
    new := false
    snif := main_cache.snifs[m.sensor_id]

    cache := snif.macs[m.mac]

    if cache.first_time == 0 {
        snif.New_macs ++
        cache = m
        cache.first_time = time.Now().Unix()
        log.Trace(cache.sensor_id," - The NEW MAC stored in cache: ",cache.mac)
        new = true  
    } else {
        cache.channel = m.channel
        cache.src_ip = m.src_ip
    }
    
    cache.notified = false // switch off the flag if MAC apears
    cache.update_time = time.Now().UnixNano()    

    if m.position == 2 {
        if m.RSSI_current != 127 {
            cache.RSSI_sum = cache.RSSI_sum + m.RSSI_current    
        }
        
        cache.RSSI_current = m.RSSI_current

        if cache.RSSI_max == 0 { 
            cache.RSSI_max = m.RSSI_current
        } else {
            if cache.RSSI_max < m.RSSI_current { cache.RSSI_max = m.RSSI_current }    
        } 
    } else {
        cache.RSSI_current = -1000 //rssi from the device (itself) is unknown here
    }
    switch m.position {
    case 1:
        cache.count_as_addr1++
    case 2:
        cache.count_as_addr2++
    case 3:
        cache.count_as_addr3++
    case 4:
        cache.count_as_addr4++
    }

    snif.macs[m.mac] = cache
    main_cache.snifs[m.sensor_id] = snif
    //main_cache.snifs[m.sensor_id].macs[m.mac] = cache

    return new, nil

}


func (m captured_MAC) lock() {
    main_cache.Lock()
}

func (m captured_MAC) unlock() {
    main_cache.Unlock()    

}


//                                   ***  MAIN CACHE ***
/*basic interface for data to cache*/

/* structure of cache for captured MACs */
type captured_snif struct { 
    Ip string                       `json:"ip"`
    Id string                       `json:"id"`    
    Pps int64                       `json:"pps"`
    Packets_total int64             `json:"total_cnt"`
    Packets_period int64            `json:"pct_cnt"`
    First_time int64                `json:"ts_first"`
    Update_time int64               `json:"ts_last"`
    Badsnif bool                    `json:"badsnif"`
    macs map[string]captured_MAC    `json:"-"`
    New_macs int64                  `json:"new_macs"`
    Post_macs int64                 `json:"post_macs"`
}

func (new captured_snif) store() (bool, error) { // m is the data from packet!
    //cached := captured_macs_cache[m.id()]
    result := false

    cache := main_cache.snifs[new.Id]

    if cache.First_time == 0 { // if new sniffer in cache
        cache = new
        cache.macs = make(map[string]captured_MAC)
        cache.First_time = time.Now().Unix()
        log.Debug(cache.Id,": the NEW Snif has been detected with ip: ",cache.Ip)
        result = true
    }
    if cache.Ip != new.Ip  {
        log.Warning("%s: ip is changed: (old:%snew%s)",cache.Id,cache.Ip,new.Ip)
        cache.Ip = new.Ip
    }
    cache.Packets_total ++
    cache.Packets_period ++

    cache.Update_time = time.Now().UnixNano()

/* other here */

    main_cache.snifs[cache.Id] = cache
    return result, nil

}

func (m captured_snif) lock() {
    main_cache.Lock()
}

func (m captured_snif) unlock() {
    main_cache.Unlock()    

}

/* Generic function to store data in cache. returns  True if new */
func SaveItInCache(l cache_int) (bool,error) {
    l.lock()
    result,err := l.store()
    l.unlock()

    return result,err

}

func CountSnifs() int {
    main_cache.Lock()
    result := len(main_cache.snifs)
    main_cache.Unlock()
    return result
}


/* output statistics as json */
func GetSnifs() map[string]captured_snif {
    main_cache.Lock()
    result := main_cache.snifs
    main_cache.Unlock()
    return result

    // if err != nil{
    //     log.Error("json err: ",err)
    //     return nil
    // } else {
    //     return result
    // }    
}
            // data := map[string]string{
            //     "id": vi.id, //strconv.FormatInt(vi.id, 10),
            //     "ip": vi.ip, // strconv.FormatInt(vi.ip, 10),
            //     "macs": strconv.Itoa(len(vi.macs)),
            //     "post_macs": strconv.FormatInt(vi.post_macs, 10),
            //     "new_macs": strconv.FormatInt(vi.new_macs, 10),
            //     "pps": strconv.FormatInt(vi.pps, 10),
            //     "pct_cnt": strconv.FormatInt(vi.packets_period, 10),
            //     "total_cnt": strconv.FormatInt(vi.packets_total, 10),
            //     "ts_first": strconv.FormatInt(vi.first_time, 10),
            //     "ts_last": strconv.FormatInt(vi.update_time/1000000000, 10),
