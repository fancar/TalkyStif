package main

import (
	"strings"
	"os"
	"github.com/spf13/viper"
)
/*
Here we're going to read config by viper lib
https://github.com/spf13/viper
 */
const (
    ouiFileName string = "oui.txt"
    httpserver_ip_port string = "0.0.0.0:8087"
)

var (
	//kafka
	CFG_KAFKA_ENABLED bool = false
	CFG_KAFKA_TOPIC string
	CFG_KAFKA_SERVERS string
	CFG_KAFKA_LINGERMS int = 1000 

	//urls
	CFG_NOTIF_ENABLED bool = true
	CFG_NOTIF_URL string
	CFG_NOTIF_PERIOD int64 = 5 // seconds 
	CFG_POST_PERIOD int64 = 5 // how frequent to post if not many macs
	CFG_POST_MACS_MAX int64 = 300000 // how frequent to post if not many macs
	CFG_STATS_URL string
	CFG_STATS_PERIOD int64 = 60
	CFG_TOKEN string
	//logs
	CFG_LOG_WRITEFILE bool
	CFG_LOG_LEVEL string
	CFG_LOG_FNAME string
	//oui database
	CFG_OUI_RENEW_PERIOD int64 = 720
	CFG_OUI_URL string
	//cache
	CFG_CACHE_CHECK int64 = 60
	CFG_CACHE_MAC_TIMEOUT int64 = 300 // The MAC will be erased from cache after the time inactive
    CFG_CACHE_SNIF_TIMEOUT int64 = 2592000 // The snif will be erased from cache after the time inactive
    CFG_CACHE_BADSNIF_TIMEOUT int64 = 60	

    //counters
    packets_count int64 // packets have been counted in CFG_NOTIF_PERIOD of time
    macs_discovered,macs_notified,macs_discovered_total,macs_notified_total int64
    kafka_errors_count, kafka_errors_count_total int64
    post_count, post_count_total int64
    post_errors_count, post_errors_count_total int64
)


func ReadConfig(fname string) {
	f := strings.Split(fname,".")
	viper.SetConfigName(f[0])
	viper.SetConfigType(f[1])

	// for developlent
	//dirpath := "/home/fancar/go/src/enforta/TalkyStif/"
	//viper.AddConfigPath(dirpath) 

	// for bin
	viper.AddConfigPath(".") 

	if err := viper.ReadInConfig(); err != nil {
		log.Error(err)
	    if _, ok := err.(viper.ConfigFileNotFoundError); ok {
	    	log.Fatal("config.yaml not found")
	        // Config file not found; ignore error if desired
	    } else {
	        // Config file was found but another error was produced
	        log.Fatal("config.yaml reading error:",err)
	    }
	    os.Exit(1)
	}
	// common settings
	CFG_NOTIF_PERIOD = viper.GetInt64("macsend_period")

	//kafka settings
	CFG_KAFKA_ENABLED = viper.GetBool("kafka.enabled")
	CFG_KAFKA_TOPIC = viper.GetString("kafka.topic")
	CFG_KAFKA_SERVERS = viper.GetString("kafka.servers")
	CFG_KAFKA_LINGERMS = viper.GetInt("kafka.lingerms")

	//url settings
	CFG_NOTIF_ENABLED = viper.GetBool("http-requests.save_localy")
	CFG_NOTIF_URL = viper.GetString("http-requests.captured-macs")
	CFG_STATS_URL = viper.GetString("http-requests.statistics")
	CFG_TOKEN = viper.GetString("http-requests.token")
	
	CFG_POST_PERIOD = viper.GetInt64("http-requests.post_period")
	CFG_POST_MACS_MAX = viper.GetInt64("http-requests.post_macs_max")
	CFG_STATS_PERIOD = viper.GetInt64("http-requests.stats_period")

	//logs
	CFG_LOG_LEVEL = viper.GetString("log.level")
	CFG_LOG_WRITEFILE = viper.GetBool("log.writefile")
	CFG_LOG_FNAME = viper.GetString("log.filename")

	//oui
	CFG_OUI_URL = viper.GetString("ouidb.url")
	CFG_OUI_RENEW_PERIOD = viper.GetInt64("ouidb.renew_period")

	//cache
	CFG_CACHE_CHECK = viper.GetInt64("cache.check")
	CFG_CACHE_MAC_TIMEOUT = viper.GetInt64("cache.mac_timeout")
	CFG_CACHE_SNIF_TIMEOUT = viper.GetInt64("cache.snif_timeout")
	CFG_CACHE_BADSNIF_TIMEOUT = viper.GetInt64("cache.badsnif_timeout")

    if CFG_STATS_PERIOD == 0 {
        panic("requests.stats_period in config file can't be zero!")
    }

}