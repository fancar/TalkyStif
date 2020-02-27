package main


import (
    "github.com/sirupsen/logrus"
    "time"
    "flag"
    "fmt"
    "os"
    "io"
)


var (
    timewait time.Duration = 10 // default time-cycle (if errors) at the start
    
    
    log_file, loglevel,port_db, proto_db,NOTIF_URL,STATS_URL string
    TOKEN string
    BEARER_TOKEN string = "Bearer " + TOKEN
    version string = "0.5.3 beta"
    Version string = "Talky Stif | TZSP colector with concurency | "+version
    
    log = logrus.New()

    time_format string = "2006-01-02 15:04:05" 
    start_time, now time.Time
    start_time_u, now_u int64
    uptime time.Duration

    //notification_time int64 //how frequent we make notifications for same mac
    post_period int64 // how frequent we post macs to a grinder-server
    stats_period int64 // how frequent we print stats to log
    oui_period int64 // how frequent we are donwload new oui database

    ouiFileUrl string
)

func Init() {
    flags()
    logging(log_file)
}

func flags() {
    //programm atrributes
    //flag.Int64Var(&notification_time,"notif_period", 300, "How frequent we are sending info about same mac")
    flag.StringVar(&proto_db,"proto", "udp", "protocol we are listening by")
    flag.StringVar(&port_db,"listen", ":37008", "server:port we are listening on")
    flag.StringVar(&NOTIF_URL,"api", "http://10.190.51.229:8090/captured_macs", //https://46b4477f329048829f0ec979cb629e02.domru.ru/raw
        "url we are going to post so called 'raw data ;)'")
    flag.StringVar(&STATS_URL,"stats-url", "http://10.190.51.229:8090/collector_stats",
        "url we are going to post collector's stats")

    flag.StringVar(&TOKEN,"token", "", "Bearer token for stats-url and api url")

    flag.StringVar(&ouiFileUrl,"ouiurl", "http://standards-oui.ieee.org/oui.txt",
        "url with oui database file")

    flag.Int64Var(&post_period,"t", 5, "In seconds. How frequent we are making posts to api")
    flag.Int64Var(&stats_period,"logtime", 60, "In seconds. How frequent we are printing statistics in log")
    flag.Int64Var(&oui_period,"ouitime", 720, "In hours. How frequent we donwload new oui database")

    flag.StringVar(&log_file,"logfile", "stifler.log", "logfile_name")
    version := flag.Bool("v", false, "prints current version")
    flag.StringVar(
        &loglevel,"loglevel", "info",
        "debug - for debuging,trace - to trace all packets")
    flag.Parse()
    if *version {
        fmt.Println(Version)
        os.Exit(0)
    }
}

func logging(logf string) {
    log.SetFormatter(&logrus.TextFormatter{
        DisableColors: false,
        FullTimestamp: true,
    })
    log.Out = os.Stdout
    frite_file := true
    switch loglevel {
    case "trace":
        log.Level = logrus.TraceLevel
        frite_file = false
    case 
        "debug":
        log.Level = logrus.DebugLevel
        frite_file = false
    case "Warn":
        log.Level = logrus.WarnLevel
    case "Error":
        log.Level = logrus.ErrorLevel
    default:
        log.Level = logrus.InfoLevel
    }
    if frite_file {
      logFile, err := os.OpenFile(logf, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0664)
      if err == nil {
           mw := io.MultiWriter(os.Stdout, logFile)
           log.SetOutput(mw)
           //log.Out = file
      } else {
       log.Info("Failed to log to file, using default stderr")
      }
    }
}


func ErrorAndExit(s string, err error) {
    if err  != nil {
        log.Error(s,err)
        os.Exit(1)
    }
}

func Error(msg string, err error) error {   
    return fmt.Errorf("%v | %v | %v",
        now.Format(time_format),
        msg,
        err)
}