package main

import (
    "github.com/fancar/tzspanalyser"
    "io"
    "net/http"
    "os"
    "time"
)

// OuidbUpdater The goroutine updates vendors database from the internet
func OuidbUpdater() {
    for {
        UpdateOuidb(ouiFileName)
        time.Sleep(OUI_RENEW_TIMEDURATION)
    }
    //quit <- struct{}{}
}

// DownloadFile download a file from the internet
func DownloadFile(filepath string, url string) error {
    log.Info("...downloading file from ", url)

    resp, err := http.Get(url)
    if err != nil {
        //log.Error("can't make get request: ",err)
        return err
    }
    defer resp.Body.Close()

    out, err := os.Create(filepath)
    if err != nil {
        return err
    }
    defer out.Close()

    _, err = io.Copy(out, resp.Body)
    return err
}

// WeNeedNewFile  desdecides if we need  renew vendor's database
func WeNeedNewFile(fname string) bool {

    file, err := os.Stat(fname)
    if err != nil {
        log.Error("oui-DB: can not get file params", err)
        return true
    }

    now := time.Now()
    diff := now.Sub(file.ModTime())

    if diff > OUI_RENEW_TIMEDURATION {
        log.Info("oui-DB: renew period: ", OUI_RENEW_TIMEDURATION)
        log.Info("oui-DB: the file is old: ", file.ModTime())
        return true
    }
    return false
}

// DownloadOui downloads vendor's database from the internet
func DownloadOui(fname string) error {

    err := DownloadFile(fname, CFG_OUI_URL)
    if err == nil {
        log.Info("oui-DB: Adding new OUI database from ", fname)
        err = tzspanalyser.OpenOuiDb(fname)
    }
    return err

}

// MakeOuidb try to open database file, download if need
func MakeOuidb(fname string) error {

    if _, err := os.Stat(fname); os.IsNotExist(err) {
        //ErrorAndExit("cant find file",err)
        log.Info("the local file not found. Trying to get a new one...")
        err := DownloadOui(fname)
        if err != nil {
            log.Error("oui-DB: can not download", err)
            return err
        }
        return nil

    } else if err != nil {
        return err
    }

    return tzspanalyser.OpenOuiDb(fname)
}

// UpdateOuidb download new database if it expired
func UpdateOuidb(fname string) {
    if WeNeedNewFile(fname) {
        err := DownloadOui(fname)
        if err != nil {
            log.Error("oui-DB: can not download new oui database file", err)
        }
    }
}
