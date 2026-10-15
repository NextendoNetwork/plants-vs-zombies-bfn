package main

// redirector - gosredirector's getServerInstance: tells the client where the Blaze server is.

import (
	"encoding/binary"
	"encoding/xml"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
)

type serverInstanceRequest struct {
	XMLName         xml.Name `xml:"serverinstancerequest"`
	Name            string   `xml:"name"`
	Platform        string   `xml:"platform"`
	ClientPlatform  string   `xml:"clientplatform"`
	BlazeSDKVersion string   `xml:"blazesdkversion"`
}

func handleRedirector(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	var req serverInstanceRequest
	if err != nil || xml.Unmarshal(body, &req) != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	log.Printf("[Redirector] name=%q platform=%q sdk=%q", req.Name, req.ClientPlatform, req.BlazeSDKVersion)
	ip := binary.BigEndian.Uint32(net.ParseIP(cfg.PublicIP).To4())
	// DirtySDK checks the Blaze certificate against this hostname, not against an IP SAN.
	out := "<?xml version='1.0' encoding='utf-8'?>\n" +
		`<serverinstanceinfo><address member="0"><valu>` +
		`<hostname>` + cfg.BlazeHost + `</hostname><ip>` + strconv.FormatUint(uint64(ip), 10) + `</ip>` +
		`<port>` + strconv.Itoa(cfg.BlazePort) + `</port></valu></address>` +
		`<secure>1</secure><trialservicename /><defaultdnsaddress>0</defaultdnsaddress>` +
		`<messages /></serverinstanceinfo>`
	w.Header().Set("Content-Type", "application/xml")
	io.WriteString(w, out)
}
