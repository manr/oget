/**********************************************************************************
 * oget (https://github.com/manr/oget)
 * 
 * A minimalistic OData command line interface for Intrexx provided OData services
 *
 * Copyright (c) 2014 United Planet GmbH
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *     United Planet GmbH
 **********************************************************************************/

package main


import (
	"up/ksh"
	"fmt"
	"net/http"
	"net/http/httputil"
	"log"
	"encoding/hex"
	"encoding/base64"
	"strings"
	"flag"
	"bufio"
	"os"
	"io/ioutil"
)


var serviceUrl string
var entityPath string
var format     string
var auth_type  string
var username   string
var password   string
var verbose    bool
var dumpHeader bool


func init() {
	flag.StringVar(&serviceUrl, "serviceUrl", "", "The service endpoint root URL (e.g. http://host:port/servicename.svc).")
	flag.StringVar(&entityPath, "entityPath", "", "The entity collection path with optional query string (e.g. /EntitySet?filter=ID eq 1).")
	flag.StringVar(&format, "fmt", "", "The format type.")
	flag.StringVar(&auth_type, "auth", "intrexx", "The auth type.")
	flag.StringVar(&username, "user", "odata", "The username.")
	flag.StringVar(&password, "pwd", "odata", "The password.")
	flag.BoolVar(&dumpHeader, "dumpHeader", false, "Dump response headers.")
	flag.BoolVar(&verbose, "verbose", false, "Print verbose log messages.")
}


func main() {
	flag.Parse()
	
	if serviceUrl == "" {
		log.Fatal("No service URL provided!")
	}
	
	if serviceUrl[len(serviceUrl)-1:] == "/" {
		serviceUrl = serviceUrl[:len(serviceUrl)-1]
	}
	
	client := http.DefaultClient
	
	sessionId, err := login(client, username, password)
	
	if err != nil {
		log.Fatal(err)
	}
	
	if entityPath != "" {
		if format != "" {
			if strings.LastIndex(entityPath, "?") == -1 {
				entityPath = entityPath + "?$format=" + format
			} else {
				entityPath = entityPath  + "&$format=" + format
			}
		}
		
		uri := serviceUrl + entityPath
		
		doRequest(client, "GET", &uri, &sessionId)
	} else {
		scanner := bufio.NewScanner(os.Stdin)
		
		for scanner.Scan() {
			url := scanner.Text()

			if format != "" {
				if strings.LastIndex(url, "?") == -1 {
					url = url + "?$format=" + format
				} else {
					url = url + "&$format=" + format
				}
			}
			
			uri := serviceUrl + url
			
			doRequest(client, "GET", &uri, &sessionId)
		}
	}	
	
	logout(client, sessionId)
	
	logVerbose(fmt.Sprintf("Intrexx session closed.\n"))
}


func doRequest(client* http.Client, httpMethod string, urlStr* string, sessionId* string) {
	var path string
	var qs string
	
	if strings.Contains(*urlStr, "?") {
		path = (*urlStr)[0:strings.LastIndex(*urlStr, "?")]
		qs = (*urlStr)[strings.LastIndex(*urlStr, "?") + 1:]
	} else {
		path = *urlStr
	}
		
	fragments:=strings.Split(path, "/")
	
	path = ""
	for i, f := range fragments {
		if i > 2 {
			path = path + "/" + f
		}
	}
	
	req, err := http.NewRequest(httpMethod, *urlStr, nil)
	req.URL.Opaque=path
	
	if qs != "" {
		req.URL.RawQuery = strings.Replace(qs, " ", "%20", -1)
	}
		
	if (*sessionId != "") {
		cookie := http.Cookie{}
		cookie.Name = "co_SId"
		cookie.Value = *sessionId
		
		req.AddCookie(&cookie)
	}
	
	logVerbose(fmt.Sprintf("Request: %s", *urlStr))
	
	resp, err := client.Do(req)
	
	if err != nil {
		log.Fatal(err)
	}

	defer resp.Body.Close()
	
	fmt.Printf("%s %s\n", httpMethod, *urlStr)

	if dumpHeader {
		dumpResp, err := httputil.DumpResponse(resp, false)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s", string(dumpResp))
	}
	
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	
	fmt.Printf("%s\n\n", string(body))
}


func login(client* http.Client, username, pwd string) (sessionId string, err error) {
	var authb64 string
	
	if auth_type == "intrexx" {
		logVerbose(fmt.Sprintf("Using Intrexx authentication.\n"))

		challenge, salt, sId := getChallenge(client, username, pwd)
		hashing := ksh.NewSha1()
		digest := hashing.MakeDigest([]byte(pwd), []byte(salt), []byte(challenge))
		digestHex := strings.ToUpper(hex.EncodeToString(digest))

		auth := username + ":" + digestHex
		authb64 = base64.StdEncoding.EncodeToString([]byte(auth))
		sessionId = sId
		logVerbose(fmt.Sprintf("Established Intrexx session. ID: %s\n", sessionId))
	} else if auth_type == "basic" {
		logVerbose(fmt.Sprintf("Using basic authentication.\n"))
		auth := username + ":" + pwd
		authb64 = base64.StdEncoding.EncodeToString([]byte(auth))
	} else {
		logVerbose(fmt.Sprintf("Using anonymous authentication.\n"))
	}
		
	req, err := http.NewRequest("GET", serviceUrl + "/", nil)
	if err != nil {
		log.Fatal(err)
	}
	
	if authb64 != "" {
		req.Header.Add("Authorization", "Basic " + authb64)
	}
	
	if sessionId != "" {
		req.Header.Add("Cookie", "co_SId=" + sessionId)
	}
	
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		log.Fatalf("Error: Login denied. (%d)", resp.StatusCode)
	} else if resp.StatusCode != 200 {
		log.Fatalf("Error: Status %d", resp.StatusCode)
	}

	for _,c := range resp.Cookies() {
		if c.Name == "co_SId" {
			sessionId = c.Value
		}
	}
	
	return sessionId, err
}


func logout(client* http.Client, sessionId string) {
	if sessionId == "" {
		return
	}
	
	req, err := http.NewRequest("GET", serviceUrl + "/$logout", nil)
	cookie := http.Cookie{}
	cookie.Name = "co_SId"
	cookie.Value = sessionId
	req.AddCookie(&cookie)
	resp, err := client.Do(req)

	if err != nil {
		log.Fatal(err)
	}

	defer resp.Body.Close()
}


func getChallenge(client* http.Client, username, pwd string) (string, string, string) {
	req, err := http.NewRequest("GET", serviceUrl + "/$challenge", nil)
	req.Header.Add("rq_username", username)
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	challenge := resp.Header.Get("Challenge")
	salt := resp.Header.Get("Salt")
	
	var sessionId string
	
	for _, c := range resp.Cookies() {
		if c.Name == "co_SId" {
			sessionId = c.Value
		}
	}
	
	return challenge, salt, sessionId
}


func logVerbose(msg string) {
	if verbose {
		log.Printf(msg)
	}
}
