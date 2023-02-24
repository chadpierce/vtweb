package main

import (
	"errors"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"log"
	"net/http"
	"time"
	"strings"

	"github.com/gorilla/mux"
)

var enableLogFile bool = true
var isBase64 bool = false
var outputPath string = "./output/"  //needs trailing slash
var apiUrl string = "https://localhost/"

type URLSet struct {
	Name    	string 	  `json:"name"`
	Status  	int 	  `json:"status"`
	Filename	string	  `json:"filename"`
	Urls		[]string  `json:"urls`
	Data		[]string  `json:"data"`
}

func encode64(decodedString string) string {
	if isBase64 == false {
		return decodedString
	}
	var encodedString = base64.StdEncoding.EncodeToString([]byte(decodedString))
	return encodedString
}

func decode64(encodedString string) string {
	if isBase64 == false {
		return encodedString
	}
	var decodedByte, _ = base64.StdEncoding.DecodeString(encodedString)
	var decodedString = string(decodedByte)
	return decodedString
}

func getEpochTime() int64 {
	return time.Now().Unix()
}

func createFile(contents string, filename string) error {
	logHeader := "OUTPUT:"
	file, err := os.Create(outputPath + filename + ".txt")
	if err != nil {
		log.Println(logHeader, "ERROR failed creating file:", filename, err)
		return errors.New("failed creating file")
	}
	defer file.Close()
	_, err = file.WriteString(contents)
	if err != nil {
		log.Println(logHeader, "ERROR failed writing to file:", filename, err)
		return errors.New("failed writing file")
	}
	return nil
}

func baseGet(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("hello, world!")
	fmt.Println("-> base get")
}

func getTimestamp() string {
	t := time.Now()
	return t.Format(time.RFC822)
}

//TODO remove single brackets as well as double "[." and "[." - seen in lazy ioc lists

func desanitizeUrl(cleanUrl string) string {
	//cleanUrl = strings.Replace(cleanUrl, "\n", "", -1)
	dirtyUrl := strings.Replace(cleanUrl, "hxxps://", "https://", 1)
	dirtyUrl = strings.Replace(dirtyUrl, "hxxp://", "http://", 1)
	dirtyUrl = strings.Replace(dirtyUrl, "[.]", ".", -1)
	dirtyUrl = strings.Replace(dirtyUrl, "(.)", ".", -1)
	return dirtyUrl
}

func sanitizeUrl(dirtyUrl string) string {
	//dirtyUrl = strings.Replace(dirtyUrl, "\n", "", -1)
	cleanUrl := strings.Replace(dirtyUrl, "https://", "hxxps://", 1)
	cleanUrl = strings.Replace(cleanUrl, "http://", "hxxp://", 1)
	cleanUrl = strings.Replace(cleanUrl, ".", "[.]", -1)
	//cleanUrl = strings.TrimSuffix(cleanUrl, "\n")
	return cleanUrl
}


// func vtUrlApiScheduler(line string) string {
// 	done := make(chan bool)
// 	vtResults := vtUrlApi(line, done)
// }

func endpointFrontEndPostURLs(w http.ResponseWriter, r *http.Request) {
	logHeader := "VTURL:"
	//errCode := "200"
	id := mux.Vars(r)["id"]
	body, err := ioutil.ReadAll(r.Body)
	var results []string
	var lines []string
	if err != nil {
		log.Println(logHeader, "ERROR no body in request " + string(id))
		//w.WriteHeader(400)
		fmt.Fprintf(w, "ERROR no body in request")
		return
	} else {
		lines = strings.Split(string(body), "\n")
		for _, line := range lines {
			line = desanitizeUrl(line)
			vtResults := vtUrlApi(line)
			if vtResults == "UNAUTHORIZED" {
				results = append(results, "ERROR: UNAUTHORIZED, check API token")
				log.Println("UNATHORIZED: CHECK API TOKEN")
				w.WriteHeader(401)
 				fmt.Fprintf(w, "UNATHORIZED: CHECK API TOKEN")
 				break
 			} else if vtResults == "QUOTA_EXCEEDED" {
 				results = append(results, "ERROR: QUOTA EXCEEDED, halted execution")
 				log.Println("QUOTA_EXCEEDED")
				w.WriteHeader(401)
 				fmt.Fprintf(w, "QUOTA_EXCEEDED")
 				break
			} else if vtResults == "NOT FOUND" {
				log.Printf("%v: NOT FOUND", sanitizeUrl(line))
				returnStr := fmt.Sprintf("%v,NOT_FOUND,-,-,-", sanitizeUrl(line))
				results = append(results, returnStr)
			} else {
				results = append(results, vtResults)
			}

		}
		strHeader := "url,verdict,rep,mal,sus\n"
		strResults := strings.Join(results, "\n")
		strResults = strHeader + strResults
		createFile(strResults, id)
		log.Println(logHeader, string(id))
		w.WriteHeader(200)
 		fmt.Fprintf(w, strResults)
 	}
}

func main() {
	file, err := os.OpenFile("./debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatal(err)
	}
	mw := io.MultiWriter(os.Stdout, file)
	if enableLogFile == true {

		log.SetOutput(mw)
	}
	log.Println("START VTAPI BACKEND")
	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/", baseGet).Methods("GET")
	//router.HandleFunc("/test/{id}", endpointFrontEndPostURLs).Methods("GET")
	router.HandleFunc("/vturl/{id}", endpointFrontEndPostURLs).Methods("POST")
	//router.HandleFunc("vt/url-scan/{id}", endpointVirusTotalUrlScan).Methods("POST")
	log.Fatal(http.ListenAndServe(":4141", router))
}

