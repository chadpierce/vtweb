package main

import (
	"fmt"
	"net/http"
	"io/ioutil"
    "encoding/base64"
    "encoding/json"
    "os"
)

var apiToken string = os.Getenv("VTAPI")

func vtUrlApi(sampleUrl string) string {	

    var urlID = base64.RawURLEncoding.EncodeToString([]byte(sampleUrl))
    url := "https://www.virustotal.com/api/v3/urls/" + urlID

    req, _ := http.NewRequest("GET", url, nil)
    req, err := http.NewRequest("GET", url, nil)
    if err != nil {
	    // TODO handle err
    }
    req.Header.Set("X-Apikey", apiToken)

    resp, err := http.DefaultClient.Do(req)
	defer resp.Body.Close()
    if err != nil {
        return fmt.Sprintf("ERROR: %v", err)
    } 
	defer resp.Body.Close()
    if resp.StatusCode == 404 {
    	return "NOT FOUND" 
    } else if resp.StatusCode == 401 {
    	return "UNAUTHORIZED"
    } else if resp.StatusCode == 429 {
    	return "QUOTA_EXCEEDED"
    } else {
	   	body, _ := ioutil.ReadAll(resp.Body)
	    var results ScanResults
	    json.Unmarshal([]byte(body), &results)
	    ratingMalicious := results.Data.Attributes.LastAnalysisStats.Malicious
	    ratingSuspicious := results.Data.Attributes.LastAnalysisStats.Suspicious
	    //ratingUndetected := results.Data.Attributes.LastAnalysisStats.Undetected
	    ratingReputation := results.Data.Attributes.Reputation
	    
	    var verdict string = ""
	    // TODO check status code, check for not found!
	    if ratingReputation < -3 || ratingMalicious > 3 || ratingSuspicious > 3 {
	        verdict = "BAD!"
	    } else if ratingReputation < 0 || ratingMalicious > 0 || ratingSuspicious > 0 {
	        verdict = "BAD?"
	    } else {
	        verdict = "OKAY"
	    }
	    cleanUrl := sanitizeUrl(sampleUrl)
	    //fmt.Printf("url: %v verdict: %v rep: %v mal: %v sus: %v", 
	    	//cleanUrl, verdict, ratingReputation, ratingMalicious, ratingSuspicious)
	    strResults := fmt.Sprintf("%v,%v,%v,%v,%v", 
	    	cleanUrl, verdict, ratingReputation, ratingMalicious, ratingSuspicious)
	    //done <- true
	    return strResults
    }
	return "ERROR"
}

type ScanResults struct {
	Data struct {
		Attributes struct {
			Categories struct {
			} `json:"categories"`
			Favicon struct {
			} `json:"favicon"`
			FirstSubmissionDate int  `json:"first_submission_date"`
			HasContent          bool `json:"has_content"`
			HTMLMeta            struct {
				Description []string `json:"description"`
				Sessid      []string `json:"sessid"`
				Viewport    []string `json:"viewport"`
			} `json:"html_meta"`
			LastAnalysisDate    int `json:"last_analysis_date"`
			LastAnalysisResults struct {
			} `json:"last_analysis_results"`
			LastAnalysisStats struct {
				Harmless   int `json:"harmless"`
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Timeout    int `json:"timeout"`
				Undetected int `json:"undetected"`
			} `json:"last_analysis_stats"`
			LastFinalURL                  string `json:"last_final_url"`
			LastHTTPResponseCode          int    `json:"last_http_response_code"`
			LastHTTPResponseContentLength int    `json:"last_http_response_content_length"`
			LastHTTPResponseContentSha256 string `json:"last_http_response_content_sha256"`
			LastHTTPResponseCookies       struct {
			} `json:"last_http_response_cookies"`
			LastHTTPResponseHeaders struct {
			} `json:"last_http_response_headers"`
			LastModificationDate int           `json:"last_modification_date"`
			LastSubmissionDate   int           `json:"last_submission_date"`
			OutgoingLinks        []string      `json:"outgoing_links"`
			Reputation           int           `json:"reputation"`
			RedirectionChain     []interface{} `json:"redirection_chain"`
			Tags                 []string      `json:"tags"`
			TargetedBrand        struct {
				//Phishtank string `json:"Phishtank"`
			} `json:"targeted_brand"`
			TimesSubmitted int    `json:"times_submitted"`
			Title          string `json:"title"`
			TotalVotes     struct {
				Harmless  int `json:"harmless"`
				Malicious int `json:"malicious"`
			} `json:"total_votes"`
			Trackers struct {
				GoogleTagManager []struct {
					ID        string `json:"id"`
					Timestamp int    `json:"timestamp"`
					URL       string `json:"url"`
				} `json:"Google Tag Manager"`
			} `json:"trackers"`
			URL string `json:"url"`
		} `json:"attributes"`
		ID    string `json:"id"`
		Links struct {
			Self string `json:"self"`
		} `json:"links"`
		Type string `json:"type"`
	} `json:"data"`
}

