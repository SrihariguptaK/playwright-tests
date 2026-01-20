# Manual Test Cases

## Story: As Employee, I want to securely access my schedule to protect my personal information
**Story ID:** story-15

### Test Case: Validate successful login and schedule access
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee has valid registered credentials in the system
- Schedule data exists for the employee in the database
- Application is accessible via HTTPS
- Authentication service is running and available
- Employee is not currently logged in

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Employee opens web browser and navigates to the application login page URL | Login page loads successfully displaying username and password input fields, login button, and HTTPS lock icon in browser address bar |
| 2 | Employee enters valid username in the username field | Username is accepted and displayed in the input field (masked or visible based on field type) |
| 3 | Employee enters valid password in the password field | Password is accepted and displayed as masked characters (dots or asterisks) |
| 4 | Employee clicks the login/submit button | System processes authentication request, validates credentials against authentication service, and completes within 2 seconds |
| 5 | System authenticates the employee credentials | Authentication succeeds, session token is created and stored, employee is redirected to dashboard or home page, and welcome message or employee name is displayed |
| 6 | Employee navigates to the schedule page by clicking on schedule menu or link | Schedule page loads successfully showing navigation to schedule section |
| 7 | System validates session token and retrieves schedule data for the authenticated employee | Only the authenticated employee's schedule data is displayed with correct dates, shifts, and assignments. No other employee's data is visible |
| 8 | Verify data transmission is encrypted by checking browser security indicators | HTTPS protocol is active, SSL/TLS certificate is valid, and secure connection icon is displayed in browser |

**Postconditions:**
- Employee is successfully logged in with active session
- Employee can view their schedule data
- Session token is valid and stored
- Access attempt is logged in system logs with timestamp and user ID
- All data transmissions were encrypted via HTTPS

---

### Test Case: Verify access denial with invalid credentials
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Application login page is accessible
- Authentication service is running
- Employee is not logged in
- Test invalid credentials are prepared (non-existent username or incorrect password)

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Employee navigates to the login page | Login page is displayed with username and password fields |
| 2 | Employee enters invalid username in the username field | Invalid username is accepted in the input field |
| 3 | Employee enters any password in the password field | Password is accepted and displayed as masked characters |
| 4 | Employee clicks the login/submit button | System attempts authentication and processes the request |
| 5 | System validates the credentials against authentication service | Authentication fails and clear error message is displayed such as 'Invalid username or password. Please try again.' No session is created |
| 6 | Employee remains on login page and attempts to directly access schedule page URL by typing schedule URL in browser | Access is denied, system redirects to login page with message 'Authentication required. Please log in to access this page.' |
| 7 | Verify no schedule data is exposed by checking page source, network traffic, and API responses | No schedule data is visible in page content, no data is returned in API responses, and no sensitive information is leaked in error messages or page source |
| 8 | Check system logs for failed authentication attempt | Failed login attempt is logged with timestamp, attempted username (not password), and failure reason |
| 9 | Repeat test with valid username but incorrect password | Authentication fails with same error message, no session created, access denied, and attempt is logged |

**Postconditions:**
- Employee is not authenticated and has no active session
- No schedule data was exposed or accessible
- Failed authentication attempts are logged in system
- Employee remains on login page
- No security vulnerabilities were exploited

---

### Test Case: Test session timeout and logout behavior
- **ID:** tc-003
- **Type:** edge-case
- **Priority:** High
- **Estimated Time:** 20 mins

**Preconditions:**
- Employee has valid credentials
- Session timeout duration is configured in the system (e.g., 15 minutes of inactivity)
- Authentication service is running
- Employee is not currently logged in
- System clock is accurate

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Employee logs in with valid credentials following standard login process | Employee is successfully authenticated, session is created with timestamp, and employee is redirected to dashboard |
| 2 | Employee navigates to schedule page and views their schedule | Schedule data is displayed successfully for the authenticated employee |
| 3 | Employee remains idle (no clicks, no keyboard input, no page navigation) for the duration exceeding the configured session timeout period | System monitors session inactivity and tracks time elapsed since last activity |
| 4 | Wait for session timeout to trigger (system automatically detects timeout) | Session expires automatically, session token is invalidated, and employee is logged out from the system |
| 5 | Employee attempts to access schedule page by clicking on schedule link or refreshing the page | Access is denied, session is no longer valid, employee is redirected to login page with message 'Your session has expired. Please log in again.' |
| 6 | Verify session token is invalidated by checking session storage and attempting API calls with old token | Session token is removed or marked invalid, API calls return 401 Unauthorized error, and no schedule data is accessible |
| 7 | Employee logs in again with valid credentials | New session is created successfully and employee can access schedule |
| 8 | Employee navigates to schedule page and views schedule data | Schedule data is displayed correctly |
| 9 | Employee clicks the logout button or link | Logout request is processed by the system |
| 10 | System processes manual logout | Session is immediately invalidated, session token is destroyed, employee is redirected to login page with confirmation message 'You have been successfully logged out.' |
| 11 | Employee attempts to access schedule page after manual logout by using browser back button or typing schedule URL | Access is denied, employee is redirected to login page, and message indicates authentication is required |
| 12 | Verify session invalidation by checking session storage and attempting API calls with old session token | Session token is completely removed, API calls return 401 Unauthorized, and no access is granted to any protected resources |

**Postconditions:**
- All sessions created during test are invalidated
- Employee is logged out and on login page
- Session timeout and logout events are logged with timestamps and user IDs
- No active sessions remain for the test employee
- System correctly enforces session security policies

---

## Story: As Employee, I want to receive error messages when schedule data fails to load to understand issues
**Story ID:** story-19

### Test Case: Validate error message display on schedule load failure
- **ID:** tc-004
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Employee has valid credentials and is logged in
- Schedule API endpoint is accessible for testing
- Ability to simulate API failure (mock service, network interception, or test environment configuration)
- Error message templates are configured in the system
- Employee has navigated to the application

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Configure test environment or use mock service to simulate schedule data retrieval failure (e.g., API returns 500 Internal Server Error, timeout, or network error) | Test environment is configured to force schedule API to fail when called |
| 2 | System attempts to retrieve schedule data from the API | API call fails as configured, system detects the failure through error response or timeout |
| 3 | Employee clicks on schedule menu item or navigates to schedule page URL | Schedule page begins loading and initiates data retrieval request |
| 4 | System processes the failed API response | System recognizes the error condition and triggers error handling logic |
| 5 | Observe the error message displayed to the employee | Descriptive, user-friendly error message is displayed within 2 seconds of failure detection, such as 'We are unable to load your schedule at this time. Please try again or contact support if the problem persists.' |
| 6 | Verify error message content for clarity and helpfulness | Error message clearly explains the issue without technical jargon, does not expose sensitive system information, and is displayed prominently on the page |
| 7 | Employee views the retry option presented in the error message or on the page | Retry button or link is clearly visible and labeled (e.g., 'Retry', 'Try Again', or 'Refresh') |
| 8 | Employee views the support contact information presented in the error message | Support contact options are clearly presented, such as 'Contact Support', email address, phone number, or help desk link |
| 9 | Verify the presentation and accessibility of retry and support options | Both retry and support options are clearly visible, properly formatted, clickable/actionable, and positioned logically within or near the error message |
| 10 | Measure time from failure detection to error message display | Error message appears within 2 seconds of the API failure being detected |

**Postconditions:**
- Error message is displayed to employee
- Employee has clear options to retry or contact support
- No schedule data is displayed (page shows error state)
- System remains stable and responsive
- Error is logged in system logs for diagnostics

---

### Test Case: Verify error logging for diagnostics
- **ID:** tc-005
- **Type:** error-case
- **Priority:** Medium
- **Estimated Time:** 8 mins

**Preconditions:**
- Employee has valid credentials and is logged in
- Error logging system is configured and operational
- Access to system error logs is available for verification
- Ability to simulate schedule data load error
- System clock is accurate for timestamp verification

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Configure test environment to trigger schedule data load error (e.g., simulate API failure, database connection error, or timeout) | Test environment is ready to produce a schedule data retrieval error |
| 2 | Note the current timestamp and logged-in employee user ID before triggering the error | Reference timestamp and user ID are recorded for log verification |
| 3 | Employee navigates to schedule page to trigger the data load error | Schedule data retrieval is attempted and fails as configured |
| 4 | System detects the schedule data load failure | Error is detected and error handling logic is triggered, including logging mechanism |
| 5 | System logs the error to the error logging system | Error entry is created in the system logs with all required information |
| 6 | Access the system error logs through logging dashboard, log files, or logging service | Error logs are accessible and can be searched or filtered |
| 7 | Search for the error log entry corresponding to the triggered schedule load failure using timestamp and user ID | Specific error log entry is located in the logs |
| 8 | Review the error log entry for timestamp accuracy | Log entry contains accurate timestamp matching the time when error occurred (within acceptable margin of seconds) |
| 9 | Review the error log entry for user context information | Log entry includes user ID, username, or employee identifier of the logged-in employee who experienced the error |
| 10 | Review the error log entry for error details and completeness | Log entry contains complete and accurate information including: error type/category, error message, API endpoint that failed, HTTP status code (if applicable), stack trace or error source, session ID, and any relevant request parameters |
| 11 | Verify log entry provides sufficient information for diagnostics and troubleshooting | Log entry contains enough detail for developers or support team to diagnose the root cause, reproduce the issue, and implement a fix |
| 12 | Verify no sensitive information (passwords, tokens, personal data) is exposed in the logs | Log entry does not contain sensitive or confidential information that could pose security risks |

**Postconditions:**
- Error is successfully logged in the system
- Log entry contains complete diagnostic information
- Logs are accessible for review and analysis
- No sensitive data is exposed in logs
- System continues to function normally after error

---

## Story: As Employee, I want to log out securely to protect my schedule information
**Story ID:** story-22

### Test Case: Validate successful logout and session invalidation
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- Employee is logged into the system with valid credentials
- Employee is on any schedule page within the application
- Active session exists with valid session token and cookies
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Locate and click the logout button on the current schedule page | Logout button is visible and clickable; logout request is sent to POST /api/auth/logout endpoint |
| 2 | System processes the logout request and invalidates the session | Session token is invalidated in the session management system; all session cookies are cleared securely; HTTP 200 response is received |
| 3 | Observe the page redirection after logout completion | Employee is automatically redirected to the login page; login page is fully displayed with username and password fields visible |
| 4 | Verify the total time taken from clicking logout to reaching login page | Entire logout process completes within 2 seconds |
| 5 | Check browser developer tools for session cookies and tokens | All session-related cookies and authentication tokens are removed from browser storage |

**Postconditions:**
- Employee session is completely terminated
- All session cookies and tokens are cleared from browser
- Employee is on the login page
- No residual session data exists in the system
- Employee must re-authenticate to access any protected pages

---

### Test Case: Verify no access after logout
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- Employee was previously logged into the system
- Employee has successfully completed logout process
- Employee is currently on the login page after logout
- Session has been invalidated and cookies cleared
- Browser history contains previously accessed schedule page URLs

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Copy or note the URL of a protected schedule page that was previously accessible | Schedule page URL is available (e.g., /schedule/view or /employee/schedule) |
| 2 | Attempt to access the schedule page by entering the URL directly in the browser address bar or using browser back button | Access to the schedule page is denied; system detects invalid/missing session |
| 3 | Observe the system response to the unauthorized access attempt | Employee is automatically redirected to the login page; error message or notification may indicate session expired or authentication required |
| 4 | Verify that no schedule data or sensitive information is displayed during the redirect | No schedule information is visible; no data leakage occurs during the redirect process |
| 5 | Attempt to access multiple different protected pages (e.g., profile, settings, other schedule views) using direct URLs | All attempts are denied; employee is redirected to login page for each attempt; consistent security behavior across all protected resources |

**Postconditions:**
- Employee remains on the login page
- No unauthorized access to schedule or protected pages occurred
- Session remains invalidated
- System security is maintained
- Employee must provide valid credentials to regain access

---

