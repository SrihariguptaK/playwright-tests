# Manual Test Cases

## Story: As Employee, I want to securely log in to access my schedule to protect my personal information
**Story ID:** story-14

### Test Case: Validate successful login with valid credentials
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- Employee has a valid registered account in the system
- Employee knows their correct username and password
- Application is accessible via HTTPS
- UserCredentials database is available and operational
- Employee is not currently logged in

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Employee opens a web browser and navigates to the application login page URL | Login page loads successfully displaying username field, password field, and login button |
| 2 | Employee enters valid username in the username field | Username is accepted and displayed in the username field |
| 3 | Employee enters valid password in the password field | Password is masked and displayed as dots or asterisks in the password field |
| 4 | Employee clicks the login button | System validates credentials against UserCredentials database, authentication completes within 2 seconds, and employee is redirected to the home/dashboard page |
| 5 | Employee navigates to the schedule page by clicking on schedule menu or link | Schedule page loads successfully displaying the employee's schedule information with proper authentication session maintained |

**Postconditions:**
- Employee is successfully authenticated and logged in
- Active session is created for the employee
- Employee has access to schedule and other protected pages
- Session token is stored securely
- Login event is logged in the system

---

### Test Case: Verify rejection of invalid credentials
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- Application is accessible via HTTPS
- Login page is functional
- UserCredentials database is available
- Employee is not currently logged in

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Employee navigates to the login page | Login page loads successfully with username and password fields displayed |
| 2 | Employee enters an invalid username (non-existent user) in the username field | Invalid username is accepted in the input field |
| 3 | Employee enters any password in the password field | Password is masked and displayed in the password field |
| 4 | Employee clicks the login button | System validates credentials, authentication fails, and error message 'Invalid credentials' is displayed on the login page within 2 seconds |
| 5 | Employee attempts to directly access the schedule page URL by typing it in the browser address bar | Access is denied, employee is redirected to the login page with message indicating authentication is required |
| 6 | Employee enters a valid username but incorrect password and clicks login | System validates credentials, authentication fails, and error message 'Invalid credentials' is displayed |

**Postconditions:**
- Employee remains unauthenticated
- No session is created
- Employee does not have access to protected pages
- Failed login attempt is logged in the system
- Employee remains on the login page

---

### Test Case: Ensure session termination on logout
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- Employee is already logged in with valid credentials
- Active session exists for the employee
- Employee is on any page within the application
- Logout button is visible and accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Employee locates and clicks the logout button | System processes logout request via POST /api/auth/logout endpoint, session is terminated within 2 seconds, and employee is redirected to the login page |
| 2 | Employee verifies they are on the login page | Login page is displayed with username and password fields, no user-specific information is visible |
| 3 | Employee attempts to access the schedule page by typing the schedule URL directly in the browser address bar | Access is denied, employee is redirected back to the login page with message indicating login is required |
| 4 | Employee clicks the browser back button | Employee remains on the login page or is redirected to login page, cannot access previously viewed authenticated pages |
| 5 | Employee attempts to access any other protected page within the application | Access is denied for all protected pages, employee is redirected to login page |

**Postconditions:**
- Employee session is completely terminated
- Session token is invalidated
- Employee cannot access any protected pages without re-authentication
- Logout event is logged in the system
- Employee is on the login page

---

## Story: As Employee, I want to log out securely to protect my schedule information
**Story ID:** story-18

### Test Case: Validate successful logout and session termination
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee is logged in with valid credentials
- Active session exists for the employee
- Employee is on a schedule-related page
- Logout button is visible on the current page

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Employee locates the logout button on the current page | Logout button is visible and clearly labeled |
| 2 | Employee clicks the logout button | System sends POST request to /api/auth/logout endpoint, session is terminated, and employee is redirected to the login page within 2 seconds |
| 3 | Employee verifies the current page is the login page | Login page is displayed with username and password input fields, no authenticated user information is visible |
| 4 | Employee attempts to navigate to the schedule page by entering the schedule page URL in the browser address bar | Access to schedule page is denied, employee is immediately redirected to the login page |
| 5 | Employee attempts to use the browser back button to return to the schedule page | Access is denied, employee is redirected to the login page, previous session cannot be restored |
| 6 | Employee attempts to access any other schedule-related page directly via URL | Access is denied to all schedule-related pages, employee is redirected to login page with message indicating authentication is required |

**Postconditions:**
- Employee session is completely invalidated
- All session tokens are destroyed
- Employee cannot access any protected schedule pages
- Employee is on the login page
- Logout action is logged with timestamp
- System maintains 100% logout success rate

---

### Test Case: Verify logout button accessibility
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 6 mins

**Preconditions:**
- Employee is logged in with valid credentials
- Active session exists
- Multiple schedule-related pages are available in the application
- Employee has permission to access various schedule pages

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Employee navigates to the main schedule page | Main schedule page loads successfully and logout button is visible in the navigation area or header |
| 2 | Employee verifies the logout button is clickable on the main schedule page | Logout button is enabled, properly styled, and responds to hover/focus events |
| 3 | Employee navigates to the schedule details page or view schedule page | Schedule details page loads successfully and logout button is visible in the same consistent location |
| 4 | Employee verifies the logout button is clickable on the schedule details page | Logout button is enabled and functional |
| 5 | Employee navigates to any other schedule-related page (e.g., schedule settings, schedule history, or schedule preferences) | Page loads successfully and logout button is visible in the consistent location across all pages |
| 6 | Employee verifies the logout button is clickable on each additional schedule-related page | Logout button is enabled, functional, and maintains consistent appearance and position across all schedule-related pages |
| 7 | Employee clicks the logout button from any of the visited pages | Logout functionality works correctly, session is terminated, and employee is redirected to login page within 2 seconds |

**Postconditions:**
- Logout button accessibility is confirmed on all schedule-related pages
- Consistent user experience is validated across all pages
- Employee is logged out successfully
- Session is terminated
- Employee is on the login page

---

## Story: As Employee, I want to receive error messages when schedule data is unavailable to understand issues
**Story ID:** story-19

### Test Case: Validate error message display on data retrieval failure
- **ID:** tc-019-001
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Employee is logged into the system with valid credentials
- Employee has permission to access schedule data
- Backend service is configured to simulate failure scenarios
- Test environment is set up with error simulation capabilities

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule page as an employee | Schedule page interface is displayed and attempts to load schedule data |
| 2 | Simulate backend failure during schedule retrieval (trigger API error response) | System detects the data retrieval failure within 1 second |
| 3 | Observe the error message displayed on the screen | Error message is displayed to employee clearly indicating schedule data is unavailable |
| 4 | Read and verify the content of the error message | Message is user-friendly, clear, and suggests next steps such as 'Please try again' or 'Contact support if the issue persists' |
| 5 | Verify the error message appears within the specified time threshold | Error message is displayed within 1 second of failure detection |
| 6 | Check backend logs for error recording | Error is logged in the backend system with appropriate details for diagnostics |

**Postconditions:**
- Error message is visible to the employee
- Application remains stable and functional
- Error is logged in the system for backend diagnostics
- Employee can attempt to retry or contact support

---

### Test Case: Ensure system stability during data failures
- **ID:** tc-019-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Employee is logged into the system
- Schedule page is accessible
- Backend service can be configured to fail on demand
- System monitoring tools are active to detect crashes

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule page as an employee | Schedule page loads and initiates data retrieval request |
| 2 | Trigger schedule data retrieval failure by simulating backend error (500 Internal Server Error, timeout, or network failure) | Backend returns error response to the frontend |
| 3 | Observe the application behavior during the failure | Application remains stable without crashes, freezes, or unresponsive states |
| 4 | Verify that the user interface continues to be responsive | UI elements remain functional and employee can navigate to other sections |
| 5 | Check for any console errors or application crashes | No application crashes occur; error is handled gracefully |
| 6 | Attempt to retry the schedule data retrieval | System allows retry attempt without requiring application restart |

**Postconditions:**
- Application remains stable and operational
- No crashes or system failures occurred
- Employee can continue using other features of the application
- Error handling mechanisms are confirmed to be working properly

---

## Story: As Employee, I want the schedule interface to load quickly to avoid delays in accessing my schedule
**Story ID:** story-20

### Test Case: Validate schedule page load times under normal conditions
- **ID:** tc-020-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Employee is logged into the system with valid credentials
- Network conditions are normal (stable internet connection)
- Backend services are running normally
- Browser cache is cleared to simulate first-time load
- Performance monitoring tools are configured and ready

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Start performance timer or monitoring tool | Timer is initiated and ready to measure page load time |
| 2 | Employee navigates to the schedule page by clicking on schedule menu or link | Schedule page begins loading and data retrieval is initiated |
| 3 | Measure the time taken for the schedule page to fully load and display schedule data | Page loads completely within 3 seconds with all schedule data visible |
| 4 | Verify that all schedule elements (dates, shifts, assignments) are rendered correctly | All schedule components are displayed properly without missing data |
| 5 | Employee interacts with schedule view by scrolling, clicking on dates, or switching views | No noticeable delays or lag during interactions; UI responds immediately |
| 6 | Perform additional navigation within the schedule (e.g., next week, previous week) | Subsequent navigation is smooth and responsive without delays |

**Postconditions:**
- Schedule page is fully loaded and functional
- Page load time is recorded and meets the 3-second threshold
- Employee can interact with schedule without performance issues
- Performance metrics are logged for analysis

---

### Test Case: Verify backend API response times
- **ID:** tc-020-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Backend API endpoints are accessible and operational
- API testing tool (e.g., Postman, curl) is configured
- Valid authentication tokens are available
- Network conditions are normal
- Backend services are not under heavy load

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Prepare API request for schedule data with valid employee credentials and parameters | API request is properly formatted with required headers and authentication |
| 2 | Start timer and send schedule data request to backend API endpoint | API request is sent successfully to the backend server |
| 3 | Monitor the API response time from request initiation to response receipt | Backend API responds with schedule data |
| 4 | Measure and record the total response time | Response is received within 2 seconds of sending the request |
| 5 | Verify the response contains complete and valid schedule data | Response payload includes all expected schedule information with correct data structure |
| 6 | Repeat the API request 3-5 times to ensure consistent performance | All subsequent requests also respond within 2 seconds consistently |

**Postconditions:**
- Backend API response times are confirmed to meet the 2-second threshold
- Schedule data is successfully retrieved
- Performance metrics are documented
- API performance is consistent across multiple requests

---

### Test Case: Ensure system handles concurrent users without degradation
- **ID:** tc-020-003
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 20 mins

**Preconditions:**
- Load testing tool is configured (e.g., JMeter, LoadRunner)
- Multiple test user accounts are available
- Backend system is in normal operational state
- Performance monitoring is enabled on backend servers
- Baseline performance metrics are established

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Configure load testing tool to simulate 50 concurrent employee users accessing schedule page | Load testing tool is properly configured with user scenarios and timing |
| 2 | Start the load test to simulate multiple concurrent employee requests to the schedule system | Load test initiates and begins sending concurrent requests from simulated users |
| 3 | Monitor the response times for all concurrent requests during the test | System processes all concurrent requests simultaneously |
| 4 | Verify that all requests are processed within the defined performance thresholds (3 seconds for page load, 2 seconds for API) | All requests are completed within performance thresholds without significant degradation |
| 5 | Check backend server metrics (CPU, memory, database connections) during concurrent load | Server resources remain within acceptable limits without bottlenecks |
| 6 | Review error rates and failed requests during the concurrent load test | Error rate is minimal (less than 1%) and no requests fail due to system overload |
| 7 | Gradually increase concurrent users to 100 and repeat monitoring | System continues to handle increased load without performance degradation beyond acceptable thresholds |

**Postconditions:**
- System performance under concurrent load is documented
- All concurrent requests were processed successfully
- Performance thresholds were maintained under load
- System stability is confirmed for multiple concurrent users
- Load test results are saved for future reference

---

