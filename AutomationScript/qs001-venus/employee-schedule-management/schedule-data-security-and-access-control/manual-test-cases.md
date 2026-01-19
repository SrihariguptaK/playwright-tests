# Manual Test Cases

## Story: As Employee, I want to securely log in to access my schedule to protect my personal information
**Story ID:** story-10

### Test Case: Validate successful login with valid credentials
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee has a valid registered account in the system
- Employee knows their correct username and password
- Application is accessible via HTTPS
- Database is operational and contains user credentials
- Browser is supported and cookies/sessions are enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open web browser and navigate to the application login page URL | Login page is displayed with username field, password field, and login button visible |
| 2 | Enter valid username in the username field | Username is accepted and displayed in the username field |
| 3 | Enter valid password in the password field | Password is masked and displayed as dots or asterisks in the password field |
| 4 | Click the login button | System validates credentials, creates secure session token, and redirects to employee dashboard within 2 seconds |
| 5 | Verify dashboard displays employee name and schedule access options | Dashboard is fully loaded showing personalized employee information and navigation menu |
| 6 | Locate and click the logout button | System terminates the session, invalidates session token, and redirects to login page with confirmation message |
| 7 | Verify login page is displayed after logout | Login page is shown with empty username and password fields, confirming successful logout |

**Postconditions:**
- User session is terminated
- Session token is invalidated in the system
- User is logged out and redirected to login page
- No active session exists for the employee

---

### Test Case: Verify login failure with invalid credentials
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- Application login page is accessible
- Database is operational
- HTTPS connection is established
- Browser is supported and functional

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open web browser and navigate to the application login page URL | Login page is displayed with username field, password field, and login button visible |
| 2 | Enter an invalid username (non-existent user) in the username field | Invalid username is accepted in the input field |
| 3 | Enter any password in the password field | Password is masked and displayed in the password field |
| 4 | Click the login button | System displays error message 'Invalid username or password' and access is denied. User remains on login page |
| 5 | Clear the fields and enter a valid username in the username field | Valid username is accepted in the input field |
| 6 | Enter an incorrect password in the password field | Incorrect password is masked and displayed in the password field |
| 7 | Click the login button | System displays error message 'Invalid username or password' and access is denied. User remains on login page |
| 8 | Verify no session token is created | No active session exists and user cannot access protected pages |

**Postconditions:**
- User remains on login page
- No session token is created
- Access to dashboard and schedule is denied
- Failed login attempt may be logged in system audit logs

---

### Test Case: Test session invalidation on logout
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Employee has valid credentials
- Application is accessible and operational
- Database is functional
- HTTPS connection is established

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to login page and enter valid username and password | Credentials are accepted in the respective fields |
| 2 | Click the login button | Login is successful, session token is created, and employee dashboard is displayed with personalized information |
| 3 | Verify access to schedule page by clicking on schedule menu option | Schedule page loads successfully showing employee's schedule data |
| 4 | Click the logout button from the dashboard or navigation menu | System invalidates the session token, terminates the session, and redirects to login page |
| 5 | Verify login page is displayed with empty fields | Login page is shown confirming successful logout |
| 6 | Manually navigate to the schedule page URL by entering it in the browser address bar | Access is denied, system detects no valid session, and user is automatically redirected to login page |
| 7 | Attempt to use browser back button to access dashboard | Access is denied and user is redirected to login page with message indicating session has expired |
| 8 | Verify session token is no longer valid in browser cookies/storage | Session token is removed or invalidated, confirming complete session termination |

**Postconditions:**
- User session is completely invalidated
- Session token is removed from system and browser
- User cannot access protected pages without re-authentication
- User is on login page ready to authenticate again

---

## Story: As Employee, I want to have access control ensuring only I can view my schedule to maintain privacy
**Story ID:** story-11

### Test Case: Verify access granted only to authenticated employee's schedule
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- At least two employee accounts exist in the system with different user IDs
- Test employee has valid credentials and an assigned schedule
- Another employee account exists with a different schedule
- Role-based access control is configured and active
- Application and database are operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to login page and enter valid username and password for the test employee | Login credentials are accepted in the respective fields |
| 2 | Click the login button to authenticate | Authentication is successful, session token is created, and employee is redirected to dashboard within 2 seconds |
| 3 | Verify employee identity is displayed on dashboard (name, employee ID) | Dashboard shows correct employee name and ID confirming successful authentication |
| 4 | Navigate to schedule page or click on 'My Schedule' menu option | System verifies employee identity and permissions, then displays the employee's own schedule data with correct dates and shifts |
| 5 | Verify schedule data belongs to the authenticated employee by checking employee ID or name on schedule | Schedule displays only the authenticated employee's shifts and personal schedule information |
| 6 | Attempt to access another employee's schedule by manually modifying the URL parameter (e.g., change employeeId=123 to employeeId=456) | System detects unauthorized access attempt, denies access, and displays error message 'Access Denied: You do not have permission to view this schedule' |
| 7 | Verify user remains on their own schedule page or is redirected to their dashboard | User is not able to view another employee's schedule and is kept within authorized pages only |
| 8 | Attempt to make API call directly to retrieve another employee's schedule using REST client or browser console | API endpoint returns 403 Forbidden status code with error message indicating insufficient permissions |

**Postconditions:**
- Employee can only access their own schedule data
- Unauthorized access attempts are blocked
- System maintains data privacy and access control integrity
- Error messages are logged for security monitoring

---

### Test Case: Verify audit logging of schedule access
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 8 mins

**Preconditions:**
- Audit logging system is enabled and configured
- Employee has valid credentials and assigned schedule
- Database audit log table is accessible
- System administrator or tester has access to view audit logs
- Another employee account exists for testing unauthorized access

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Note the current timestamp before starting the test | Current timestamp is recorded for later verification of log entries |
| 2 | Login to the application with valid employee credentials | Authentication is successful and employee is redirected to dashboard |
| 3 | Navigate to and access the employee's own schedule page | Schedule data is displayed successfully showing employee's shifts and schedule information |
| 4 | Access the system audit logs through admin panel or database query | Audit log interface or database table is accessible |
| 5 | Search for log entries matching the employee's user ID and the timestamp of schedule access | Audit log entry is found containing: timestamp of access, user ID of employee, action performed (schedule view), resource accessed (schedule endpoint), and success status |
| 6 | Verify log entry contains all required information: timestamp, user ID, action type, and resource | Log entry is complete with accurate timestamp (within 1 second of actual access), correct user ID, action type 'SCHEDULE_ACCESS', and schedule resource identifier |
| 7 | Attempt unauthorized access by trying to view another employee's schedule (modify URL or API call) | Access is denied with error message 'Access Denied: You do not have permission to view this schedule' |
| 8 | Check audit logs for the unauthorized access attempt | Audit log entry is created containing: timestamp of attempt, user ID of employee who attempted access, action performed (unauthorized schedule access attempt), target resource (other employee's schedule ID), and failure status with reason |
| 9 | Verify unauthorized attempt log includes details of the denied access | Log entry shows accurate timestamp, correct user ID, action type 'UNAUTHORIZED_ACCESS_ATTEMPT', target employee ID, and failure reason 'INSUFFICIENT_PERMISSIONS' |

**Postconditions:**
- All schedule access attempts are logged in audit system
- Audit logs contain complete information for security monitoring
- Both successful and failed access attempts are recorded
- Logs are timestamped and associated with correct user IDs
- Audit trail is maintained for compliance and security review

---

## Story: As Employee, I want to log out securely to protect my schedule information
**Story ID:** story-16

### Test Case: Validate successful logout and session termination
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee is logged into the application with valid credentials
- Employee has an active session with valid session token
- Employee is on any schedule page within the application
- Browser has session data stored (cookies, local storage, session storage)

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Locate the logout button on the current schedule page | Logout button is visible and accessible on the page |
| 2 | Click the logout button | POST request is sent to /api/auth/logout endpoint |
| 3 | Observe the system response after clicking logout | Session token is invalidated on the server side and employee is automatically redirected to the login page within 2 seconds |
| 4 | Verify the current page URL after logout | Employee is on the login page with URL showing login endpoint |
| 5 | Click the browser back button to attempt returning to the schedule page | Access is denied and employee is redirected back to the login page |
| 6 | Manually enter the URL of a schedule page in the browser address bar | Access is denied and employee is redirected to the login page with appropriate authentication required message |
| 7 | Attempt to make an API call using the previous session token | API returns 401 Unauthorized error indicating session token is invalid |

**Postconditions:**
- Employee session is completely terminated
- Session token is invalidated and cannot be reused
- Employee is on the login page
- No authenticated pages are accessible without re-login

---

### Test Case: Verify client-side session data clearance on logout
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Employee is logged into the application with valid credentials
- Employee has an active session with session data stored in browser
- Browser developer tools are available for inspection
- Session data exists in cookies, local storage, and/or session storage

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open browser developer tools (F12) and navigate to Application/Storage tab | Developer tools open and storage inspection panel is visible |
| 2 | Inspect and document existing session data in Cookies section | Session cookies are present (e.g., session token, user ID, authentication cookies) |
| 3 | Inspect and document existing session data in Local Storage section | Local storage contains session-related data (e.g., user preferences, cached data) |
| 4 | Inspect and document existing session data in Session Storage section | Session storage contains temporary session data |
| 5 | Click the logout button from the application | Logout process initiates and employee is redirected to login page |
| 6 | Return to browser developer tools and inspect Cookies section | All session-related cookies are removed or cleared from browser storage |
| 7 | Inspect Local Storage section in developer tools | All sensitive session data is cleared from local storage |
| 8 | Inspect Session Storage section in developer tools | All session storage data is completely cleared |
| 9 | Verify no authentication tokens or sensitive employee data remains in any browser storage | No residual session data, tokens, or sensitive information is found in cookies, local storage, or session storage |

**Postconditions:**
- All client-side session data is completely cleared
- No authentication tokens remain in browser storage
- No sensitive employee information is accessible in browser
- Employee is on the login page requiring fresh authentication

---

