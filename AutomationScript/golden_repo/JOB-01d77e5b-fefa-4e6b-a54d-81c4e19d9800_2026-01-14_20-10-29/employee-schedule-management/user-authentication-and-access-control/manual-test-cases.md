# Manual Test Cases

## Story: As Employee, I want to securely log in to the schedule system to protect my personal data
**Story ID:** story-14

### Test Case: Validate successful SSO login and schedule access
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- Employee has valid corporate credentials
- Corporate SSO portal is operational
- Schedule system is accessible
- Employee has been provisioned in the system
- Browser cookies are enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to schedule system login page | User is automatically redirected to corporate SSO portal login page |
| 2 | Enter valid corporate username and password on SSO portal | Credentials are accepted by SSO portal |
| 3 | Submit authentication form | User is redirected back to schedule system and logged in successfully with welcome message displayed |
| 4 | Access personal schedule page from navigation menu | Personal schedule page loads successfully displaying employee's schedule data |
| 5 | Verify user session is active by checking session indicator | User name and active session indicator are displayed in header |

**Postconditions:**
- Employee is authenticated and logged into the system
- Active session is established
- Session token is stored securely
- Login attempt is logged in audit trail with timestamp and user details

---

### Test Case: Verify session timeout after inactivity
- **ID:** tc-002
- **Type:** edge-case
- **Priority:** High
- **Estimated Time:** 18 mins

**Preconditions:**
- Employee is logged into the schedule system
- Active session exists
- Session timeout is configured to 15 minutes
- System clock is accurate

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in to the schedule system using valid SSO credentials | User is successfully logged in and schedule page is accessible |
| 2 | Note the current time and remain inactive (no clicks, no keyboard input) for exactly 15 minutes | No user activity is detected by the system during this period |
| 3 | After 15 minutes of inactivity, observe the system behavior | Session expires automatically and user is logged out with a session timeout notification message |
| 4 | Attempt to access the personal schedule page by clicking on schedule link or entering URL directly | Access is denied and user is redirected to the login page with message indicating session has expired |
| 5 | Verify that session cookies and tokens have been cleared | No valid session tokens exist in browser storage or cookies |

**Postconditions:**
- User session is terminated
- Session tokens are invalidated
- User is logged out of the system
- Session timeout event is logged in audit trail

---

### Test Case: Ensure unauthorized access is blocked
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is not logged into the schedule system
- No active session exists
- Schedule system is operational
- User has a valid browser

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open browser and directly navigate to the schedule page URL without logging in | Access is denied immediately |
| 2 | Observe system response | User is automatically redirected to the login page with message indicating authentication is required |
| 3 | Verify that no schedule data is displayed or accessible | No sensitive schedule information is visible or retrievable |
| 4 | Check browser developer tools for any exposed session tokens or data | No valid session tokens or sensitive data are present |
| 5 | Verify unauthorized access attempt is logged | Failed access attempt is recorded in audit log with timestamp and attempted URL |

**Postconditions:**
- User remains unauthenticated
- No access to schedule data is granted
- User is on login page
- Unauthorized access attempt is logged in audit trail

---

## Story: As Employee, I want to log out securely to protect my schedule information
**Story ID:** story-18

### Test Case: Validate successful logout and session termination
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee is logged into the schedule system
- Active session exists with valid session token
- Logout button is visible and accessible
- User is on any page within the schedule system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Locate the logout button in the application header or navigation menu | Logout button is visible and clickable |
| 2 | Click the logout button | User session is immediately terminated and user is redirected to the login page |
| 3 | Verify logout confirmation message is displayed | Message confirming successful logout is shown on login page |
| 4 | Check browser cookies and session storage for session tokens | All session cookies and tokens are cleared and no longer present |
| 5 | Click browser back button to attempt returning to schedule page | Access is denied and user remains on login page or is redirected back to login page |
| 6 | Attempt to access the personal schedule page by entering the URL directly in browser | Access is denied and user is redirected to login page with authentication required message |
| 7 | Verify that schedule data is not accessible without re-authentication | No schedule information is displayed and system requires login to proceed |
| 8 | Check that logout action is logged in audit trail | Logout event is recorded with timestamp and user details in system logs |

**Postconditions:**
- User session is completely terminated
- All session cookies and tokens are cleared
- User is on the login page
- User cannot access any protected pages without re-authentication
- Logout event is logged in audit trail

---

