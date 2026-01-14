# Manual Test Cases

## Story: As Employee, I want to securely log in to the schedule system to achieve personalized schedule access
**Story ID:** story-11

### Test Case: Validate successful login with valid credentials
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- Employee account exists in the system with valid credentials
- Employee account is active and not locked
- Login page is accessible via HTTPS
- Browser is supported (Chrome, Firefox, Safari, Edge)
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open web browser and navigate to the login page URL | Login page loads successfully displaying username field, password field, login button, and 'Forgot Password' link |
| 2 | Enter valid username in the username field | Username is accepted and displayed in the field without validation errors |
| 3 | Enter valid password in the password field | Password is masked with dots or asterisks and no validation errors are shown |
| 4 | Click the 'Login' button to submit the login form | System processes authentication within 2 seconds, user is authenticated successfully, and redirected to the schedule dashboard with personalized greeting or username displayed |
| 5 | Verify the schedule dashboard displays correctly | Schedule dashboard loads with employee-specific data, navigation menu is visible, and session is established |

**Postconditions:**
- User is logged in with active session
- User has access to schedule dashboard
- Login attempt is logged in audit trail
- Session timeout timer is initiated

---

### Test Case: Verify rejection of invalid login attempts
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee account exists in the system
- Employee account is active and not currently locked
- Login page is accessible
- Account lockout policy is configured for 5 failed attempts

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the login page URL | Login form is displayed with username field, password field, and login button |
| 2 | Enter valid username and incorrect password in the respective fields | Fields accept the input without client-side validation errors |
| 3 | Click the 'Login' button to submit the form | System displays error message 'Invalid username or password' and user remains on login page. Failed attempt counter increments to 1 |
| 4 | Enter valid username and incorrect password again | Fields accept the input |
| 5 | Click the 'Login' button to submit the form (2nd attempt) | System displays error message 'Invalid username or password' and user remains on login page. Failed attempt counter increments to 2 |
| 6 | Repeat login attempt with valid username and incorrect password (3rd attempt) | System displays error message 'Invalid username or password'. Failed attempt counter increments to 3 |
| 7 | Repeat login attempt with valid username and incorrect password (4th attempt) | System displays error message 'Invalid username or password'. Failed attempt counter increments to 4 |
| 8 | Repeat login attempt with valid username and incorrect password (5th attempt) | System displays error message 'Your account has been locked due to multiple failed login attempts. Please contact administrator or use password recovery' and account is locked. User cannot proceed to login |
| 9 | Attempt to login with correct credentials for the locked account | System displays message 'Your account is locked. Please contact administrator or use password recovery' and denies access |

**Postconditions:**
- User account is locked after 5 failed attempts
- All failed login attempts are logged in audit trail
- User notification is triggered (email/SMS if configured)
- User remains on login page without access to system

---

### Test Case: Test password recovery workflow
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- Employee account exists with registered email address
- Email service is configured and operational
- Login page is accessible
- Password recovery feature is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the login page URL | Login form is displayed with 'Forgot Password' link visible below or near the login button |
| 2 | Click on the 'Forgot Password' link | User is redirected to password recovery page displaying email input field and submit button with instructions 'Enter your registered email address to receive password reset instructions' |
| 3 | Enter valid registered email address in the email field | Email address is accepted and displayed in the field with proper email format validation |
| 4 | Click the 'Submit' or 'Send Reset Link' button | System displays confirmation message 'Password reset instructions have been sent to your email address' and processes the request within 2 seconds |
| 5 | Check the registered email inbox for password reset email | Password reset email is received within 5 minutes containing reset link, instructions, and expiration time (typically 24 hours) |
| 6 | Click the password reset link in the email | User is redirected to password reset page with fields for new password and confirm password, along with password complexity requirements displayed |

**Postconditions:**
- Password reset email is sent successfully
- Password reset token is generated and stored
- Password recovery attempt is logged in audit trail
- User can proceed to reset password using the link

---

## Story: As Employee, I want to view my daily schedule to achieve clear understanding of my work shifts
**Story ID:** story-12

### Test Case: Validate daily schedule display with accurate shift details
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- Employee account is created and active
- Employee has valid login credentials
- Employee has at least one shift scheduled for the current day
- Schedule data exists in the database
- User is not currently logged in

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the login page and enter valid employee credentials (username and password) | Login is successful and user is redirected to the schedule dashboard within 2 seconds |
| 2 | Verify the schedule dashboard loads completely | Schedule dashboard is displayed with navigation options including 'Daily View', 'Weekly View', and other menu items. Current date is visible |
| 3 | Click on 'Daily View' option or tab in the navigation menu | Daily schedule view loads within 3 seconds displaying the current day's schedule with date prominently shown |
| 4 | Review the displayed shift information for start time | Shift start time is displayed in clear format (e.g., 09:00 AM) and matches the scheduled start time in the database |
| 5 | Review the displayed shift information for end time | Shift end time is displayed in clear format (e.g., 05:00 PM) and matches the scheduled end time in the database |
| 6 | Verify the shift location information | Shift location is clearly displayed (e.g., 'Building A - Floor 2' or 'Downtown Office') and matches database records |
| 7 | Verify the shift role information | Employee role for the shift is displayed (e.g., 'Cashier', 'Manager', 'Sales Associate') and matches database records |
| 8 | Check for shift status indicator | Shift status is displayed (e.g., 'Confirmed', 'Pending') with appropriate visual indicator (color or icon) |
| 9 | Verify the current day is highlighted visually | Current day is highlighted with distinct background color, border, or other visual emphasis to differentiate from other days |

**Postconditions:**
- User remains logged in with active session
- Daily schedule view is displayed
- All shift details are accurately shown
- Page load time is within 3 seconds performance requirement

---

### Test Case: Verify access restriction to employee's own schedule
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Two employee accounts exist: Employee A and Employee B
- Both employees have valid login credentials
- Both employees have schedules assigned in the system
- Role-based access control is configured
- User is not currently logged in

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to login page and log in using Employee A's credentials (username and password) | Employee A is successfully authenticated and redirected to schedule dashboard showing Employee A's schedule data |
| 2 | Note the current URL in the browser address bar | URL contains Employee A's identifier or session token (e.g., /schedule/employee/A or /schedule/daily?user=employeeA) |
| 3 | Manually modify the URL to attempt accessing Employee B's schedule by changing the employee identifier in the URL (e.g., change employeeA to employeeB) | System detects unauthorized access attempt and displays error message 'Access Denied: You do not have permission to view this schedule' or redirects to Employee A's own schedule |
| 4 | Verify that Employee B's schedule data is not displayed | No schedule information for Employee B is visible. Only error message or Employee A's schedule is shown |
| 5 | Click logout button or link to end Employee A's session | Employee A is logged out successfully and redirected to login page. Session is terminated |
| 6 | Log in using Employee B's credentials (username and password) | Employee B is successfully authenticated and redirected to schedule dashboard |
| 7 | Verify the schedule dashboard displays Employee B's schedule | Schedule dashboard loads within 3 seconds showing Employee B's personal schedule with correct shift details, location, and role information specific to Employee B |
| 8 | Confirm that Employee A's schedule data is not visible to Employee B | Only Employee B's schedule is displayed. No information about Employee A's shifts or schedule is visible |

**Postconditions:**
- Access control is enforced successfully
- Unauthorized access attempt is logged in audit trail
- Employee B is logged in with access to only their own schedule
- Data privacy is maintained between employee accounts

---

## Story: As Employee, I want to view my weekly schedule to plan my workweek effectively
**Story ID:** story-13

### Test Case: Validate weekly schedule display and navigation
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee account exists in the system with valid credentials
- Employee has assigned shifts for current and next week
- Schedule database is accessible and populated with shift data
- Application is accessible via supported browser
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the application login page and enter valid employee credentials (username and password), then click the Login button | Employee is successfully authenticated and redirected to the schedule dashboard. Dashboard displays navigation options including weekly view option |
| 2 | Click on or select the 'Weekly View' option from the schedule dashboard | Current week's schedule is displayed showing all assigned shifts with start times, end times, and location details. Current week is visually highlighted. Page loads within 4 seconds |
| 3 | Click on the 'Next Week' navigation button or arrow to move forward one week | Next week's schedule is displayed accurately with all assigned shifts, start times, end times, and locations. Week dates update correctly. Navigation completes without errors. Page loads within 4 seconds |

**Postconditions:**
- Employee remains logged into the system
- Weekly schedule view remains active and accessible
- Next week's schedule data is displayed on screen
- System maintains session state for further navigation

---

### Test Case: Verify schedule data access restriction
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- Two employee accounts exist: Employee A and Employee B with valid credentials
- Both employees have assigned shifts in the system
- Employee B's schedule data exists in the database
- Application enforces employee-specific data access security
- Application is accessible via supported browser

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the application login page and enter Employee A's valid credentials (username and password), then click the Login button | Employee A is successfully authenticated and redirected to their schedule dashboard. Dashboard displays Employee A's schedule information and navigation options |
| 2 | Attempt to access Employee B's weekly schedule by manipulating URL parameters, API calls, or any available navigation method to view another employee's schedule data | Access is denied. System displays an error message indicating 'Access Denied' or 'You do not have permission to view this schedule'. Employee B's schedule data is not displayed. Employee A remains on their own schedule view or is redirected to an error page. Security log records the unauthorized access attempt |

**Postconditions:**
- Employee A remains logged in with access only to their own schedule
- Employee B's schedule data remains protected and inaccessible to Employee A
- System security logs record the access denial event
- No unauthorized data exposure occurs

---

## Story: As Employee, I want to view my monthly schedule to have a long-term overview of my shifts
**Story ID:** story-14

### Test Case: Validate monthly schedule display and navigation
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee account exists in the system with valid credentials
- Employee has assigned shifts for current and next month
- Schedule database is accessible and populated with monthly shift data
- Application is accessible via supported browser
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the application login page and enter valid employee credentials (username and password), then click the Login button | Employee is successfully authenticated and redirected to the schedule dashboard. Dashboard displays navigation options including monthly view option |
| 2 | Click on or select the 'Monthly View' option from the schedule dashboard | Current month's schedule is displayed showing all assigned shifts with start times, end times, and location details. Current month is visually highlighted. Calendar format displays all days of the month. Page loads within 5 seconds |
| 3 | Click on the 'Next Month' navigation button or arrow to move forward one month | Next month's schedule is displayed accurately with all assigned shifts, start times, end times, and locations. Month and year update correctly. All dates for the next month are visible. Navigation completes without errors. Page loads within 5 seconds |

**Postconditions:**
- Employee remains logged into the system
- Monthly schedule view remains active and accessible
- Next month's schedule data is displayed on screen
- System maintains session state for further navigation

---

### Test Case: Verify access restriction to employee's monthly schedule
- **ID:** tc-004
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- Two employee accounts exist: Employee A and Employee B with valid credentials
- Both employees have assigned shifts in the system for the current month
- Employee B's monthly schedule data exists in the database
- Application enforces employee-specific data access security
- Application is accessible via supported browser

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the application login page and enter Employee A's valid credentials (username and password), then click the Login button | Employee A is successfully authenticated and redirected to their schedule dashboard. Dashboard displays Employee A's schedule information and navigation options |
| 2 | Attempt to access Employee B's monthly schedule by manipulating URL parameters, API calls, or any available navigation method to view another employee's schedule data | Access is denied. System displays an error message indicating 'Access Denied' or 'You do not have permission to view this schedule'. Employee B's monthly schedule data is not displayed. Employee A remains on their own schedule view or is redirected to an error page. Security log records the unauthorized access attempt |

**Postconditions:**
- Employee A remains logged in with access only to their own schedule
- Employee B's monthly schedule data remains protected and inaccessible to Employee A
- System security logs record the access denial event
- No unauthorized data exposure occurs

---

## Story: As Employee, I want the schedule interface to be responsive to use on mobile devices to achieve accessibility anytime
**Story ID:** story-19

### Test Case: Validate responsive layout on mobile devices
- **ID:** tc-019-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- Employee has valid login credentials
- Schedule interface is deployed and accessible
- Smartphone device with modern browser (Chrome, Safari, Firefox) is available
- Device has active internet connection
- Test device screen size is between 320px - 480px width

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open smartphone browser and navigate to the schedule interface URL | Schedule login page loads and displays correctly on mobile screen |
| 2 | Log in with valid employee credentials | User is authenticated and schedule dashboard is displayed |
| 3 | Observe the layout of the schedule interface on the smartphone screen | Layout adjusts to screen size without horizontal scrolling, all elements are visible and properly aligned |
| 4 | Navigate to different schedule views (daily, weekly, monthly) | Each view adapts responsively to the mobile screen, maintaining readability and usability |
| 5 | Access and use filter options (date range, department, employee) | Filter controls are accessible, properly sized for touch interaction, and function correctly |
| 6 | Scroll vertically and horizontally through the schedule content | Scrolling is smooth, no content is cut off, and no unwanted horizontal scrolling occurs |
| 7 | Tap on various interactive controls (buttons, dropdowns, date pickers) | Controls respond accurately and promptly to touch input without delay or misregistration |
| 8 | Test touch gestures such as swipe and pinch-to-zoom if applicable | Touch gestures work as expected and enhance navigation experience |
| 9 | Rotate device from portrait to landscape orientation | Interface adapts seamlessly to orientation change, maintaining functionality and layout integrity |

**Postconditions:**
- User remains logged in to the schedule interface
- No UI elements are broken or misaligned
- All schedule data is displayed correctly
- Session is active for further testing or normal use

---

### Test Case: Verify load times on mobile network
- **ID:** tc-019-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Employee has valid login credentials
- Mobile device is connected to 4G network (not WiFi)
- Network speed testing tool or browser developer tools are available
- Schedule interface is deployed and accessible
- Browser cache is cleared before test execution

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Ensure mobile device is connected to 4G network and WiFi is disabled | Device shows 4G/LTE connection indicator |
| 2 | Clear browser cache and cookies | Browser cache is empty, ensuring fresh page load |
| 3 | Open browser developer tools or network monitoring tool to track load time | Network monitoring tool is active and ready to record metrics |
| 4 | Navigate to the schedule interface URL and start timer | Page begins loading, network requests are initiated |
| 5 | Wait for the page to fully load and become interactive | Page loads completely within 5 seconds, all content is visible and interactive |
| 6 | Record the total page load time from network monitoring tool | Load time is documented and is under 5 seconds |
| 7 | Log in with valid credentials and measure dashboard load time | Schedule dashboard loads within 5 seconds after authentication |
| 8 | Navigate to different schedule views and measure load times for each | Each view transition completes within 5 seconds on 4G network |

**Postconditions:**
- Load time metrics are documented for analysis
- User is logged into the schedule interface
- Performance baseline is established for mobile network access
- No performance degradation is observed

---

## Story: As Employee, I want to log out securely from the schedule system to protect my personal information
**Story ID:** story-20

### Test Case: Validate secure logout process
- **ID:** tc-020-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Employee has valid login credentials
- Schedule system is accessible and operational
- User is not currently logged in
- Browser is open with no active sessions
- Logout button is implemented and visible on all schedule pages

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule system login page | Login page is displayed with username and password fields |
| 2 | Enter valid employee credentials and click login button | User is authenticated successfully |
| 3 | Verify that the schedule dashboard is displayed | Schedule dashboard loads with employee's schedule data visible |
| 4 | Locate the logout button on the dashboard page | Logout button is visible and accessible in the navigation area |
| 5 | Click the logout button | System initiates logout process, user session is terminated, and user is redirected to login page within 2 seconds |
| 6 | Verify the current page is the login page | Login page is displayed, indicating successful logout |
| 7 | Click browser back button to attempt navigation to schedule dashboard | Access is denied, user is redirected back to login page or shown access denied message |
| 8 | Manually enter the schedule dashboard URL in the browser address bar | System detects no active session, redirects to login page, and denies access to protected content |
| 9 | Verify no error messages or session warnings are displayed | Clean logout experience with appropriate messaging on login page |

**Postconditions:**
- User session is completely terminated
- Authentication tokens are revoked
- User cannot access protected pages without re-authentication
- System is ready for new login
- No residual session data remains active

---

### Test Case: Verify cached data clearance on logout
- **ID:** tc-020-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Employee has valid login credentials
- Schedule system is accessible
- Browser developer tools are available for cache inspection
- User is not currently logged in
- Browser cache contains no previous session data

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open browser developer tools and navigate to Application/Storage tab | Developer tools are open and storage inspection is available |
| 2 | Navigate to the schedule system login page and log in with valid credentials | User is authenticated and schedule dashboard is displayed |
| 3 | Navigate through multiple schedule views (daily, weekly, monthly) to generate cached data | Schedule data for different views is loaded and displayed correctly |
| 4 | Inspect browser cache, cookies, and local storage in developer tools | Schedule data, session tokens, and cookies are present in browser storage |
| 5 | Document the cached items including session tokens, cookies, and local storage entries | List of cached data is recorded for comparison after logout |
| 6 | Click the logout button | User is logged out and redirected to login page within 2 seconds |
| 7 | Immediately inspect browser cache, cookies, and local storage again | Session-related cached data, authentication tokens, and cookies are cleared or invalidated |
| 8 | Verify that session tokens and authentication cookies are removed | No valid session tokens or authentication cookies remain in browser storage |
| 9 | Log in again with the same credentials | User is authenticated successfully with new session |
| 10 | Observe the schedule data loading process | Fresh schedule data is loaded from the server, not from cache, indicated by network requests in developer tools |
| 11 | Verify new session tokens and cookies are created | New authentication tokens and session cookies are present in browser storage, different from previous session |

**Postconditions:**
- All session-related cached data from previous session is cleared
- New session is established with fresh authentication tokens
- User has access to schedule with new session
- No data leakage from previous session
- System maintains security and privacy standards

---

