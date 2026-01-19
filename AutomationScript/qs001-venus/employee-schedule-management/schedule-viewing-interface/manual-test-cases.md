# Manual Test Cases

## Story: As Employee, I want to view my daily schedule to plan my workday effectively
**Story ID:** story-7

### Test Case: Validate successful display of daily schedule
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee has valid login credentials
- Employee has at least one shift scheduled for current and next day
- Web portal is accessible and operational
- Employee is not already logged into the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the web portal login page using a supported browser | Login page is displayed with username and password fields |
| 2 | Enter valid employee credentials (username and password) and click Login button | Employee is successfully authenticated and redirected to the dashboard page |
| 3 | Verify the dashboard is fully loaded | Dashboard is displayed with navigation menu and employee information visible |
| 4 | Click on the Schedule section from the navigation menu | Schedule section opens with view options available |
| 5 | Select the Daily View option | Daily schedule for the current day is displayed showing shift start time, end time, location, role details, and any special notes |
| 6 | Verify all shift details are accurate and complete for the current day | All shift information matches the expected schedule data including times, location, and role |
| 7 | Click on the Next Day navigation button or arrow | Schedule view updates to display the next day's schedule with correct date and shift details |
| 8 | Verify the next day's schedule displays correctly | Next day's schedule shows accurate shift information with proper formatting and all details visible |

**Postconditions:**
- Employee remains logged into the system
- Daily schedule view is displaying the next day's schedule
- No errors or warnings are displayed
- Session remains active

---

### Test Case: Verify access restriction for unauthenticated users
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- User is not logged into the system
- No active session exists in the browser
- Daily schedule URL is known
- Web portal is accessible and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Clear all browser cookies and cache to ensure no active session exists | Browser cache and cookies are cleared successfully |
| 2 | Open a new browser window or tab | New browser window opens successfully |
| 3 | Directly enter the daily schedule URL (e.g., /schedules/daily) in the address bar and press Enter | Access is denied and user is automatically redirected to the login page |
| 4 | Verify the login page is displayed with appropriate message | Login page appears with a message indicating authentication is required to access the requested page |
| 5 | Verify that no schedule data is visible or accessible | No schedule information is displayed and no unauthorized access to data occurs |

**Postconditions:**
- User remains on the login page
- No schedule data has been exposed
- System security is maintained
- No unauthorized session is created

---

### Test Case: Test responsiveness on mobile devices
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Employee has valid login credentials
- Smartphone device is available with internet connectivity
- Mobile browser is installed and functional
- Employee has at least one shift scheduled for the current day
- Web portal supports mobile browsers

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open the mobile browser on the smartphone device | Mobile browser launches successfully |
| 2 | Navigate to the web portal URL and access the login page | Login page loads and displays correctly on the mobile screen with properly sized input fields |
| 3 | Enter valid employee credentials and tap the Login button | Employee is authenticated and redirected to the mobile-optimized dashboard |
| 4 | Tap on the Schedule section from the mobile navigation menu | Schedule section opens with options clearly visible and accessible on mobile screen |
| 5 | Select the Daily View option by tapping on it | Daily schedule page loads and displays correctly on the mobile screen |
| 6 | Verify all schedule elements are visible without horizontal scrolling | Schedule displays with shift details (time, location, role) properly formatted and readable on mobile screen without requiring horizontal scrolling |
| 7 | Test the navigation controls by tapping the next day and previous day buttons | Navigation buttons are easily tappable and schedule updates correctly when navigating between days |
| 8 | Rotate the device to landscape orientation | Schedule view adjusts responsively to landscape mode maintaining readability and usability |
| 9 | Rotate the device back to portrait orientation | Schedule view adjusts back to portrait mode correctly without loss of functionality |

**Postconditions:**
- Employee remains logged in on mobile device
- Daily schedule is displayed correctly in current orientation
- All navigation controls remain functional
- Mobile session remains active

---

## Story: As Employee, I want to view my weekly schedule to plan my workweek efficiently
**Story ID:** story-8

### Test Case: Validate weekly schedule display and navigation
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Employee has valid login credentials
- Employee has shifts scheduled for current and next week
- Web portal is accessible and operational
- Employee is not already logged into the system
- Current week contains at least one scheduled shift

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the web portal login page using a supported browser | Login page is displayed with username and password fields |
| 2 | Enter valid employee credentials (username and password) and click Login button | Employee is successfully authenticated and redirected to the dashboard page |
| 3 | Verify the dashboard is fully loaded with all navigation elements visible | Dashboard is displayed showing navigation menu, employee information, and main content area |
| 4 | Click on the Schedule section from the navigation menu | Schedule section opens displaying available view options (daily, weekly) |
| 5 | Select the Weekly View option | Weekly schedule for the current week is displayed showing all days from week start to week end |
| 6 | Verify the weekly schedule displays all scheduled shifts with complete details | All shifts for the current week are visible showing shift times, locations, roles, and any special notes for each day |
| 7 | Verify weekends are highlighted or visually distinguished from weekdays | Weekend days (Saturday and Sunday) are highlighted with different background color or visual indicator |
| 8 | Verify any holidays in the current week are appropriately marked | Holiday dates are highlighted or marked with special indicator if present in the current week |
| 9 | Click on the Next Week navigation button or arrow | Schedule view updates to display the next week's schedule with correct week dates |
| 10 | Verify the next week's schedule displays correctly with all shift information | Next week's schedule shows accurate shift details for all scheduled days with proper formatting and complete information |
| 11 | Click on the Previous Week navigation button to return to the current week | Schedule view returns to the current week displaying the original schedule data |

**Postconditions:**
- Employee remains logged into the system
- Weekly schedule view is displaying the current week
- No errors or warnings are displayed
- Session remains active
- Navigation controls remain functional

---

### Test Case: Verify access control for weekly schedule
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- User is not logged into the system
- No active session exists in the browser
- Weekly schedule URL is known
- Web portal is accessible and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Clear all browser cookies, cache, and session data | Browser data is cleared successfully and no active sessions remain |
| 2 | Open a new browser window or incognito/private browsing window | New browser window opens with no cached credentials or session data |
| 3 | Directly enter the weekly schedule URL (e.g., /schedules/weekly) in the address bar and press Enter | Access is denied and user is automatically redirected to the login page |
| 4 | Verify the login page is displayed | Login page appears with authentication form and appropriate message indicating login is required |
| 5 | Verify no schedule data or sensitive information is visible on the page | No weekly schedule information is displayed and no unauthorized data access occurs |
| 6 | Check the browser address bar for the current URL | URL shows the login page path, confirming successful redirection from the protected schedule page |

**Postconditions:**
- User remains on the login page
- No schedule data has been exposed or accessed
- System security protocols are enforced
- No unauthorized session is created
- Access control is functioning correctly

---

### Test Case: Test UI responsiveness on tablet devices
- **ID:** tc-006
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Employee has valid login credentials
- Tablet device is available with internet connectivity
- Tablet browser is installed and functional
- Employee has shifts scheduled for the current week
- Web portal supports tablet browsers
- Tablet screen resolution is standard (e.g., 768x1024 or similar)

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open the browser application on the tablet device | Tablet browser launches successfully and is ready for navigation |
| 2 | Navigate to the web portal URL in the tablet browser | Login page loads and displays correctly optimized for tablet screen size |
| 3 | Enter valid employee credentials using the on-screen keyboard and tap Login | Employee is authenticated successfully and redirected to the tablet-optimized dashboard |
| 4 | Tap on the Schedule section from the navigation menu | Schedule section opens with view options clearly visible and properly sized for tablet interaction |
| 5 | Select the Weekly View option by tapping on it | Weekly schedule page loads and displays correctly on the tablet screen |
| 6 | Verify the entire week is visible without requiring horizontal scrolling | All seven days of the week are displayed in a readable format without horizontal scrolling, with shift details clearly visible |
| 7 | Verify all shift information is readable including times, locations, and roles | Text is appropriately sized for tablet viewing and all schedule details are legible without zooming |
| 8 | Test the next week navigation by tapping the next week button | Navigation button responds to touch input and schedule updates to show next week correctly |
| 9 | Test the previous week navigation by tapping the previous week button | Navigation button responds to touch input and schedule returns to previous week correctly |
| 10 | Rotate the tablet to landscape orientation | Weekly schedule view adjusts responsively to landscape mode, maintaining readability and proper layout |
| 11 | Verify all schedule elements remain accessible and properly formatted in landscape mode | Schedule displays correctly in landscape with all days visible and navigation controls accessible |
| 12 | Rotate the tablet back to portrait orientation | Weekly schedule view adjusts back to portrait mode correctly without loss of data or functionality |

**Postconditions:**
- Employee remains logged in on tablet device
- Weekly schedule is displayed correctly in current orientation
- All navigation controls remain functional
- Tablet session remains active
- No layout or display errors are present

---

## Story: As Employee, I want to view my monthly schedule to plan long-term commitments
**Story ID:** story-13

### Test Case: Validate monthly schedule display and navigation
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Employee has valid login credentials
- Employee is authenticated with OAuth 2.0
- Employee has assigned shifts in the current and next month
- EmployeeSchedules API is accessible and operational
- Web application is loaded in a supported browser

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Employee logs into the web application using valid credentials | Employee is successfully authenticated and redirected to the dashboard |
| 2 | Employee navigates to the schedule section from the main menu | Schedule section is displayed with view options available |
| 3 | Employee selects monthly view option | Monthly schedule for current month is displayed showing all assigned shifts, weekends are highlighted, holidays are highlighted distinctly, and the page loads within 3 seconds |
| 4 | Employee verifies that all shifts for the current month are visible on the calendar | All shifts assigned to the employee for the current month are displayed with correct dates and times |
| 5 | Employee clicks the next month navigation button | Schedule for next month is displayed without errors, showing all assigned shifts for that month, and the transition is smooth |
| 6 | Employee clicks the previous month navigation button to return to current month | Schedule for current month is displayed again without errors |
| 7 | Employee hovers mouse cursor over a shift entry on the calendar | Shift details are displayed in a tooltip or popup showing shift time, duration, location, and any additional relevant information |
| 8 | Employee moves cursor away from the shift entry | Shift details tooltip or popup disappears |
| 9 | Employee clicks on a different shift entry | Shift details for the clicked shift are displayed showing complete information |

**Postconditions:**
- Employee remains logged in
- Monthly schedule view remains active
- No errors are logged in the system
- API call to GET /api/schedules/monthly was successful

---

### Test Case: Verify responsiveness on desktop and mobile
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Employee has valid login credentials
- Employee has assigned shifts in the current month
- Desktop browser (Chrome, Firefox, or Safari) is available
- Mobile device or mobile emulator is available
- EmployeeSchedules API is accessible and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Employee logs into the web application on a desktop browser using valid credentials | Employee is successfully authenticated and redirected to the dashboard on desktop |
| 2 | Employee navigates to the schedule section and selects monthly view on desktop | Monthly schedule is displayed correctly with proper layout, all shifts are visible, navigation controls are accessible, and weekends/holidays are highlighted |
| 3 | Employee verifies that the calendar grid displays properly on desktop with adequate spacing and readability | Calendar grid is well-formatted, shift entries are readable, and all UI elements are properly aligned |
| 4 | Employee tests navigation between months using desktop interface | Navigation works smoothly without layout issues or broken elements |
| 5 | Employee hovers over shifts and clicks on shifts to view details on desktop | Shift details display correctly in tooltips or popups without overlapping or layout issues |
| 6 | Employee logs into the web application on a mobile device or mobile emulator | Employee is successfully authenticated and redirected to the dashboard on mobile |
| 7 | Employee navigates to the schedule section and selects monthly view on mobile | Monthly schedule is displayed correctly with responsive layout optimized for mobile screen, all shifts are visible, navigation controls are touch-friendly, and weekends/holidays are highlighted |
| 8 | Employee verifies that the calendar grid adapts properly to mobile screen size | Calendar grid is responsive, shift entries are readable without horizontal scrolling, and all UI elements are accessible |
| 9 | Employee tests navigation between months using mobile touch interface | Navigation works smoothly with touch gestures without layout issues or broken elements |
| 10 | Employee taps on shifts to view details on mobile | Shift details display correctly in mobile-optimized format without overlapping or layout issues |

**Postconditions:**
- Employee remains logged in on both devices
- Monthly schedule view displays correctly on both desktop and mobile
- No responsive design issues are present
- All functionality works on both platforms

---

## Story: As Employee, I want to receive confirmation when my schedule is successfully loaded to ensure data accuracy
**Story ID:** story-14

### Test Case: Validate confirmation message on successful load
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee has valid login credentials
- Employee has assigned shifts in the schedule
- Schedule APIs are accessible and operational
- Web application is loaded in a supported browser
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Employee logs into the web application using valid credentials | Employee is successfully authenticated and redirected to the dashboard |
| 2 | Employee navigates to the schedule section | Schedule section page is displayed with view options available |
| 3 | Employee requests schedule view by selecting a schedule view option (daily, weekly, or monthly) | Loading indicator is displayed while schedule data is being retrieved |
| 4 | System retrieves schedule data from the Schedule API | Schedule data is successfully loaded and displayed on the screen with all shifts visible |
| 5 | Employee observes the confirmation message after schedule loads | A confirmation message is displayed indicating successful schedule load (e.g., 'Schedule loaded successfully' or 'Your schedule is up to date') within 1 second of the schedule being displayed |
| 6 | Employee verifies that the confirmation message is clearly visible and appropriately styled | Confirmation message is displayed in a noticeable location (e.g., top of page or as a toast notification) with appropriate styling (e.g., green color or success icon) |
| 7 | Employee waits to observe if the confirmation message auto-dismisses or requires manual dismissal | Confirmation message either auto-dismisses after a few seconds or can be manually dismissed by the employee |
| 8 | Employee verifies that the displayed schedule data matches expected shifts | All expected shifts are displayed with correct dates, times, and details |

**Postconditions:**
- Employee remains logged in
- Schedule is successfully loaded and displayed
- Confirmation message has been displayed and dismissed
- No errors are logged in the system
- Schedule data is accurate and complete

---

### Test Case: Validate error message and retry on failure
- **ID:** tc-004
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Employee has valid login credentials
- Employee is authenticated and logged in
- Ability to simulate API failure is available (test environment or mock setup)
- Web application is loaded in a supported browser

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Test engineer configures the test environment to simulate API failure for schedule load request | API is configured to return an error response or timeout when schedule data is requested |
| 2 | Employee navigates to the schedule section | Schedule section page is displayed with view options available |
| 3 | Employee requests schedule view by selecting a schedule view option | Loading indicator is displayed while system attempts to retrieve schedule data |
| 4 | System attempts to retrieve schedule data from the Schedule API which fails due to simulated error | API request fails and returns an error response |
| 5 | Employee observes the error handling behavior | An error message is displayed clearly indicating that the schedule failed to load (e.g., 'Unable to load schedule' or 'Schedule loading failed. Please try again.') |
| 6 | Employee verifies that the error message includes a retry option | A retry button or link is displayed alongside the error message allowing the employee to attempt reloading the schedule |
| 7 | Employee verifies that the error message is clearly visible and appropriately styled | Error message is displayed in a noticeable location with appropriate styling (e.g., red color or error icon) |
| 8 | Test engineer restores normal API functionality to allow successful schedule load | API is configured to return successful responses for schedule data requests |
| 9 | Employee clicks the retry button or link | Loading indicator is displayed again and schedule reload is attempted |
| 10 | System retrieves schedule data from the Schedule API successfully | Schedule data is successfully loaded and displayed on the screen with all shifts visible |
| 11 | Employee observes the confirmation message after successful retry | A confirmation message is displayed indicating successful schedule load, and the error message is no longer visible |

**Postconditions:**
- Employee remains logged in
- Schedule is successfully loaded after retry
- Error message is no longer displayed
- Confirmation message has been displayed
- API is restored to normal functionality
- System logs contain appropriate error and recovery information

---

## Story: As Employee, I want to navigate between different schedule views to access the information I need
**Story ID:** story-15

### Test Case: Validate navigation between schedule views
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee has valid login credentials
- Employee is logged into the schedule system
- Schedule data exists for the employee
- Web browser is supported (Chrome, Firefox, Safari, Edge)
- Internet connection is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule dashboard and verify the default view is displayed | Schedule dashboard loads successfully with default view (daily/weekly/monthly) displayed |
| 2 | Locate and click on the 'Weekly View' navigation control button | Weekly view navigation button is highlighted or selected |
| 3 | Observe the schedule display update | Weekly schedule is displayed showing 7 days in a grid or list format with all scheduled shifts visible for the current week |
| 4 | Locate and click on the 'Monthly View' navigation control button | Monthly view navigation button is highlighted or selected |
| 5 | Observe the schedule display update | Monthly schedule is displayed showing the entire month in calendar format with all scheduled shifts visible for the current month |
| 6 | Locate and click on the 'Daily View' navigation control button | Daily view navigation button is highlighted or selected |
| 7 | Observe the schedule display update | Daily schedule is displayed showing only the current day with detailed shift information and time slots |
| 8 | Verify that employee context (name, department, selected date) is maintained across all view changes | Employee information and selected date context remain consistent across all views |

**Postconditions:**
- Employee remains logged in
- Daily view is currently displayed
- No errors or warnings are present
- Navigation controls remain functional
- User session is still active

---

### Test Case: Verify load times for schedule views
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Employee has valid login credentials
- Employee is logged into the schedule system
- Schedule data exists for the employee covering daily, weekly, and monthly periods
- Network connection is stable with normal bandwidth
- Browser developer tools or performance monitoring tool is available
- System is under normal load conditions

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open browser developer tools and navigate to the Network or Performance tab to monitor load times | Developer tools are open and ready to capture performance metrics |
| 2 | From the current view, click on the 'Daily View' navigation control and start timing | Daily view begins loading immediately upon click |
| 3 | Measure and record the time taken for the daily view to fully load and display all schedule data | Daily view loads completely within 3 seconds with all shifts and details visible |
| 4 | Click on the 'Weekly View' navigation control and start timing | Weekly view begins loading immediately upon click |
| 5 | Measure and record the time taken for the weekly view to fully load and display all schedule data | Weekly view loads completely within 3 seconds with all 7 days and shifts visible |
| 6 | Click on the 'Monthly View' navigation control and start timing | Monthly view begins loading immediately upon click |
| 7 | Measure and record the time taken for the monthly view to fully load and display all schedule data | Monthly view loads completely within 3 seconds with entire month calendar and all shifts visible |
| 8 | Review all recorded load times and verify each is under the 3-second threshold | All three views (daily, weekly, monthly) have load times documented as under 3 seconds |
| 9 | Verify that no loading errors, timeouts, or performance warnings occurred during navigation | No errors are displayed in the console or UI, and all views loaded successfully |

**Postconditions:**
- All schedule views have been tested for load time performance
- Performance metrics are documented
- Employee remains logged in
- System is in a stable state
- No performance degradation is observed

---

## Story: As Employee, I want to securely log in to the schedule system to protect my personal schedule data
**Story ID:** story-16

### Test Case: Validate successful login with valid credentials
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- Employee has a registered account in the schedule system
- Employee has valid username and password credentials
- Login page is accessible via HTTPS
- Web browser is supported and up to date
- Employee is not currently logged in
- No active session exists for the employee

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule system login page URL | Login page loads successfully displaying username and password input fields, and a login button |
| 2 | Verify that the connection is secure by checking for HTTPS in the URL and a padlock icon in the browser | HTTPS protocol is confirmed and secure connection indicator is visible |
| 3 | Enter a valid registered username in the username field | Username is entered and displayed in the username field (or masked appropriately) |
| 4 | Enter the correct password corresponding to the username in the password field | Password is entered and displayed as masked characters (dots or asterisks) |
| 5 | Click the 'Login' or 'Sign In' button | System processes the login request and shows a loading indicator if applicable |
| 6 | Observe the authentication process and page transition | User is successfully authenticated and redirected to the schedule dashboard or home page |
| 7 | Verify that the schedule dashboard displays the employee's name, schedule data, and navigation options | Dashboard loads with personalized employee information, current schedule view, and all navigation controls visible |
| 8 | Check that a valid session has been established by verifying session indicators (e.g., logout button, user profile) | Session is active with logout option available and user profile/name displayed |

**Postconditions:**
- Employee is successfully logged into the system
- Active session is established and maintained
- Employee has access to their schedule dashboard
- Session token/cookie is stored securely
- Login attempt is logged in the system audit trail

---

### Test Case: Verify login failure with invalid credentials
- **ID:** tc-004
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Login page is accessible via HTTPS
- Web browser is supported and up to date
- Employee is not currently logged in
- Test account credentials are available for testing invalid scenarios

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule system login page URL | Login page loads successfully displaying username and password input fields, and a login button |
| 2 | Enter an invalid or non-existent username in the username field | Invalid username is entered and displayed in the username field |
| 3 | Enter any password in the password field | Password is entered and displayed as masked characters |
| 4 | Click the 'Login' or 'Sign In' button | System processes the login request |
| 5 | Observe the system response | Login is denied and an error message is displayed such as 'Invalid username or password' without specifying which field is incorrect |
| 6 | Verify that the user remains on the login page and is not redirected | User remains on the login page with input fields cleared or ready for re-entry |
| 7 | Enter a valid registered username in the username field | Valid username is entered and displayed in the username field |
| 8 | Enter an incorrect password in the password field | Incorrect password is entered and displayed as masked characters |
| 9 | Click the 'Login' or 'Sign In' button | System processes the login request |
| 10 | Observe the system response | Login is denied and an error message is displayed such as 'Invalid username or password' without specifying which field is incorrect |
| 11 | Verify that no session is created and no access to the schedule system is granted | User remains unauthenticated with no access to protected resources |
| 12 | Verify that failed login attempts are logged for security monitoring | Failed login attempts are recorded in the system audit log with timestamp and attempted username |

**Postconditions:**
- Employee is not logged into the system
- No active session is created
- Login page remains accessible for retry
- Error message is displayed to the user
- Failed login attempts are logged for security purposes
- System remains secure with no unauthorized access granted

---

### Test Case: Test session timeout after inactivity
- **ID:** tc-005
- **Type:** edge-case
- **Priority:** High
- **Estimated Time:** 20 mins

**Preconditions:**
- Employee has valid login credentials
- Session timeout policy is configured in the system (e.g., 15 minutes of inactivity)
- Employee is not currently logged in
- System clock is accurate
- Session timeout duration is known and documented

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule system login page and log in with valid credentials | Employee is successfully authenticated and redirected to the schedule dashboard |
| 2 | Verify that the session is active by checking for user profile information and active session indicators | Active session is confirmed with user name displayed and logout option available |
| 3 | Note the current time and remain inactive (no mouse movements, clicks, or keyboard input) for the duration of the configured session timeout period | No user activity is detected by the system during the timeout period |
| 4 | Wait until the session timeout period has elapsed (e.g., 15 minutes plus 1 minute buffer) | Session timeout period has fully elapsed |
| 5 | Attempt to interact with the schedule system by clicking on any navigation element or schedule view | System detects that the session has expired |
| 6 | Observe the system response to the interaction attempt | User is automatically logged out and redirected to the login page with a session timeout message such as 'Your session has expired due to inactivity. Please log in again.' |
| 7 | Verify that the user no longer has access to protected schedule data without re-authenticating | All protected resources are inaccessible and require re-authentication |
| 8 | Attempt to navigate directly to the schedule dashboard URL without logging in again | System redirects to the login page and denies access to the dashboard |
| 9 | Verify that the expired session token/cookie is invalidated and cannot be reused | Session token is invalidated and any attempt to use it results in authentication failure |

**Postconditions:**
- Employee session is terminated due to inactivity
- Employee is logged out of the system
- User is redirected to the login page
- Session timeout message is displayed
- Session token/cookie is invalidated
- System security is maintained with no unauthorized access possible
- Session timeout event is logged in the audit trail

---

