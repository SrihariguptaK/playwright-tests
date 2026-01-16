# Manual Test Cases

## Story: As Employee, I want to view my daily schedule to plan my workday effectively
**Story ID:** story-12

### Test Case: Validate successful daily schedule display with valid employee login
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Employee has valid login credentials
- Employee has at least one shift scheduled for current day
- Web portal is accessible and operational
- Database contains valid schedule data for the employee
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the web portal login page | Login page is displayed with username and password fields |
| 2 | Enter valid employee credentials (username and password) | Credentials are accepted without validation errors |
| 3 | Click the Login button | Login successful and employee dashboard is displayed within 3 seconds |
| 4 | Navigate to the schedule section from the dashboard menu | Schedule section is accessible and navigation completes successfully |
| 5 | Select daily view option | Daily schedule view loads and displays current day's date as header |
| 6 | Verify shift details displayed including start time, end time, location, and role | All shift details are displayed correctly and match the employee's scheduled shifts for the current day |
| 7 | Click the previous day navigation button | Schedule for the previous day loads within 3 seconds showing correct date and shift information |
| 8 | Click the next day navigation button twice | Schedule advances to the next day, then to the day after, loading correctly without errors each time |
| 9 | Verify page layout on desktop view | Schedule displays properly with all elements visible and properly formatted for desktop resolution |
| 10 | Resize browser window to mobile dimensions or access from mobile device | Schedule adapts to mobile layout with responsive design, all information remains accessible |

**Postconditions:**
- Employee remains logged in
- Daily schedule view is displayed
- No errors are logged in the system
- Session remains active

---

### Test Case: Verify access restriction for unauthenticated users
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is not logged into the system
- Web portal is accessible
- Direct URL to daily schedule page is known
- Valid employee credentials are available for second part of test

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open a new browser window or incognito/private browsing session | New browser session opens with no active authentication |
| 2 | Attempt to access the daily schedule URL directly (e.g., /schedules/daily) without logging in | Access is denied and user is automatically redirected to the login page |
| 3 | Verify error message or notification is displayed | System displays appropriate message such as 'Please log in to access this page' or 'Authentication required' |
| 4 | Verify the URL has changed to the login page | Browser URL shows login page path, confirming redirect occurred |
| 5 | Enter valid employee credentials on the login page | Credentials are accepted and validation passes |
| 6 | Click the Login button | Login successful and user is redirected to the daily schedule page or dashboard |
| 7 | Navigate to the daily schedule section if not automatically redirected | Access is granted and daily schedule is displayed with employee's shift information |
| 8 | Verify all schedule features are now accessible | Employee can view shifts, navigate between days, and access all schedule functionality |

**Postconditions:**
- User is authenticated and logged in
- Access to daily schedule is granted
- Security validation is confirmed working
- Session is established

---

### Test Case: Test system behavior when no shifts are scheduled
- **ID:** tc-003
- **Type:** edge-case
- **Priority:** Medium
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee is logged into the system
- Employee has access to daily schedule view
- There exists at least one date with no scheduled shifts for the employee
- System is configured to display appropriate messages for empty schedules

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the daily schedule view from the dashboard | Daily schedule view loads successfully |
| 2 | Use the date navigation to select a specific day known to have no scheduled shifts | Selected date is displayed in the schedule header |
| 3 | Observe the schedule display area for the selected day | System displays a clear message stating 'No scheduled shifts for this day' or similar appropriate message |
| 4 | Verify that no shift details (time, location, role) are shown | Schedule area is empty except for the informational message, no placeholder or incorrect data is displayed |
| 5 | Verify the page layout remains intact and professional | Page structure is maintained, navigation controls are still visible and functional |
| 6 | Navigate to the previous day using the navigation button | System loads the previous day's schedule correctly, showing shifts if available or appropriate message if not |
| 7 | Navigate to the next day using the navigation button | System loads the next day's schedule correctly, showing shifts if available or appropriate message if not |
| 8 | Return to the day with no shifts and verify message persists | 'No scheduled shifts for this day' message is consistently displayed |

**Postconditions:**
- Employee remains logged in
- System correctly handles empty schedule scenario
- Navigation functionality remains operational
- No errors are generated

---

## Story: As Employee, I want to view my weekly schedule to plan my workweek efficiently
**Story ID:** story-13

### Test Case: Validate weekly schedule display with accurate shift data
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Employee has valid login credentials
- Employee has multiple shifts scheduled across the current week
- Web portal is accessible and operational
- Database contains valid weekly schedule data
- System performance meets 3-second load time requirement

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the web portal and log in with valid employee credentials | Login successful and employee dashboard is displayed |
| 2 | Navigate to the schedule section from the main menu | Schedule section loads and displays available view options |
| 3 | Select the weekly schedule view option | Weekly schedule view loads within 3 seconds displaying the current week |
| 4 | Verify the week date range is displayed in the header (e.g., 'Week of Jan 1 - Jan 7, 2024') | Correct week date range is shown corresponding to the current week |
| 5 | Verify all seven days of the week are displayed (Monday through Sunday or Sunday through Saturday based on configuration) | All seven days are visible with proper date labels |
| 6 | Review each scheduled shift and verify shift start time is displayed correctly | All shift start times match the expected schedule data for each day |
| 7 | Review each scheduled shift and verify shift end time is displayed correctly | All shift end times match the expected schedule data for each day |
| 8 | Verify location information is displayed for each shift | Location details are shown and accurate for all scheduled shifts |
| 9 | Verify role information is displayed for each shift | Role assignments are shown and accurate for all scheduled shifts |
| 10 | Click the previous week navigation button | Schedule loads for the previous week within 3 seconds, displaying correct date range and any scheduled shifts |
| 11 | Click the next week navigation button twice | Schedule advances through weeks correctly, loading each week's data within 3 seconds without errors |
| 12 | Return to current week view | Current week schedule is displayed again with all original shift data intact |
| 13 | Test responsive design by resizing browser to tablet dimensions | Weekly schedule adapts to tablet layout maintaining readability and functionality |
| 14 | Test responsive design by resizing browser to mobile dimensions | Weekly schedule adapts to mobile layout, possibly showing days in scrollable or stacked format while maintaining all information |

**Postconditions:**
- Employee remains logged in
- Weekly schedule view is displayed
- All shift data is accurately presented
- Navigation functionality is confirmed working
- No system errors occurred

---

### Test Case: Verify weekend and holiday highlighting in weekly view
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 7 mins

**Preconditions:**
- Employee is logged into the system
- Weekly schedule view is accessible
- Current or navigable week contains weekend days (Saturday and Sunday)
- System has company holidays configured in the database
- Test week includes at least one company holiday (or navigate to a week with a holiday)

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the weekly schedule view | Weekly schedule for current week is displayed |
| 2 | Identify Saturday in the weekly schedule display | Saturday is visible in the week view |
| 3 | Verify Saturday has visual distinction (different background color, border, or styling) | Saturday is highlighted or styled differently from weekdays, clearly indicating it is a weekend day |
| 4 | Identify Sunday in the weekly schedule display | Sunday is visible in the week view |
| 5 | Verify Sunday has visual distinction (different background color, border, or styling) | Sunday is highlighted or styled differently from weekdays, clearly indicating it is a weekend day |
| 6 | Navigate to a week that contains a company holiday using the week navigation controls | Weekly schedule loads for the selected week containing a holiday |
| 7 | Identify the company holiday date in the weekly schedule | Holiday date is visible in the week view |
| 8 | Verify the holiday has distinct visual highlighting (different color, icon, or label) | Holiday is clearly marked with visual distinction such as special background color, holiday icon, or 'Holiday' label |
| 9 | Verify holiday name or description is displayed if applicable | Holiday name (e.g., 'New Year's Day', 'Independence Day') is shown on or near the date |
| 10 | Compare the visual styling of weekends versus holidays versus regular weekdays | Each type (weekend, holiday, weekday) has distinct and easily distinguishable visual styling |
| 11 | Test highlighting visibility on mobile view by resizing browser or accessing from mobile device | Weekend and holiday highlighting remains visible and clear in mobile responsive layout |

**Postconditions:**
- Weekends are visually distinguished in weekly view
- Holidays are visually distinguished in weekly view
- Visual distinctions are clear and consistent
- Employee remains logged in

---

### Test Case: Test access restriction for unauthenticated users
- **ID:** tc-006
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is not logged into the system
- Web portal is accessible
- Direct URL to weekly schedule page is known
- Valid employee credentials are available for verification

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open a new browser window or incognito/private browsing session to ensure no active session exists | New browser session opens with no authentication cookies or active sessions |
| 2 | Attempt to directly access the weekly schedule URL (e.g., /schedules/weekly) by typing it in the address bar | Access is denied and system does not display the weekly schedule |
| 3 | Verify automatic redirect to the login page occurs | Browser is redirected to the login page URL |
| 4 | Verify an appropriate authentication error message or prompt is displayed | Message such as 'Please log in to access this page', 'Authentication required', or 'Session expired' is shown |
| 5 | Verify the login page displays username and password fields | Login form is properly displayed and functional |
| 6 | Enter valid employee credentials in the login form | Credentials are entered without errors |
| 7 | Submit the login form by clicking the Login button | Authentication is successful and user is logged into the system |
| 8 | Verify redirect to weekly schedule page or dashboard occurs after successful login | User is redirected to either the originally requested weekly schedule page or the main dashboard |
| 9 | Navigate to the weekly schedule view if not automatically redirected | Weekly schedule view is now accessible and displays employee's schedule data |
| 10 | Verify all weekly schedule features are functional (navigation, data display) | All features work correctly and employee can view and navigate weekly schedules |

**Postconditions:**
- Unauthenticated access is successfully blocked
- User is authenticated after login
- Access to weekly schedule is granted post-authentication
- Security controls are validated as working correctly

---

## Story: As Employee, I want to view my monthly schedule to plan long-term commitments
**Story ID:** story-17

### Test Case: Validate monthly schedule calendar display
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Employee account exists in the system with valid credentials
- Employee has assigned shifts in the current month and adjacent months
- System is accessible and operational
- Employee is not logged in initially
- Test data includes shifts across multiple months

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the employee portal login page | Login page is displayed with username and password fields |
| 2 | Enter valid employee credentials and click Login button | Employee is successfully authenticated and redirected to the dashboard |
| 3 | Navigate to the schedule section from the main menu | Schedule section is accessible and displays schedule view options |
| 4 | Select the monthly view option | Calendar displays in monthly grid format showing the current month with all days visible |
| 5 | Review the calendar to verify all scheduled shifts are displayed | All assigned shifts for the current month are accurately displayed on their respective dates with correct shift details (time, location, role) |
| 6 | Click the 'Previous Month' navigation button | Calendar transitions to the previous month and displays all scheduled shifts for that month accurately |
| 7 | Click the 'Next Month' navigation button twice | Calendar navigates forward through months correctly, displaying accurate shift data for each month without errors |
| 8 | Verify the page load time using browser developer tools or stopwatch | Monthly schedule loads within 4 seconds on the supported device |

**Postconditions:**
- Employee remains logged in
- Monthly schedule view is displayed
- No errors are logged in the system
- Calendar is positioned on the last navigated month

---

### Test Case: Verify highlighting of days with scheduled shifts
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee is logged into the system
- Employee has access to the schedule section
- Test employee has scheduled shifts on specific days in the current month
- Test employee has some days without scheduled shifts in the current month
- Monthly calendar view is available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule section and select monthly view | Monthly calendar is displayed in grid format for the current month |
| 2 | Identify days in the calendar that have scheduled shifts assigned to the employee | Days with scheduled shifts are visually distinct from days without shifts (e.g., different background color, border, or icon) |
| 3 | Compare highlighted days against the employee's actual shift schedule data | All days with scheduled shifts are highlighted and no days without shifts are incorrectly highlighted |
| 4 | Verify the visual distinction is clear and accessible (check contrast and visibility) | Highlighting is easily distinguishable and meets accessibility standards for color contrast |
| 5 | Navigate to a different month with scheduled shifts | Highlighting persists correctly in the new month, accurately reflecting scheduled shift days |

**Postconditions:**
- Employee remains logged in
- Calendar view remains functional
- Visual highlighting is consistent across all viewed months
- No visual rendering errors are present

---

## Story: As Employee, I want to receive confirmation that my schedule is loaded successfully to ensure data accuracy
**Story ID:** story-18

### Test Case: Validate loading indicator and success confirmation
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Employee account exists with valid credentials
- Employee has scheduled shifts in the system
- System is operational and API endpoints are accessible
- Employee is logged into the system
- Network connection is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule section from the main menu | Schedule section link is accessible and clickable |
| 2 | Click on the schedule view option to request schedule data | Loading indicator (spinner, progress bar, or loading message) is immediately displayed on the screen |
| 3 | Observe the loading indicator while schedule data is being fetched | Loading indicator remains visible and animated throughout the data fetch process |
| 4 | Wait for the schedule data to load completely | Schedule data loads successfully and is displayed on the screen |
| 5 | Verify that a success confirmation message or icon appears after data loads | Success confirmation message (e.g., 'Schedule loaded successfully') or success icon (e.g., green checkmark) is displayed prominently |
| 6 | Verify the loading indicator disappears after successful load | Loading indicator is no longer visible once success confirmation is shown |
| 7 | Check that the confirmation is visible on desktop, tablet, and mobile devices | Loading indicator and success confirmation are accessible and clearly visible on all supported device types |

**Postconditions:**
- Employee schedule is fully loaded and displayed
- Success confirmation has been shown to the user
- Loading indicator is no longer visible
- Employee remains logged in
- System is ready for further interactions

---

### Test Case: Validate error message on schedule load failure
- **ID:** tc-004
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Employee is logged into the system
- Test environment allows simulation of API failures or network errors
- Employee has permission to access schedule section
- System error handling mechanisms are implemented

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Configure test environment to simulate schedule data load failure (e.g., disconnect network, mock API failure, or use test flag) | Test environment is configured to force a schedule load failure |
| 2 | Navigate to the schedule section and request schedule view | Loading indicator is displayed as the system attempts to fetch schedule data |
| 3 | Wait for the simulated failure to occur | System detects the failure to load schedule data |
| 4 | Observe the error message displayed to the employee | Clear error message is displayed indicating schedule loading failed (e.g., 'Unable to load schedule. Please try again later.' or 'Schedule data could not be retrieved.') |
| 5 | Verify the error message is user-friendly and does not expose technical details | Error message is written in plain language without technical jargon or system error codes visible to the employee |
| 6 | Check that the loading indicator is replaced by the error message | Loading indicator disappears and error message is prominently displayed |
| 7 | Verify error message visibility on different devices (desktop, tablet, mobile) | Error message is clearly visible and accessible on all supported device types |
| 8 | Restore normal system configuration | Test environment is returned to normal operational state |

**Postconditions:**
- Error message has been displayed to the employee
- Loading indicator is no longer visible
- Employee remains logged in
- System is ready for retry or other actions
- Test environment is restored to normal configuration

---

## Story: As Employee, I want to navigate between different schedule views to access the information I need quickly
**Story ID:** story-19

### Test Case: Validate navigation between schedule views
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- Employee account exists in the system
- Employee is logged into the application
- Employee has access to the schedule section
- Schedule data exists for the current week and month
- Browser is supported and up to date

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule section from the main dashboard | Schedule section loads and displays the default daily view for the current date |
| 2 | Note the current date displayed in the daily view | Current date is clearly visible and matches today's date |
| 3 | Click on the 'Weekly View' navigation tab or button | Weekly schedule view loads displaying the week containing the previously viewed date, with the same date context maintained |
| 4 | Verify that the week displayed contains the date from the daily view | The week range includes the original date, confirming date context is retained |
| 5 | Click on the 'Monthly View' navigation tab or button | Monthly schedule view loads displaying the month containing the previously viewed date, with the same date context maintained |
| 6 | Verify that the month displayed contains the date from the previous views | The month shown includes the original date, confirming date context is retained across all view transitions |
| 7 | Click on the 'Daily View' navigation tab or button | Daily schedule view loads, returning to the original date context |

**Postconditions:**
- Employee remains logged in
- Schedule view is set to daily view
- Date context is preserved throughout navigation
- No errors or warnings are displayed

---

### Test Case: Test navigation performance
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee account exists in the system
- Employee is logged into the application
- Employee has access to the schedule section
- Schedule data exists for multiple days, weeks, and months
- Browser is supported and up to date
- Network connection is stable
- Performance monitoring tool or timer is available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule section and ensure daily view is displayed | Daily schedule view is loaded and visible |
| 2 | Start timer and click on the 'Weekly View' navigation control | Weekly view loads and displays within 1 second, timer confirms load time is under 1 second |
| 3 | Start timer and click on the 'Monthly View' navigation control | Monthly view loads and displays within 1 second, timer confirms load time is under 1 second |
| 4 | Start timer and click on the 'Daily View' navigation control | Daily view loads and displays within 1 second, timer confirms load time is under 1 second |
| 5 | Repeat steps 2-4 for a total of 5 complete navigation cycles | Each navigation action consistently completes within 1 second across all cycles |
| 6 | Record and verify all navigation times | All recorded navigation times are under 1 second, meeting the performance requirement |

**Postconditions:**
- Employee remains logged in
- All navigation actions completed successfully
- Performance metrics confirm sub-1-second navigation times
- No performance degradation observed over multiple cycles
- No errors or warnings are displayed

---

## Story: As Employee, I want to access my schedule securely to protect my personal and work information
**Story ID:** story-20

### Test Case: Validate authentication requirement for schedule access
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- Employee account exists in the system with valid credentials
- Application is deployed and accessible
- User is not currently logged in
- Browser cache and cookies are cleared
- Direct schedule URL is known

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open a new browser window or incognito/private browsing session | New browser session opens with no active authentication |
| 2 | Enter the direct URL to the schedule page in the address bar (e.g., https://app.example.com/schedule) | Browser attempts to navigate to the schedule URL |
| 3 | Press Enter to navigate to the schedule URL | System detects unauthenticated access attempt and redirects to the login page instead of displaying the schedule |
| 4 | Verify that the login page is displayed and the schedule is not accessible | Login page is shown with username and password fields, schedule content is not visible |
| 5 | Enter valid employee username in the username field | Username is accepted and displayed in the field |
| 6 | Enter valid employee password in the password field | Password is masked and accepted in the field |
| 7 | Click the 'Login' or 'Sign In' button | System authenticates the credentials successfully |
| 8 | Verify redirection after successful login | User is redirected to their personal schedule page, displaying only their own schedule data |
| 9 | Verify that the schedule content is now visible and accessible | Employee's schedule is fully displayed with all expected schedule information visible |

**Postconditions:**
- Employee is successfully authenticated and logged in
- Employee has access to their own schedule only
- Session is established and active
- No unauthorized access occurred

---

### Test Case: Test session timeout after inactivity
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 20 mins

**Preconditions:**
- Employee account exists in the system with valid credentials
- Application is deployed and accessible
- Session timeout is configured to 15 minutes of inactivity
- User is not currently logged in
- Timer or clock is available to track 15 minutes

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the application login page | Login page is displayed with authentication fields |
| 2 | Enter valid employee credentials and click login | Authentication succeeds and user is logged into the application |
| 3 | Navigate to the schedule section | Employee's schedule is displayed and accessible |
| 4 | Note the current time and remain completely inactive (no mouse movements, clicks, or keyboard input) | Session remains active, schedule remains visible |
| 5 | Wait for exactly 15 minutes without any user interaction | 15 minutes of inactivity elapses with no user actions performed |
| 6 | After 15 minutes, attempt to interact with the schedule (e.g., click on a schedule item or navigation element) | Session has expired, user is automatically logged out and redirected to the login page |
| 7 | Verify that the login page is displayed and a session timeout message is shown | Login page is visible with a message indicating the session expired due to inactivity |
| 8 | Verify that attempting to use the browser back button does not restore access to the schedule | Back button either returns to login page or shows an error, schedule remains inaccessible without re-authentication |

**Postconditions:**
- User session is terminated
- User is logged out of the application
- Schedule is no longer accessible without re-authentication
- Session timeout mechanism is confirmed to be working correctly

---

### Test Case: Verify HTTPS enforcement
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- Application is deployed with HTTPS configured
- SSL/TLS certificates are properly installed
- HTTP to HTTPS redirect is configured on the server
- Browser supports HTTPS
- User is not currently logged in

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open a new browser window | Browser window opens successfully |
| 2 | In the address bar, type the HTTP version of the schedule URL (e.g., http://app.example.com/schedule) ensuring 'http://' is explicitly used | HTTP URL is entered in the address bar |
| 3 | Press Enter to attempt navigation to the HTTP URL | Browser attempts to connect using HTTP protocol |
| 4 | Observe the URL in the address bar after the page loads | Connection is automatically redirected from HTTP to HTTPS, URL in address bar changes to 'https://app.example.com/schedule' or shows HTTPS with a padlock icon |
| 5 | Verify the presence of the security padlock icon in the browser address bar | Padlock icon is visible, indicating a secure HTTPS connection is established |
| 6 | Click on the padlock icon to view connection details | Connection information shows the connection is secure, certificate is valid, and HTTPS protocol is being used |
| 7 | Attempt to access other application pages using HTTP protocol | All HTTP requests are automatically redirected to HTTPS, maintaining secure connection throughout |

**Postconditions:**
- All connections to the application use HTTPS protocol
- HTTP to HTTPS redirect is functioning correctly
- Secure connection is maintained for all pages
- No insecure HTTP connections are allowed

---

## Story: As Employee, I want to view schedule details including location and role to understand my assignments fully
**Story ID:** story-21

### Test Case: Validate display of shift location and role
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee account exists and is active in the system
- Employee is logged into the application
- Employee has at least one shift assigned with location and role information
- Schedule data is populated in EmployeeSchedules table with extended fields

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule view page from the main dashboard | Schedule view page loads successfully and displays the current week/month schedule |
| 2 | Locate the first assigned shift in the schedule view | Shift is visible with date and time information displayed |
| 3 | Verify the location information is displayed for the shift | Location name/address is clearly visible on the shift card or entry (e.g., 'Main Office - Building A' or 'Downtown Branch') |
| 4 | Verify the role information is displayed for the shift | Role/position is clearly visible on the shift card or entry (e.g., 'Cashier', 'Manager', 'Sales Associate') |
| 5 | Navigate to additional shifts in the schedule view | Each shift consistently displays both location and role information in the same format |
| 6 | Verify the location and role match the assigned shift details in the system | All displayed location and role information corresponds accurately to the employee's assigned shifts |

**Postconditions:**
- Employee remains on the schedule view page
- No data has been modified
- Schedule information remains accurate and unchanged

---

### Test Case: Validate access to special notes or instructions
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Employee account exists and is active in the system
- Employee is logged into the application
- Employee has at least one shift assigned with special notes or instructions
- Schedule view page is accessible
- Test data includes shifts with special instructions populated

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule view page | Schedule view page loads successfully displaying all assigned shifts |
| 2 | Identify a shift that has special notes or instructions (indicated by an icon, badge, or visual indicator) | Shift with special notes is visually distinguishable from shifts without notes (e.g., info icon, asterisk, or highlighted border) |
| 3 | Hover the mouse cursor over the shift with special notes (for desktop/web interface) | Tooltip appears displaying the special instructions or notes clearly and legibly |
| 4 | If on mobile/tablet, tap or select the shift with special notes | Expandable section opens or modal appears showing the special instructions or notes |
| 5 | Read the displayed special instructions | Instructions are complete, readable, and formatted properly (e.g., 'Bring safety equipment', 'Training session at 9 AM', 'Dress code: Business formal') |
| 6 | Move cursor away from the shift or close the expandable section | Tooltip disappears or expandable section closes, returning to the normal schedule view |
| 7 | Test the same interaction on different device types (desktop, tablet, mobile) | Special notes are accessible and displayed clearly on all device types with appropriate UI elements for each platform |
| 8 | Verify that shifts without special notes do not display empty tooltips or expandable sections | Only shifts with actual notes show the indicator and provide access to the details |

**Postconditions:**
- Employee remains on the schedule view page
- No data has been modified
- Special instructions remain unchanged in the system
- UI returns to default state after interaction

---

