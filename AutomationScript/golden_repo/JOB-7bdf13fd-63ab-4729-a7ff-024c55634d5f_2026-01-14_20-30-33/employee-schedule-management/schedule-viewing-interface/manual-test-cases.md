# Manual Test Cases

## Story: As Employee, I want to view my daily schedule to plan my workday effectively
**Story ID:** story-1

### Test Case: Validate daily schedule display for authenticated employee
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Employee has valid login credentials in the system
- Employee has at least one shift assigned for the current day
- Web portal is accessible and operational
- Database contains accurate schedule data for the employee
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the web portal login page using a supported browser | Login page is displayed with username and password fields |
| 2 | Enter valid employee credentials (username and password) and click the Login button | Login is successful and employee dashboard is displayed with navigation menu visible |
| 3 | Click on the 'Schedule' or 'My Schedule' option in the navigation menu | Daily schedule view for the current day is displayed by default showing the date header |
| 4 | Review the displayed schedule and verify shift start time is shown | Shift start time is clearly displayed in the correct time format (e.g., 9:00 AM) |
| 5 | Verify shift end time is displayed for each shift | Shift end time is clearly displayed in the correct time format (e.g., 5:00 PM) |
| 6 | Verify the location/workplace is displayed for each shift | Location information is displayed accurately (e.g., 'Building A - Floor 3' or 'Downtown Office') |
| 7 | Verify the role/position is displayed for each shift | Role information is displayed accurately (e.g., 'Customer Service Representative' or 'Sales Associate') |
| 8 | Cross-reference displayed schedule data with database records using employee ID and current date | All displayed shift times, locations, and roles match exactly with the EmployeeSchedules table records |
| 9 | Verify the page load time from clicking Schedule menu to full display | Page loads completely within 2 seconds as per performance requirements |

**Postconditions:**
- Employee remains logged into the system
- Daily schedule remains displayed on screen
- No errors are logged in the system
- Session remains active for further navigation

---

### Test Case: Verify navigation to previous and next days
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Employee is logged into the web portal
- Employee is on the daily schedule view page
- Current day schedule is displayed
- Employee has schedules for previous and next days in the database
- Navigation buttons (Previous Day/Next Day) are visible on the interface

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Note the current date displayed in the schedule header | Current date is clearly visible (e.g., 'Monday, January 15, 2024') |
| 2 | Click on the 'Previous Day' or left arrow navigation button | Page transitions smoothly and schedule for the previous day is displayed |
| 3 | Verify the date header has changed to the previous day | Date header shows the previous day's date (e.g., 'Sunday, January 14, 2024') |
| 4 | Verify shift details displayed for the previous day | All shift times, locations, and roles for the previous day are displayed accurately |
| 5 | Cross-check displayed data with database records for the previous day | Schedule data matches database records for the previous day without any discrepancies |
| 6 | Measure the response time for the previous day navigation | Navigation and data load completes within 2 seconds without delays |
| 7 | Click on the 'Next Day' or right arrow navigation button | Page transitions smoothly and schedule for the next day (original current day) is displayed |
| 8 | Verify the date header has changed to the next day | Date header shows the next day's date, returning to the original current day |
| 9 | Click 'Next Day' button again to move forward one more day | Schedule for the day after current day is displayed with updated date header |
| 10 | Verify shift details for the next day are accurate | All shift information is displayed correctly and matches database records |
| 11 | Check UI responsiveness by rapidly clicking Previous and Next buttons alternately | UI updates smoothly without freezing, lag, or display errors; each click registers correctly |
| 12 | Verify no JavaScript errors appear in browser console during navigation | Browser console shows no errors; all API calls return successful responses |

**Postconditions:**
- Employee remains on the daily schedule view
- Navigation buttons remain functional
- No data corruption or display errors occur
- System maintains session state
- Browser history reflects navigation actions

---

### Test Case: Ensure unauthorized users cannot access schedules
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Web portal is accessible
- Test employee account with valid credentials exists
- Another employee account exists in the system for cross-access testing
- OAuth2 authentication and RBAC are properly configured
- Direct URL to schedule page is known for testing

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open a new browser window in incognito/private mode | New browser window opens with no cached credentials or session data |
| 2 | Directly enter the schedule URL in the address bar (e.g., https://portal.company.com/schedules/daily) without logging in | Access is denied and user is automatically redirected to the login page |
| 3 | Verify an appropriate message is displayed indicating authentication is required | Message such as 'Please log in to access this page' or 'Authentication required' is displayed |
| 4 | Check the browser URL after redirect | URL shows the login page path (e.g., https://portal.company.com/login) |
| 5 | Enter valid employee credentials (username and password) and click Login | Login is successful and user is redirected to the dashboard or schedule page |
| 6 | Navigate to the daily schedule view | Employee's own daily schedule is displayed with correct shift information |
| 7 | Verify that only the logged-in employee's schedule is visible | Schedule displays only shifts assigned to the logged-in employee; no other employee data is visible |
| 8 | Note the employee ID from the current session (visible in profile or URL parameter) | Current employee ID is identified (e.g., employeeId=12345) |
| 9 | Manually modify the URL to attempt accessing another employee's schedule by changing the employeeId parameter (e.g., change employeeId=12345 to employeeId=67890) | Access is denied immediately |
| 10 | Verify an appropriate error message is displayed | Error message such as 'Access Denied: You do not have permission to view this schedule' or 'Unauthorized access attempt' is displayed |
| 11 | Verify the HTTP response code for the unauthorized access attempt | HTTP 403 (Forbidden) or 401 (Unauthorized) status code is returned |
| 12 | Check that the user remains on their own schedule or is redirected to an error page | User is either kept on their own schedule page or shown a proper error page; no other employee's data is exposed |
| 13 | Verify the security event is logged in the system audit log | Unauthorized access attempt is recorded in audit logs with timestamp, employee ID, and attempted action |

**Postconditions:**
- Unauthorized access attempts are blocked successfully
- Security logs contain records of access attempts
- Employee's own schedule access remains functional
- No data breach or unauthorized data exposure occurs
- System security integrity is maintained

---

## Story: As Employee, I want to view my weekly schedule to plan my workweek efficiently
**Story ID:** story-2

### Test Case: Validate weekly schedule display for authenticated employee
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Employee has valid login credentials in the system
- Employee has multiple shifts assigned for the current week
- Web portal is accessible and operational
- Database contains accurate weekly schedule data
- Weekly view feature is enabled in the schedule section

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the web portal login page using a supported browser | Login page is displayed with username and password input fields |
| 2 | Enter valid employee credentials (username and password) and click the Login button | Login is successful and employee dashboard is displayed with navigation options visible |
| 3 | Click on the 'Schedule' or 'My Schedule' option in the navigation menu | Schedule page is displayed with view options (daily/weekly) available |
| 4 | Click on the 'Weekly View' button or tab to switch to weekly schedule display | Weekly schedule view is displayed showing a calendar layout for the current week |
| 5 | Verify the week date range is displayed in the header | Week range is clearly shown (e.g., 'Week of January 15-21, 2024' or 'Jan 15 - Jan 21') |
| 6 | Verify all seven days of the week are displayed in the calendar view | All days from Monday (or Sunday) through Sunday (or Saturday) are visible with date labels |
| 7 | Check that each day shows the day name and date | Each column or row displays day name and date (e.g., 'Monday, Jan 15', 'Tuesday, Jan 16') |
| 8 | Verify shifts are displayed for each scheduled day of the week | All assigned shifts appear on their respective days in the calendar |
| 9 | Click on or hover over a shift entry to view detailed information | Shift details popup or expanded view shows start time, end time, location, and role |
| 10 | Verify shift start and end times are displayed for each shift | Time information is clearly visible (e.g., '9:00 AM - 5:00 PM') |
| 11 | Verify location information is displayed for each shift | Location details are shown accurately (e.g., 'Main Office', 'Warehouse B') |
| 12 | Verify role/position information is displayed for each shift | Role information is shown correctly (e.g., 'Cashier', 'Team Lead') |
| 13 | Cross-reference all displayed shifts with database records using employee ID and current week start date | All shifts displayed match exactly with EmployeeSchedules table records for the current week |
| 14 | Verify days with no scheduled shifts are clearly indicated | Empty days show 'No shifts scheduled' or remain blank with clear visual indication |
| 15 | Measure the page load time from clicking Weekly View to full display of all shifts | Page loads completely within 3 seconds as per performance requirements |

**Postconditions:**
- Employee remains logged into the system
- Weekly schedule view remains active and functional
- All shift data is accurately displayed
- No errors are logged in the system
- Session remains active for further interactions

---

### Test Case: Verify navigation to previous and next weeks
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Employee is logged into the web portal
- Employee is on the weekly schedule view page
- Current week schedule is displayed
- Employee has schedules for previous and next weeks in the database
- Navigation buttons (Previous Week/Next Week) are visible and enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Note the current week date range displayed in the schedule header | Current week range is clearly visible (e.g., 'Week of January 15-21, 2024') |
| 2 | Count the number of shifts displayed for the current week | All shifts for the current week are visible and countable |
| 3 | Click on the 'Previous Week' or left arrow navigation button | Page transitions smoothly and weekly schedule for the previous week is displayed |
| 4 | Verify the week date range header has changed to the previous week | Date range shows the previous week (e.g., 'Week of January 8-14, 2024') |
| 5 | Verify all days of the previous week are displayed correctly | All seven days with correct dates for the previous week are shown |
| 6 | Verify shift details for the previous week are displayed accurately | All shifts for the previous week show correct times, locations, and roles |
| 7 | Cross-check displayed shifts with database records for the previous week | All displayed shift data matches database records for the previous week without discrepancies |
| 8 | Measure the response time for previous week navigation | Navigation and data load completes within 3 seconds without delays or errors |
| 9 | Verify UI responsiveness by checking for smooth transitions and no visual glitches | Calendar updates smoothly with no flickering, layout breaks, or loading errors |
| 10 | Click on the 'Next Week' or right arrow navigation button | Page transitions smoothly and schedule returns to the original current week |
| 11 | Verify the week date range has changed back to the current week | Date range shows the current week again (e.g., 'Week of January 15-21, 2024') |
| 12 | Click 'Next Week' button again to navigate to the following week | Schedule for the next week is displayed with updated date range |
| 13 | Verify the week date range header shows the next week | Date range displays the next week (e.g., 'Week of January 22-28, 2024') |
| 14 | Verify shift details for the next week are accurate | All shifts for the next week display correct information matching database records |
| 15 | Test rapid navigation by clicking Previous and Next buttons multiple times in succession | UI updates correctly for each click without freezing, data corruption, or display errors |
| 16 | Check browser console for any JavaScript errors during navigation | No errors appear in console; all API calls return successful responses (HTTP 200) |
| 17 | Verify data accuracy remains consistent after multiple navigation actions | Schedule data remains accurate and consistent with database records after all navigation |

**Postconditions:**
- Employee remains on the weekly schedule view
- Navigation buttons remain functional
- No data corruption or display errors occur
- System maintains session state correctly
- Browser history reflects navigation actions
- API calls are properly logged

---

### Test Case: Ensure unauthorized users cannot access weekly schedules
- **ID:** tc-006
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- Web portal is accessible and operational
- Test employee account with valid credentials exists
- Another employee account exists for cross-access testing
- OAuth2 authentication and RBAC are properly configured
- Direct URL to weekly schedule page is known
- Security logging is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open a new browser window in incognito/private mode to ensure no cached session | New browser window opens with no stored credentials or active sessions |
| 2 | Directly enter the weekly schedule URL in the address bar (e.g., https://portal.company.com/schedules/weekly) without logging in | Access is denied and user is automatically redirected to the login page |
| 3 | Verify an appropriate authentication error message is displayed | Message such as 'Please log in to access this page' or 'Authentication required' is shown |
| 4 | Check the browser URL after automatic redirect | URL shows the login page path with possible return URL parameter |
| 5 | Verify the HTTP response code for the unauthorized access attempt | HTTP 401 (Unauthorized) or 302 (Redirect) status code is returned |
| 6 | Enter valid employee credentials (username and password) and click Login button | Login is successful and user is authenticated into the system |
| 7 | Verify user is redirected to the dashboard or the originally requested weekly schedule page | User lands on appropriate page after successful authentication |
| 8 | Navigate to the weekly schedule view if not already there | Employee's own weekly schedule is displayed with all assigned shifts |
| 9 | Verify that only the logged-in employee's schedule is visible | Weekly schedule shows only shifts assigned to the logged-in employee; no other employee data is visible |
| 10 | Identify the current employee ID from the session (check URL parameters, profile, or browser developer tools) | Current employee ID is identified (e.g., employeeId=12345) |
| 11 | Manually modify the URL to attempt accessing another employee's weekly schedule by changing the employeeId parameter (e.g., change employeeId=12345 to employeeId=67890) | Access is immediately denied by the system |
| 12 | Verify an appropriate authorization error message is displayed | Error message such as 'Access Denied: You do not have permission to view this schedule' or 'Unauthorized access' is displayed |
| 13 | Check the HTTP response code for the unauthorized access attempt | HTTP 403 (Forbidden) status code is returned |
| 14 | Verify the user is redirected back to their own schedule or an error page | User remains on their own schedule or is shown a proper error page; no unauthorized data is exposed |
| 15 | Attempt to access another employee's schedule using API endpoint directly (e.g., using browser console or API testing tool) | API request is rejected with 403 Forbidden response |
| 16 | Verify the security event is logged in the system audit log | Unauthorized access attempt is recorded with timestamp, employee ID, attempted action, and target resource |
| 17 | Check that no sensitive data from other employees is leaked in error messages or responses | Error messages contain no sensitive information; only generic access denial messages are shown |

**Postconditions:**
- All unauthorized access attempts are successfully blocked
- Security audit logs contain complete records of access attempts
- Employee's own weekly schedule access remains functional
- No data breach or unauthorized data exposure occurs
- System security and RBAC integrity is maintained
- User session remains valid and secure

---

## Story: As Employee, I want to view my schedule on mobile devices to access it anytime, anywhere
**Story ID:** story-6

### Test Case: Validate schedule viewing on various mobile devices
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- Employee has valid login credentials
- Schedule data exists for the employee in the system
- Mobile devices (smartphone and tablet) are available for testing
- Mobile devices have internet connectivity (4G/Wi-Fi)
- Schedule portal URL is accessible from mobile browsers

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open mobile browser on smartphone and navigate to schedule portal URL | Login page loads and displays correctly with responsive layout fitting smartphone screen |
| 2 | Enter valid employee credentials and tap login button | User is authenticated successfully and redirected to schedule dashboard |
| 3 | View the schedule dashboard on smartphone in portrait orientation | Schedule view renders correctly with all elements visible and properly aligned for portrait mode |
| 4 | Rotate smartphone to landscape orientation | Schedule view automatically adjusts and renders correctly in landscape mode without layout issues |
| 5 | Use touch gestures to navigate to daily schedule view | Daily schedule loads smoothly, touch controls are responsive, and schedule details are clearly visible |
| 6 | Swipe or tap to navigate to weekly schedule view | Weekly schedule loads without delay, all days are visible, and touch navigation works smoothly |
| 7 | Tap on individual shift entries to view details | Shift details expand or display correctly with all information readable |
| 8 | Repeat steps 1-7 on tablet device | All functionality works correctly on tablet with appropriate layout adjustments for larger screen size |
| 9 | Verify schedule data accuracy by comparing displayed shifts with expected schedule | All shift times, dates, locations, and roles match the expected schedule data |
| 10 | Check UI elements including buttons, text size, and spacing | All UI elements are appropriately sized for touch interaction, text is readable, and spacing prevents accidental taps |

**Postconditions:**
- User remains logged in on mobile device
- No errors or layout issues are present
- Schedule data remains unchanged
- Mobile session is active

---

### Test Case: Ensure mobile page load performance
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Employee has valid login credentials
- Mobile device is available for testing
- Access to both 4G mobile network and Wi-Fi network
- Performance measurement tools are available (browser dev tools or stopwatch)
- Schedule data exists in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Connect mobile device to 4G network and clear browser cache | Device is connected to 4G network and browser cache is cleared |
| 2 | Start timer and navigate to schedule portal login page | Login page loads completely within 3 seconds |
| 3 | Login with valid credentials and measure time until schedule dashboard is fully loaded | Schedule dashboard loads completely within 3 seconds after login |
| 4 | Navigate to daily schedule view and measure load time | Daily schedule view loads completely within 3 seconds |
| 5 | Navigate to weekly schedule view and measure load time | Weekly schedule view loads completely within 3 seconds |
| 6 | Logout and clear browser cache | User is logged out successfully and cache is cleared |
| 7 | Connect mobile device to Wi-Fi network | Device is connected to Wi-Fi network with stable connection |
| 8 | Repeat steps 2-5 on Wi-Fi network and measure load times | All pages (login, dashboard, daily schedule, weekly schedule) load within 3 seconds on Wi-Fi |
| 9 | Document all load times for comparison | All measured load times are under 3 seconds threshold |

**Postconditions:**
- All page load times are documented
- Performance meets the 3-second requirement
- User is logged out
- Browser cache is cleared

---

### Test Case: Verify mobile session security
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Employee has valid login credentials
- Mobile device with browser is available
- Session timeout policy is configured in the system
- Internet connectivity is available
- Knowledge of configured session timeout duration

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open mobile browser and navigate to schedule portal | Login page loads successfully |
| 2 | Enter valid employee credentials and login | User is authenticated and schedule dashboard is displayed |
| 3 | Note the current time and leave the mobile device idle without any interaction | User remains on schedule page with active session |
| 4 | Wait for the configured session timeout period to elapse (remain idle) | Time passes without any user interaction with the application |
| 5 | After timeout period has passed, attempt to interact with the schedule (e.g., navigate to different view or refresh) | Session has expired and user is automatically redirected to login page with session timeout message |
| 6 | Verify that a clear message is displayed indicating session expiration | User sees a notification or message stating 'Your session has expired. Please log in again.' or similar |
| 7 | Attempt to use browser back button to access schedule without re-authenticating | Access is denied and user is redirected back to login page |
| 8 | Enter valid credentials and login again | User is re-authenticated successfully and can access schedule normally |
| 9 | Verify that session token has been renewed after re-authentication | New session is established with fresh authentication token |

**Postconditions:**
- User is logged in with new session after re-authentication
- Previous session is completely invalidated
- Session security policies are enforced correctly
- No unauthorized access to schedule data occurred

---

## Story: As Employee, I want to print my schedule from the web interface to have a physical copy
**Story ID:** story-7

### Test Case: Validate print functionality for daily schedule
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Employee has valid login credentials
- Schedule data exists for the employee
- Printer is connected and configured
- Web browser supports print functionality
- User has access to schedule viewing permissions

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open web browser and navigate to schedule portal URL | Login page loads successfully |
| 2 | Enter valid employee credentials and click login button | User is authenticated and redirected to schedule dashboard |
| 3 | Navigate to daily schedule view for current date | Daily schedule is displayed with all shifts, times, locations, and role information visible |
| 4 | Verify that all shift details are present including start time, end time, location, and assigned role | All shift details are complete and accurate on the screen |
| 5 | Locate and click the 'Print' button or option in the schedule interface | Print preview window opens displaying the formatted schedule |
| 6 | Review the print preview for proper formatting, including headers, shift details, and layout | Print preview shows clean, formatted schedule with all details clearly visible, no overlapping text, proper margins, and professional appearance |
| 7 | Verify that print preview includes employee name, date, and all shift information (time, location, role) | All relevant details are present in the print preview exactly as displayed on screen |
| 8 | Check that unnecessary UI elements (navigation menus, buttons, headers) are excluded from print preview | Print preview contains only schedule content without web interface elements |
| 9 | Click 'Print' button in the print preview dialog | Print dialog opens with printer selection and settings options |
| 10 | Select printer and confirm print job | Print job is sent to printer successfully |
| 11 | Retrieve printed document from printer and compare with print preview | Printed copy matches the print preview exactly, all text is readable, formatting is preserved, and all shift details are present |
| 12 | Verify printed schedule includes all details: date, employee name, shift times, locations, and roles | All required information is present and clearly legible on the printed copy |

**Postconditions:**
- User remains logged in
- Physical printed copy of schedule is available
- Print job completed successfully without errors
- Schedule data remains unchanged in the system

---

### Test Case: Verify access control for print feature
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Schedule portal is accessible via web browser
- Print functionality exists in the system
- User is not currently logged in
- Valid login credentials are available for verification

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open web browser and ensure no active session exists (clear cookies/cache if needed) | Browser has no active authentication session |
| 2 | Attempt to directly access the schedule print URL or endpoint without logging in (if URL is known) | Access is denied and user is redirected to login page with appropriate error message |
| 3 | Navigate to the schedule portal main URL without logging in | Login page is displayed |
| 4 | Attempt to access print functionality through browser developer tools or URL manipulation without authentication | Access is denied, authentication is required, and user cannot access print feature |
| 5 | Verify that error message or redirect clearly indicates authentication is required | User sees message such as 'Please log in to access this feature' or is redirected to login page |
| 6 | Login with valid employee credentials | User is authenticated successfully and can access schedule dashboard |
| 7 | Navigate to daily schedule and verify print option is now visible and accessible | Print button/option is available and functional for authenticated user |
| 8 | Logout from the application | User is logged out and session is terminated |
| 9 | Attempt to use browser back button to access print functionality after logout | Access is denied and user is redirected to login page, confirming session invalidation |

**Postconditions:**
- Unauthorized access to print functionality is prevented
- Authentication is enforced for print feature
- User is logged out with no active session
- Security controls are validated

---

## Story: As Employee, I want to view past schedules to review my work history
**Story ID:** story-8

### Test Case: Validate retrieval of past schedules by date range
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Employee account exists in the system with valid credentials
- Historical schedule data exists for the employee for at least the past month
- Employee has network connectivity and access to the web application
- Browser is supported and up to date

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the application login page and enter valid employee credentials (username and password), then click Login button | Employee is successfully authenticated and redirected to the dashboard or home page |
| 2 | Navigate to the schedule section by clicking on the Schedule menu item or navigation link | Schedule interface is displayed showing the current week's schedule with navigation controls visible |
| 3 | Locate and click on the date range selector or past schedule navigation control | Date range picker or calendar interface is displayed allowing selection of past dates |
| 4 | Select a past date range (e.g., start date: first day of last month, end date: last day of last month) and click Apply or Submit | System processes the request and displays schedules for the selected date range within 3 seconds, showing all shifts for that period |
| 5 | Review the displayed shift details including dates, times, locations, and any notes or assignments | All shift details are clearly visible and formatted correctly with proper date/time information |
| 6 | Cross-reference displayed schedule data with known historical records or previous documentation | Displayed data matches historical records exactly with 100% accuracy in dates, times, and shift assignments |
| 7 | Click Logout button to end the session | Employee is successfully logged out and redirected to the login page |

**Postconditions:**
- Employee session is terminated
- No data is modified in the system
- Historical schedule data remains unchanged
- User is returned to login page

---

### Test Case: Ensure performance under large data loads
- **ID:** tc-002
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Employee account exists with extensive historical schedule data (minimum 6-12 months)
- Employee is logged into the system
- Network connection is stable
- Performance monitoring tools are available to measure response time

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule section from the main dashboard | Schedule interface loads and displays current schedule view |
| 2 | Open the date range selector and select a large date range (e.g., 6 months or 12 months of historical data) | Date range selector accepts the large range selection without errors |
| 3 | Start timer and click Apply or Submit to request the large dataset | System begins processing the request and shows loading indicator |
| 4 | Monitor the loading process and measure the time until data is fully displayed | All schedule data for the requested range loads and displays completely within 3 seconds |
| 5 | Verify that all data is rendered correctly without missing records or truncated information | Complete dataset is displayed with proper pagination or scrolling functionality, no errors or missing data |
| 6 | Test navigation through the large dataset using pagination controls or scroll functionality | Navigation is smooth and responsive without lag or performance degradation |
| 7 | Check browser console and network tab for any errors or performance warnings | No errors, warnings, or performance issues are logged |

**Postconditions:**
- System performance remains stable
- No memory leaks or browser crashes occur
- Large dataset is successfully retrieved and displayed
- Application remains responsive for subsequent actions

---

### Test Case: Verify access control for historical schedules
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Employee account exists in the system but user is not currently logged in
- Application is accessible via browser
- Past schedule data exists in the system
- Authentication and authorization mechanisms are active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open a new browser window or incognito/private browsing session | Clean browser session is started with no existing authentication cookies |
| 2 | Attempt to directly access the past schedules URL by entering the schedule endpoint URL (e.g., /schedules?dateRange=past) in the address bar | System detects unauthenticated access attempt |
| 3 | Observe the system response to the unauthorized access attempt | Access is denied and user is automatically redirected to the login page with an appropriate message (e.g., 'Please log in to access this page' or 'Authentication required') |
| 4 | Verify that no schedule data is visible or accessible in the browser | No sensitive schedule information is displayed or accessible through browser developer tools, network tab, or page source |
| 5 | Check the URL after redirection | User is on the login page with original requested URL potentially stored for post-login redirect |
| 6 | Attempt to access the API endpoint directly (GET /api/schedules?employeeId={id}&dateRange={start,end}) without authentication token | API returns 401 Unauthorized or 403 Forbidden status code with no data payload |

**Postconditions:**
- User remains unauthenticated
- No schedule data is exposed or accessible
- User is on the login page ready to authenticate
- Security logs record the unauthorized access attempt

---

## Story: As Employee, I want to receive error messages when schedule data fails to load to understand issues
**Story ID:** story-9

### Test Case: Validate error message display on data load failure
- **ID:** tc-004
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Employee is logged into the system with valid credentials
- Ability to simulate backend failures or network errors exists (via test environment, proxy, or mock server)
- Error logging system is active and accessible for verification
- Employee has access to the schedule section

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Configure test environment to simulate backend failure (e.g., stop backend service, configure mock server to return 500 error, or use network throttling tool to simulate timeout) | Backend is configured to fail schedule data retrieval requests |
| 2 | Navigate to the schedule section by clicking on Schedule menu item | System attempts to load schedule data and encounters the simulated backend failure |
| 3 | Observe the UI response to the data loading failure | A clear, user-friendly error message is displayed (e.g., 'Unable to load schedule data. Please try again or contact support if the problem persists.') instead of a blank page or technical error |
| 4 | Verify that the error message is prominently displayed and easy to read | Error message is visible with appropriate styling (color, icon, positioning) and does not require scrolling to see |
| 5 | Locate and click the Retry button provided in the error message | System attempts to reload the schedule data, showing a loading indicator during the retry attempt |
| 6 | Verify the UI remains responsive during and after the error by attempting to navigate to other sections or interact with UI elements | UI remains fully responsive with no freezing, hanging, or unresponsive elements. User can navigate away or interact with other features |
| 7 | Access the backend error logs or monitoring system to verify error logging | Error is logged in the backend system with sufficient detail including timestamp, user ID, error type, API endpoint, error message, and stack trace for troubleshooting |
| 8 | Check browser console for any JavaScript errors or unhandled exceptions | No unhandled JavaScript errors or console exceptions are present; errors are properly caught and handled |

**Postconditions:**
- UI remains stable and responsive
- Error is properly logged in backend system
- User can retry or navigate to other sections
- No application crash or data corruption occurs

---

### Test Case: Ensure error messages guide user actions
- **ID:** tc-005
- **Type:** error-case
- **Priority:** Medium
- **Estimated Time:** 8 mins

**Preconditions:**
- Employee is logged into the system
- Test environment allows simulation of schedule load errors
- Support contact information is configured in the system
- Error handling mechanisms are implemented

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Configure the test environment to trigger a schedule load error (e.g., simulate database connection failure, API timeout, or server error) | System is configured to fail when attempting to load schedule data |
| 2 | Navigate to the schedule section to trigger the error condition | Schedule data fails to load and error handling is triggered |
| 3 | Read and analyze the displayed error message content | Error message is displayed with clear, non-technical language explaining what went wrong (e.g., 'We're having trouble loading your schedule right now') |
| 4 | Verify that the error message includes a Retry button or link | A clearly labeled 'Retry' or 'Try Again' button is visible and accessible within the error message |
| 5 | Verify that the error message includes support contact information | Error message displays support contact options such as 'Contact Support', email address, phone number, or help desk link |
| 6 | Click on the support contact link or button if provided | User is directed to appropriate support channel (email client opens, support form displays, or help page loads) |
| 7 | Click the Retry button to test retry functionality | System attempts to reload schedule data with loading indicator displayed |
| 8 | Verify that the error message provides actionable guidance without causing user confusion | Message clearly guides user on next steps: retry the action or contact support, with no ambiguous or technical jargon |

**Postconditions:**
- User understands what went wrong and what actions are available
- User can retry the operation or contact support
- Error is handled gracefully without system instability
- User experience is maintained despite the error condition

---

## Story: As Employee, I want to securely log in to the schedule system to protect my personal schedule data
**Story ID:** story-10

### Test Case: Validate successful login with valid credentials
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee has a valid registered account in the system
- Employee knows their correct username and password
- System is accessible and login page is available
- HTTPS is enabled on the application
- Browser is supported and up to date

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the login page URL | Login form is displayed with username field, password field, and login button visible |
| 2 | Enter valid username in the username field | Username is accepted and displayed in the field (masked or visible) |
| 3 | Enter valid password in the password field | Password is accepted and displayed as masked characters (dots or asterisks) |
| 4 | Click the login button | User is authenticated successfully and redirected to the dashboard page |
| 5 | Verify the dashboard displays user-specific information | Dashboard shows employee name, welcome message, and navigation menu |
| 6 | Navigate to the schedule section from the dashboard | Schedule page loads successfully |
| 7 | Verify schedule data is displayed | Employee's personal schedule data is visible with dates, shifts, and assignments |

**Postconditions:**
- User is logged in with an active session
- User has access to all authorized schedule features
- Session cookie is created and stored securely
- User activity is logged in the system audit trail

---

### Test Case: Verify login failure with invalid credentials
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Login page is accessible
- System is operational
- HTTPS is enabled on the application

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the login page URL | Login form is displayed with username and password fields |
| 2 | Enter an invalid username in the username field | Invalid username is accepted in the field |
| 3 | Enter any password in the password field | Password is accepted and displayed as masked characters |
| 4 | Click the login button | Error message is displayed stating 'Invalid username or password' and access is denied |
| 5 | Verify user remains on the login page | User is not redirected and stays on the login page |
| 6 | Clear the fields and enter a valid username | Valid username is entered successfully |
| 7 | Enter an invalid password in the password field | Invalid password is accepted and displayed as masked characters |
| 8 | Click the login button | Error message is displayed stating 'Invalid username or password' and access is denied |
| 9 | Attempt to access the schedule page directly via URL without authentication | Access is denied and user is redirected to the login page |

**Postconditions:**
- User is not authenticated
- No session is created
- Failed login attempt is logged in the system
- User remains on the login page
- No access to schedule data is granted

---

### Test Case: Ensure session timeout after inactivity
- **ID:** tc-003
- **Type:** edge-case
- **Priority:** High
- **Estimated Time:** 20 mins

**Preconditions:**
- Employee has a valid account
- Session timeout period is configured in the system (e.g., 15 minutes)
- Employee is not logged in initially
- System clock is accurate

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the login page and enter valid credentials | User is authenticated and redirected to the dashboard |
| 2 | Navigate to the schedule page | Schedule data is displayed successfully |
| 3 | Note the current time and remain idle without any interaction | User session remains active during the idle period |
| 4 | Wait for the configured inactivity timeout period to elapse (e.g., 15 minutes) | Time passes without any user interaction |
| 5 | After timeout period, attempt to interact with the page (e.g., click a button or refresh) | Session has expired and user is automatically redirected to the login page |
| 6 | Verify a session timeout message is displayed | Message states 'Your session has expired due to inactivity. Please log in again.' |
| 7 | Attempt to access the schedule page directly via URL | Access is denied and user is redirected to the login page with prompt to re-authenticate |
| 8 | Enter valid credentials and log in again | User is authenticated successfully and can access the schedule data |

**Postconditions:**
- Previous session is terminated and invalidated
- User must re-authenticate to access the system
- Session timeout event is logged in the system
- No unauthorized access to schedule data occurred

---

## Story: As Employee, I want to log out securely to protect my schedule information
**Story ID:** story-11

### Test Case: Validate successful logout and session termination
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Employee has a valid account
- Employee is not currently logged in
- System is accessible and operational
- Browser cookies are enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the login page | Login form is displayed |
| 2 | Enter valid username and password | Credentials are accepted |
| 3 | Click the login button | User is authenticated and redirected to the dashboard |
| 4 | Navigate to the schedule page from the dashboard | Schedule page loads and displays employee's schedule data |
| 5 | Verify the logout button is visible on the schedule page | Logout button is clearly visible and accessible in the navigation menu or header |
| 6 | Click the logout button | User is logged out immediately and redirected to the login page |
| 7 | Verify a logout confirmation message is displayed | Message states 'You have been successfully logged out' or similar confirmation |
| 8 | Check browser cookies and session storage | Session cookies and client-side session data are cleared |
| 9 | Click the browser back button | User is not able to access the previous schedule page and remains on login page or is redirected to login |
| 10 | Attempt to access the schedule page directly by entering the URL | Access is denied and user is redirected to the login page with message to authenticate |
| 11 | Verify no schedule data is cached or visible | No sensitive schedule information is displayed without re-authentication |

**Postconditions:**
- User session is completely terminated on the server
- All client-side session data and cookies are cleared
- User cannot access any protected pages without logging in again
- Logout action is logged in the system audit trail
- User is on the login page ready to authenticate again if needed

---

