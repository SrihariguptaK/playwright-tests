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
| 2 | Enter valid employee credentials and click Login button | Login successful and employee dashboard is displayed within 3 seconds |
| 3 | Navigate to the schedule section from the dashboard menu | Schedule section is accessible and navigation is successful |
| 4 | Select daily view option | Daily schedule for current day is displayed showing shift start time, end time, location, and role information |
| 5 | Verify all shift details are accurate and complete | All scheduled shifts display correct times, locations, and role assignments matching employee records |
| 6 | Click on previous day navigation button | Schedule for previous day loads correctly within 3 seconds without errors |
| 7 | Click on next day navigation button twice | Schedule for next day loads correctly within 3 seconds without errors |
| 8 | Verify responsive layout on mobile device or resize browser window to mobile dimensions | Daily schedule displays correctly with responsive layout adapted for mobile view |

**Postconditions:**
- Employee remains logged in
- Daily schedule view is active
- No errors are logged in the system
- Session remains valid

---

### Test Case: Verify access restriction for unauthenticated users
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is not logged into the system
- Web portal is accessible
- OAuth2 authentication is properly configured
- Valid employee credentials are available for testing

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open browser and directly navigate to daily schedule URL without logging in | Access is denied and user is automatically redirected to login page |
| 2 | Verify error message or notification is displayed | Appropriate message is shown indicating authentication is required |
| 3 | Enter valid employee username and password on login page | Credentials are accepted and login process initiates |
| 4 | Click Login button to authenticate | Login successful and user is redirected to dashboard or daily schedule page |
| 5 | Verify access to daily schedule is now granted | Daily schedule page loads successfully with employee's shift information displayed |
| 6 | Verify OAuth2 token is present in session | Valid authentication token is stored and session is established |

**Postconditions:**
- User is successfully authenticated
- Access to daily schedule is granted
- Session is active with valid OAuth2 token
- Security logs record the authentication attempt

---

### Test Case: Test system behavior when no shifts are scheduled
- **ID:** tc-003
- **Type:** edge-case
- **Priority:** Medium
- **Estimated Time:** 4 mins

**Preconditions:**
- Employee is logged into the web portal
- Employee has access to schedule section
- At least one day exists in the schedule with no assigned shifts for the employee
- Database is accessible and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the daily schedule view from the dashboard | Daily schedule interface is displayed |
| 2 | Use date navigation to select a day with no scheduled shifts | Selected date is highlighted and system attempts to load schedule data |
| 3 | Verify the message displayed on the screen | System displays clear message 'No scheduled shifts for this day' or similar appropriate notification |
| 4 | Verify no error messages or system failures occur | Page loads successfully without errors, showing only the informational message |
| 5 | Navigate to a day with scheduled shifts | Schedule data loads correctly showing assigned shifts |
| 6 | Navigate back to the day with no shifts | System again displays 'No scheduled shifts for this day' message consistently |

**Postconditions:**
- System handles empty schedule gracefully
- No errors are generated
- User can continue navigating to other dates
- Session remains active

---

## Story: As Employee, I want to view my weekly schedule to plan my workweek efficiently
**Story ID:** story-13

### Test Case: Validate weekly schedule display with accurate shift data
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Employee has valid login credentials
- Employee has shifts scheduled for the current week
- Web portal is accessible and operational
- Database contains valid weekly schedule data
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the web portal and enter valid employee credentials | Login successful and employee dashboard is displayed |
| 2 | Navigate to the schedule section from the main menu | Schedule section opens successfully |
| 3 | Select weekly view option | Weekly schedule for current week is displayed showing all days from Monday to Sunday |
| 4 | Verify all scheduled shifts are displayed with accurate dates and times | Each shift shows correct date, start time, end time, location, and role information for the entire week |
| 5 | Verify the week start and end dates are correctly displayed | Week range is clearly shown with proper start and end dates |
| 6 | Click on previous week navigation button | Schedule for previous week loads correctly within 3 seconds showing all shifts for that week |
| 7 | Verify data accuracy for the previous week | All shift information is accurate and matches employee records for the previous week |
| 8 | Click on next week navigation button twice to move forward | Schedule for next week loads correctly within 3 seconds without errors |
| 9 | Test responsive design by resizing browser or viewing on mobile device | Weekly schedule adapts to screen size and remains readable and functional |

**Postconditions:**
- Employee remains logged in
- Weekly schedule view is active
- No errors are logged in the system
- Navigation history is maintained
- Session remains valid

---

### Test Case: Verify weekend and holiday highlighting in weekly view
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee is logged into the web portal
- Employee has access to weekly schedule view
- Current or selected week includes weekend days (Saturday and Sunday)
- At least one company holiday exists in the viewable schedule period
- Holiday data is configured in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to weekly schedule view from the dashboard | Weekly schedule interface is displayed showing all seven days of the week |
| 2 | Identify weekend days (Saturday and Sunday) in the weekly view | Weekend days are visually distinct with different background color, border, or highlighting compared to weekdays |
| 3 | Verify the visual distinction is clear and consistent | Weekend highlighting is easily noticeable and follows design standards |
| 4 | Navigate to a week that includes a company holiday | Weekly schedule loads showing the week with the holiday |
| 5 | Identify the holiday date in the weekly view | Holiday is visually distinct with special highlighting, icon, or label indicating it is a company holiday |
| 6 | Verify holiday name or description is displayed | Holiday name is shown clearly on the highlighted date |
| 7 | Check if shifts scheduled on holidays have any special indicators | Any shifts on holidays are displayed with appropriate visual cues |

**Postconditions:**
- Weekend and holiday highlighting is functioning correctly
- Visual distinctions are clear and consistent
- User can easily identify non-working days
- Session remains active

---

### Test Case: Test access restriction for unauthenticated users
- **ID:** tc-006
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is not logged into the system
- Web portal is accessible
- OAuth2 authentication is properly configured
- Weekly schedule URL is known
- Valid employee credentials are available for testing

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open browser in incognito/private mode to ensure no active session | Browser opens with no cached credentials or active sessions |
| 2 | Directly navigate to weekly schedule URL without logging in | Access is denied and user is automatically redirected to login page |
| 3 | Verify appropriate authentication error or message is displayed | Message indicates authentication is required to access the weekly schedule |
| 4 | Attempt to bypass login by manipulating URL parameters | All attempts are blocked and user remains on login page or receives access denied error |
| 5 | Enter valid employee credentials on the login page | Credentials are accepted and authentication process completes successfully |
| 6 | Verify user is redirected to weekly schedule or dashboard after successful login | User gains access to weekly schedule view with all shift data displayed |
| 7 | Verify OAuth2 token is properly established in the session | Valid authentication token is present and session is secure |

**Postconditions:**
- User is successfully authenticated
- Access to weekly schedule is granted only after authentication
- Security measures are functioning correctly
- Security logs record authentication attempts
- Session is active with valid OAuth2 token

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
- Employee is not already logged in
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the application login page | Login page is displayed with username and password fields |
| 2 | Enter valid employee credentials and click Login button | Employee is successfully authenticated and redirected to the dashboard |
| 3 | Navigate to the schedule section from the main menu | Schedule section is displayed with view options available |
| 4 | Select monthly view option | Calendar displays in monthly grid format showing the current month with all scheduled shifts accurately positioned on their respective dates |
| 5 | Verify that all assigned shifts are visible on the calendar with correct dates, times, and shift details | All shifts match the employee's schedule data with accurate information displayed |
| 6 | Click the previous month navigation button | Calendar transitions to the previous month and displays all scheduled shifts for that month correctly without errors |
| 7 | Click the next month navigation button twice | Calendar navigates forward through months, displaying accurate shift data for each month without errors or delays |
| 8 | Verify the page load time is within acceptable limits | Monthly schedule loads within 4 seconds on the current device |

**Postconditions:**
- Employee remains logged in
- Monthly calendar view is displayed
- No errors are present in the system logs
- Session remains active

---

### Test Case: Verify highlighting of days with scheduled shifts
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee is logged into the system
- Employee has at least one scheduled shift in the current month
- Employee has at least one day without scheduled shifts in the current month
- Monthly schedule view is accessible
- Browser supports CSS styling for visual highlighting

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the monthly schedule view | Monthly calendar is displayed in grid format for the current month |
| 2 | Identify days on the calendar that have scheduled shifts assigned | Days with scheduled shifts are visually distinct from days without shifts through highlighting, color coding, or other visual indicators |
| 3 | Compare highlighted days against the employee's known shift schedule | All days with scheduled shifts are highlighted and all days without shifts are not highlighted, confirming accurate visual representation |
| 4 | Verify the visual distinction is clear and easily identifiable | The highlighting method (color, border, background, or icon) is clearly visible and distinguishable from non-highlighted days |
| 5 | Navigate to a different month with known shift assignments | The new month displays with appropriate highlighting on days containing scheduled shifts |

**Postconditions:**
- Employee remains on the monthly schedule view
- Visual highlighting remains consistent across navigation
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
- Employee has schedule data available in the system
- System backend is operational and accessible
- Employee is logged into the application
- Network connection is active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule section from the main menu | Schedule section begins to load |
| 2 | Observe the screen immediately after requesting the schedule view | A loading indicator (spinner, progress bar, or loading message) is displayed prominently on the screen while schedule data is being fetched |
| 3 | Wait for the schedule data to complete loading | Loading indicator remains visible throughout the data fetch process |
| 4 | Observe the screen once schedule data has finished loading | Loading indicator disappears and a success confirmation message or icon (such as checkmark, success banner, or confirmation text) is displayed to indicate successful data load |
| 5 | Verify that the schedule data is displayed correctly on the screen | Schedule information is visible and accurate, confirming the successful load |
| 6 | Navigate to a different view and return to the schedule view | Loading indicator appears again during data fetch, followed by success confirmation upon completion |
| 7 | Test on a mobile device or responsive view | Loading indicator and success confirmation are visible and accessible on smaller screen sizes |

**Postconditions:**
- Schedule data is displayed correctly
- Success confirmation has been shown to the user
- No error messages are present
- Employee remains logged in and on the schedule view

---

### Test Case: Validate error message on schedule load failure
- **ID:** tc-004
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Employee is logged into the application
- Test environment allows simulation of backend failures
- Ability to disconnect network or simulate API failure
- Employee has valid credentials and session

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Simulate a schedule data load failure by disconnecting network connection or blocking the API endpoint GET /api/schedules/monthly | Backend API is unable to respond to schedule data requests |
| 2 | Navigate to the schedule section to request schedule view | Loading indicator is displayed as the system attempts to fetch schedule data |
| 3 | Wait for the system to detect the load failure | Loading indicator disappears after timeout or error detection |
| 4 | Observe the error message displayed on the screen | A clear, user-friendly error message is displayed indicating that the schedule could not be loaded, with possible reasons or instructions for the employee |
| 5 | Verify the error message is visible and readable on the current device | Error message is prominently displayed with appropriate styling and is accessible on all supported devices |
| 6 | Check if the error message provides actionable guidance (e.g., retry button, contact support) | Error message includes helpful information or options for the employee to resolve the issue |
| 7 | Restore network connection or API access and attempt to reload the schedule | System successfully loads schedule data and displays success confirmation |

**Postconditions:**
- Error message was displayed clearly during the failure scenario
- System recovers gracefully when connectivity is restored
- No application crashes or unhandled exceptions occurred
- Employee session remains active

---

## Story: As Employee, I want to navigate between different schedule views to access the information I need quickly
**Story ID:** story-19

### Test Case: Validate navigation between schedule views
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee account exists in the system
- Employee is logged into the application
- Employee has access to the schedule section
- Schedule data exists for the current week and month
- Browser is supported (Chrome, Firefox, Safari, Edge)
- Internet connection is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule section from the main dashboard | Schedule section loads and displays the default daily view with current date |
| 2 | Verify the current date is displayed in the daily view | Daily schedule shows the current date with all scheduled shifts and activities |
| 3 | Click on the 'Weekly View' navigation tab or button | Weekly schedule loads displaying the current week (Monday to Sunday) that contains the previously viewed date |
| 4 | Verify the date context is maintained in weekly view | The week containing the previously viewed date is displayed with all shifts for the 7-day period |
| 5 | Click on the 'Monthly View' navigation tab or button | Monthly schedule loads displaying the current month that contains the previously viewed week |
| 6 | Verify the date context is maintained in monthly view | The month containing the previously viewed date is displayed with all scheduled shifts visible in calendar format |
| 7 | Click on the 'Daily View' navigation tab or button | Daily schedule loads returning to the original date context |
| 8 | Verify all navigation controls are clearly visible and labeled | Navigation tabs/buttons are prominently displayed with clear labels (Daily, Weekly, Monthly) and visual indication of active view |

**Postconditions:**
- Employee remains logged in
- Schedule view is set to the last selected view (Daily)
- Date context is preserved throughout navigation
- No errors are displayed
- System state is unchanged

---

### Test Case: Test navigation performance
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Employee account exists in the system
- Employee is logged into the application
- Employee has access to the schedule section
- Schedule data exists for multiple days, weeks, and months
- Browser developer tools or performance monitoring tool is available
- Network connection is stable with normal speed
- System is not under heavy load

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule section and ensure daily view is displayed | Daily schedule view loads successfully |
| 2 | Open browser developer tools and navigate to Network or Performance tab to monitor load times | Developer tools are open and ready to capture performance metrics |
| 3 | Click on 'Weekly View' navigation control and measure the time taken to load | Weekly view loads completely within 1 second, all schedule data is visible and interactive |
| 4 | Click on 'Monthly View' navigation control and measure the time taken to load | Monthly view loads completely within 1 second, calendar displays all scheduled shifts |
| 5 | Click on 'Daily View' navigation control and measure the time taken to load | Daily view loads completely within 1 second, schedule details are fully rendered |
| 6 | Repeat the navigation sequence: Daily → Weekly → Monthly → Daily for a total of 5 complete cycles | Each view transition completes within 1 second across all cycles |
| 7 | Rapidly switch between views by clicking navigation controls in quick succession | System handles rapid navigation smoothly, each view loads within 1 second without errors or UI freezing |
| 8 | Review performance metrics in developer tools for all navigation actions | All recorded navigation times are under 1 second, no performance warnings or errors are logged |
| 9 | Switch to Weekly view, wait 2 seconds, then switch to Monthly view and measure load time | Monthly view loads within 1 second regardless of pause duration |
| 10 | Verify no loading spinners or delays exceed 1 second during any view transition | All visual feedback and content rendering complete within the 1-second performance requirement |

**Postconditions:**
- Employee remains logged in
- Schedule data integrity is maintained
- No performance degradation is observed
- No errors or warnings are logged in console
- System returns to stable state
- All navigation controls remain functional

---

## Story: As Employee, I want to access my schedule securely to protect my personal and work information
**Story ID:** story-20

### Test Case: Validate authentication requirement for schedule access
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Employee account exists in the system with valid credentials
- Application is deployed and accessible
- HTTPS is properly configured
- User is not currently logged in (cleared browser cache and cookies)
- Schedule data exists for the test employee account
- Direct schedule URL is known

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open a new browser window or incognito/private browsing session | New browser session opens with no active authentication cookies |
| 2 | Enter the direct URL to the schedule page (e.g., https://app.example.com/schedule) in the address bar | Browser navigates to the entered URL |
| 3 | Press Enter to attempt accessing the schedule page without authentication | System detects unauthenticated access and immediately redirects to the login page |
| 4 | Verify the login page is displayed with username and password fields | Login page loads with authentication form, no schedule data is visible or accessible |
| 5 | Verify the URL has changed to the login page URL | URL shows login page path (e.g., https://app.example.com/login) with possible redirect parameter |
| 6 | Enter valid employee username in the username field | Username is accepted and displayed in the field |
| 7 | Enter valid employee password in the password field | Password is masked and accepted in the field |
| 8 | Click the 'Login' or 'Sign In' button to submit credentials | System validates credentials and authenticates the employee |
| 9 | Verify successful authentication and redirection | Employee is redirected to their schedule page showing their personal schedule data |
| 10 | Verify only the authenticated employee's schedule is displayed | Schedule shows only shifts and information belonging to the logged-in employee, no other employee data is visible |
| 11 | Check the browser address bar for the schedule URL | URL shows the schedule page path with secure HTTPS protocol |
| 12 | Verify authentication session is established by checking for session indicators | User profile or name is displayed, logout option is available, session is active |

**Postconditions:**
- Employee is successfully authenticated and logged in
- Employee has access to their own schedule only
- Secure session is established
- Authentication cookies are set
- User can navigate within the application
- No unauthorized data is accessible

---

### Test Case: Test session timeout after inactivity
- **ID:** tc-004
- **Type:** edge-case
- **Priority:** High
- **Estimated Time:** 20 mins

**Preconditions:**
- Employee account exists with valid credentials
- Session timeout is configured to 15 minutes of inactivity
- Employee is not currently logged in
- System clock is accurate
- No automated scripts or background processes will interact with the application
- Timer or clock is available to track 15-minute period

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the application login page | Login page is displayed with authentication form |
| 2 | Enter valid employee credentials (username and password) | Credentials are accepted in the form fields |
| 3 | Click the 'Login' button to authenticate | Employee is successfully authenticated and redirected to their schedule page |
| 4 | Verify successful login by confirming schedule data is visible | Employee's schedule is displayed with all shifts and details visible |
| 5 | Note the current time and begin the inactivity period - do not interact with the application in any way (no mouse movements, clicks, or keyboard input) | Application remains displayed but receives no user input |
| 6 | Wait for exactly 15 minutes without any interaction with the browser or application | Time passes with no user activity detected by the system |
| 7 | After 15 minutes have elapsed, attempt to interact with the application by clicking on any schedule element or navigation control | System detects session timeout and either immediately logs out the user or displays a session expired message |
| 8 | Verify the user is logged out and redirected to the login page | Login page is displayed, schedule data is no longer accessible, session is terminated |
| 9 | Verify a session timeout message or notification is displayed | User sees a clear message indicating the session expired due to inactivity (e.g., 'Your session has expired. Please log in again.') |
| 10 | Attempt to use browser back button to return to schedule page | System prevents access and redirects back to login page, no cached schedule data is displayed |
| 11 | Verify authentication cookies have been cleared | Session cookies are removed from browser, no valid session exists |

**Postconditions:**
- Employee session is terminated
- Employee is logged out of the application
- Schedule data is no longer accessible
- Authentication cookies are cleared
- User must re-authenticate to access schedule
- No security vulnerabilities are exposed

---

### Test Case: Verify HTTPS enforcement
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Application is deployed with HTTPS configured
- SSL/TLS certificates are valid and properly installed
- HTTP to HTTPS redirect is configured on the server
- Employee account exists in the system
- Browser supports both HTTP and HTTPS protocols
- DNS is properly configured for the application domain

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open a new browser window or tab | New browser session is ready |
| 2 | In the address bar, type the application schedule URL using HTTP protocol explicitly (e.g., http://app.example.com/schedule) | HTTP URL is entered in the address bar |
| 3 | Press Enter to attempt accessing the schedule page over HTTP | Browser sends HTTP request to the server |
| 4 | Observe the browser address bar during and after the page load | Connection is automatically redirected from HTTP to HTTPS, address bar shows 'https://' protocol |
| 5 | Verify the secure connection indicator is displayed in the browser | Browser displays a padlock icon or 'Secure' indicator next to the URL, confirming HTTPS connection |
| 6 | Click on the padlock icon to view certificate information | SSL/TLS certificate details are displayed showing valid certificate issued to the correct domain |
| 7 | Verify the final URL in the address bar uses HTTPS protocol | URL displays as 'https://app.example.com/schedule' or similar with HTTPS protocol |
| 8 | Check that the redirect happened automatically without user intervention | Redirect was seamless and automatic, no manual action was required from the user |
| 9 | Open browser developer tools and navigate to the Network tab | Network tab shows the HTTP request received a 301 or 302 redirect response to HTTPS |
| 10 | Attempt to access other application pages using HTTP protocol (e.g., http://app.example.com/login) | All pages automatically redirect to HTTPS, no page is accessible over unsecured HTTP |
| 11 | Verify no mixed content warnings appear in the browser console | All resources (images, scripts, stylesheets) are loaded over HTTPS, no security warnings are displayed |

**Postconditions:**
- All connections to the application use HTTPS protocol
- SSL/TLS encryption is active for all data transmission
- No insecure HTTP connections are allowed
- Security indicators are properly displayed in browser
- Application is accessible only through secure protocol
- User data is protected during transmission

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
| 3 | Verify the location information is displayed for the shift | Location field shows the correct assigned location (e.g., 'Building A - Floor 2', 'Downtown Office', etc.) clearly and is easily readable |
| 4 | Verify the role information is displayed for the shift | Role field shows the correct assigned role (e.g., 'Cashier', 'Manager', 'Sales Associate', etc.) clearly and is easily readable |
| 5 | Navigate to additional shifts in the schedule view | Each shift consistently displays both location and role information in the same format |
| 6 | Verify the location and role data matches the employee's actual shift assignments from the system records | All displayed location and role information is accurate and corresponds to the employee's assigned shifts with 100% accuracy |

**Postconditions:**
- Employee remains on the schedule view page
- No data has been modified
- Schedule information remains accurate and accessible

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
- Special instructions field is populated for at least one shift

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule view page | Schedule view page loads successfully displaying all assigned shifts |
| 2 | Identify a shift that has special notes or instructions (indicated by an icon, highlight, or other visual indicator) | Shift with special notes is visually distinguishable from shifts without notes through an indicator (e.g., info icon, asterisk, or different styling) |
| 3 | Hover the mouse cursor over the shift with special notes | A tooltip appears displaying the special instructions or notes clearly and legibly within 1-2 seconds of hovering |
| 4 | If tooltip is not triggered by hover, click or tap on the shift to expand details | An expandable section opens showing the special instructions or notes in a readable format |
| 5 | Read the displayed special instructions | Special instructions are complete, clearly formatted, and contain all relevant information (e.g., 'Bring safety equipment', 'Training session at 9 AM', 'Report to Manager John') |
| 6 | Move cursor away from the shift or close the expanded section | Tooltip disappears or expandable section closes, returning to the normal schedule view |
| 7 | Test the same interaction on a mobile device or tablet (if applicable) | Special instructions are accessible through tap interaction and display correctly on smaller screens |
| 8 | Verify that shifts without special notes do not display empty tooltips or expandable sections | Shifts without special notes either show no indicator or display 'No special instructions' when accessed |

**Postconditions:**
- Employee remains on the schedule view page
- No data has been modified
- Special instructions remain accessible for future viewing
- UI returns to default state after interaction

---

