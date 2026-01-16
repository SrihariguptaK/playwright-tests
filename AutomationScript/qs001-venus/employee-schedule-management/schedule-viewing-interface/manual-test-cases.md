# Manual Test Cases

## Story: As Employee, I want to view my daily schedule to plan my workday effectively
**Story ID:** story-7

### Test Case: Validate daily schedule display for logged-in employee
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee has valid login credentials
- Employee has at least one shift scheduled for today and previous day
- Schedule portal is accessible and operational
- Employee is not already logged into the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule portal login page | Login page is displayed with username and password fields |
| 2 | Enter valid employee credentials and click 'Login' button | Employee is successfully authenticated and dashboard is displayed with navigation options |
| 3 | Click on 'Daily View' option from the navigation menu | System navigates to daily schedule view and displays today's date as the default selected date |
| 4 | Review the displayed schedule information for today | System displays today's schedule with correct shift details including shift start time, shift end time, location, and role assignment. Current day is highlighted |
| 5 | Click on the 'Previous Day' navigation button | System displays the schedule for the previous day without errors or delays (response time under 2 seconds). Date indicator updates to show previous day's date |
| 6 | Verify the previous day's schedule details | Schedule displays correct shift information for the previous day including start/end times, location, and role |

**Postconditions:**
- Employee remains logged into the system
- Daily schedule view remains active
- Previous day's schedule is displayed
- No errors are logged in the system

---

### Test Case: Verify access restriction to other employees' schedules
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- Employee is logged into the schedule portal
- Employee knows or can construct the URL pattern for accessing schedules
- Another employee's ID is known for testing purposes
- OAuth 2.0 authentication is properly configured
- Role-based access control is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to daily schedule view for own employee account | System displays the employee's own daily schedule successfully |
| 2 | Note the current URL structure in the browser address bar | URL contains the logged-in employee's ID parameter (e.g., /api/schedules/daily?employeeId={currentEmployeeId}&date={date}) |
| 3 | Manually modify the URL by changing the employeeId parameter to another employee's ID and press Enter | System denies access and displays an authorization error message (e.g., '403 Forbidden - You are not authorized to view this schedule') |
| 4 | Verify that no schedule data for the other employee is visible on the page | No schedule information is displayed, only the authorization error message is shown |
| 5 | Navigate back to the daily schedule view using the navigation menu | System displays the logged-in employee's own schedule without errors |
| 6 | Verify all schedule details are correctly displayed | Own schedule is displayed with accurate shift times, location, and role information |

**Postconditions:**
- Employee can only access their own schedule
- Security logs record the unauthorized access attempt
- Employee remains logged into the system
- No data breach has occurred

---

### Test Case: Test responsive layout on mobile devices
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Employee has valid login credentials
- Mobile device (smartphone or tablet) is available for testing
- Mobile device has internet connectivity
- Mobile browser is installed and updated
- Employee has shifts scheduled for today and tomorrow
- Screen resolution is typical for mobile devices (e.g., 375x667 or similar)

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open the mobile browser on the device and navigate to the schedule portal login page | Login page loads and displays correctly on mobile screen with properly sized input fields and buttons |
| 2 | Enter valid employee credentials and tap 'Login' button | Employee is authenticated and dashboard is displayed with mobile-optimized layout |
| 3 | Tap on 'Daily View' option from the navigation menu | Daily schedule view loads and displays today's schedule |
| 4 | Review the schedule layout on the mobile screen | Schedule layout adjusts correctly for mobile viewport with readable text size (minimum 14px), properly aligned shift details, and all information visible without horizontal scrolling. Touch targets are appropriately sized (minimum 44x44px) |
| 5 | Verify all schedule details are clearly visible | Shift start time, end time, location, and role are all displayed clearly and are easily readable on the mobile screen |
| 6 | Tap on the 'Next Day' navigation button | System navigates to the next day's schedule smoothly without layout issues or delays |
| 7 | Tap on the 'Previous Day' navigation button | System navigates back to the previous day's schedule. Navigation controls function correctly with proper touch responsiveness |
| 8 | Rotate the device to landscape orientation | Layout adjusts appropriately to landscape mode while maintaining readability and usability |

**Postconditions:**
- Mobile layout remains responsive and functional
- Employee remains logged in
- All navigation controls are accessible and functional
- No layout breaking or rendering issues occur

---

## Story: As Employee, I want to view my weekly schedule to plan my workweek efficiently
**Story ID:** story-8

### Test Case: Validate weekly schedule display for logged-in employee
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Employee has valid login credentials
- Employee has multiple shifts scheduled across the current week and next week
- Schedule portal is accessible and operational
- Current week has at least 2-3 shifts scheduled
- Employee is not already logged into the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule portal login page | Login page is displayed with username and password fields |
| 2 | Enter valid employee credentials and click 'Login' button | Employee is successfully authenticated and dashboard is displayed with available navigation options |
| 3 | Click on 'Weekly View' option from the navigation menu | System navigates to weekly schedule view and displays the current week as the default view with week start and end dates clearly indicated |
| 4 | Review all shifts displayed for the current week | System displays all scheduled shifts for the current week accurately. Each shift shows complete details including start time, end time, location, and role. Shifts are organized by day of the week (Monday through Sunday) |
| 5 | Verify the current week is highlighted or indicated | Current week is visually distinguished (highlighted, bordered, or marked) to indicate it is the active week being viewed |
| 6 | Count the total number of shifts displayed and verify against expected schedule | All shifts for the week are displayed with no missing entries. Count matches the expected number of scheduled shifts |
| 7 | Click on the 'Next Week' navigation button | System displays shifts for the next week without errors or delays (response time under 2 seconds). Week date range updates to show next week's start and end dates |
| 8 | Verify the next week's schedule details | All shifts for next week are displayed accurately with correct start/end times, locations, and roles. Layout remains consistent with current week view |

**Postconditions:**
- Employee remains logged into the system
- Weekly schedule view remains active
- Next week's schedule is displayed
- No errors are logged in the system
- Page load time was under 2 seconds

---

### Test Case: Verify access control for weekly schedules
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee is logged into the schedule portal
- Employee is currently viewing weekly schedule
- Another employee's ID is available for testing
- OAuth 2.0 authentication is active
- Role-based access control is properly configured

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to weekly schedule view for own employee account | System displays the employee's own weekly schedule successfully with all shifts visible |
| 2 | Note the current URL structure displayed in the browser address bar | URL contains the logged-in employee's ID and week start date parameters (e.g., /api/schedules/weekly?employeeId={currentEmployeeId}&weekStart={date}) |
| 3 | Manually modify the URL by changing the employeeId parameter to another employee's ID and press Enter | System immediately denies access and displays an authorization error message (e.g., '403 Forbidden - Access denied. You can only view your own schedule') |
| 4 | Verify that no schedule data for the other employee is visible | No weekly schedule information for the other employee is displayed. Only the authorization error message is shown on the page |
| 5 | Attempt to use browser back button to return to own schedule | Browser navigates back to the previous valid page |
| 6 | Click on 'Weekly View' from the navigation menu | System displays the logged-in employee's own weekly schedule without errors |
| 7 | Verify all weekly schedule details are correctly displayed | Own weekly schedule is displayed correctly with accurate shift information including times, locations, and roles for all days of the week |

**Postconditions:**
- Employee can only access their own weekly schedule
- Security logs contain record of the unauthorized access attempt
- Employee remains logged into the system
- No unauthorized data was exposed
- System security controls functioned as expected

---

### Test Case: Test weekly view responsiveness on mobile
- **ID:** tc-006
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Employee has valid login credentials
- Mobile device (smartphone or tablet) is available for testing
- Mobile device has stable internet connectivity
- Mobile browser is installed and up to date
- Employee has shifts scheduled across current week and next week
- Screen resolution is typical for mobile devices

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open the mobile browser and navigate to the schedule portal login page | Login page loads correctly on mobile device with properly sized and accessible input fields |
| 2 | Enter valid employee credentials and tap 'Login' button | Employee is authenticated successfully and dashboard is displayed with mobile-optimized layout |
| 3 | Tap on 'Weekly View' option from the navigation menu | Weekly schedule view loads and displays the current week's schedule |
| 4 | Review the weekly schedule layout on the mobile screen | Layout adjusts correctly for mobile viewport with readable text (minimum 14px font size), properly formatted weekly calendar or list view, and all shift information visible without requiring horizontal scrolling |
| 5 | Scroll vertically through the weekly schedule | Scrolling is smooth and all days of the week with their respective shifts are accessible. Headers remain visible or appropriately positioned |
| 6 | Verify all shift details are clearly visible for each day | For each scheduled shift, start time, end time, location, and role are displayed clearly and are easily readable on the mobile screen. Information is not truncated or overlapping |
| 7 | Tap on the 'Next Week' navigation button | System navigates to next week's schedule smoothly without layout issues, delays, or rendering problems. Week date range updates correctly |
| 8 | Tap on the 'Previous Week' navigation button | System navigates back to the previous week's schedule. Navigation controls function correctly with proper touch responsiveness and visual feedback |
| 9 | Rotate the device to landscape orientation | Layout adjusts appropriately to landscape mode. Weekly schedule remains readable and usable with proper spacing and formatting |
| 10 | Rotate the device back to portrait orientation | Layout adjusts back to portrait mode smoothly without any display issues or data loss |

**Postconditions:**
- Mobile layout remains responsive across orientations
- Employee remains logged in
- All navigation controls are functional on mobile
- Weekly schedule data is accurately displayed
- No layout breaking or rendering issues occurred

---

## Story: As Employee, I want to view my monthly schedule to plan long-term commitments
**Story ID:** story-12

### Test Case: Validate monthly schedule display
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Employee account exists in the system with valid credentials
- Employee has scheduled shifts for the current month and next month
- Employee is logged out initially
- Application is accessible and running
- Test data includes at least 3 shifts in current month with complete details

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the application login page | Login page is displayed with username and password fields |
| 2 | Enter valid employee credentials and click 'Login' button | Employee is successfully authenticated and redirected to the dashboard |
| 3 | Locate and click on 'Monthly View' option in the navigation menu | Current month's schedule is displayed in calendar grid format showing all days of the month with scheduled shifts highlighted |
| 4 | Verify that all scheduled shifts for the current month are visible on the calendar | All shifts are displayed on their respective dates with basic information (time, shift type) visible on the calendar grid |
| 5 | Click on a date that has a scheduled shift | Shift details are displayed in a popup or side panel showing complete information including shift time, duration, location, and any additional notes |
| 6 | Close the shift details popup/panel by clicking the close button or clicking outside the panel | Popup/panel closes and monthly calendar view remains displayed |
| 7 | Locate and click the 'Next Month' navigation button or arrow | Calendar transitions to display the next month's schedule without errors, showing the correct month name and year in the header |
| 8 | Verify that shifts scheduled for the next month are displayed correctly | All shifts for the next month are visible on their respective dates with accurate information |

**Postconditions:**
- Employee remains logged in
- Monthly view displays the next month's schedule
- No errors are logged in the system
- Session remains active

---

### Test Case: Verify access control for monthly schedules
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Two employee accounts exist in the system (Employee A and Employee B)
- Employee A is logged in to the application
- Employee B has scheduled shifts in the current month
- Access control and authorization mechanisms are configured
- Employee A knows Employee B's employee ID

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | While logged in as Employee A, navigate to the monthly schedule view | Employee A's monthly schedule is displayed correctly |
| 2 | Attempt to modify the URL or use API endpoint to access Employee B's monthly schedule by changing the employeeId parameter (e.g., /api/schedules/monthly?employeeId={EmployeeB_ID}&month={current_month}) | Access denied error message is displayed indicating 'You do not have permission to view this schedule' or similar authorization error |
| 3 | Verify that no schedule data for Employee B is visible or accessible | No shift information for Employee B is displayed, and the calendar remains empty or shows an error message |
| 4 | Check that Employee A is redirected back to their own schedule or an error page | System either redirects to Employee A's schedule or displays an appropriate error page with HTTP 403 Forbidden status |

**Postconditions:**
- Employee A remains logged in with access only to their own schedule
- Employee B's schedule data remains secure and inaccessible to Employee A
- Security event is logged in the system audit trail
- No unauthorized data exposure occurred

---

### Test Case: Test responsiveness of monthly view on mobile
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Employee account exists with valid credentials
- Employee has scheduled shifts for the current month
- Mobile device (smartphone or tablet) is available for testing
- Mobile device has internet connectivity
- Application is mobile-responsive and accessible via mobile browser
- Screen resolution is set to typical mobile dimensions (e.g., 375x667 for iPhone, 360x640 for Android)

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open the application URL in a mobile device browser (Chrome, Safari, or Firefox) | Application login page loads and displays correctly on mobile screen without horizontal scrolling |
| 2 | Enter valid employee credentials using the mobile keyboard and tap 'Login' button | Employee is successfully authenticated and redirected to the mobile-optimized dashboard |
| 3 | Tap on 'Monthly View' option in the navigation menu (may be in a hamburger menu) | Monthly calendar view loads and displays in a mobile-optimized layout with calendar grid adjusted for smaller screen |
| 4 | Verify that the calendar grid is readable with dates and shift information visible without zooming | Calendar displays with appropriately sized text and touch-friendly elements, all content is legible, and no text or elements are cut off |
| 5 | Tap on a date with a scheduled shift | Shift details appear in a mobile-optimized popup or panel that fits the screen, with all information readable and properly formatted |
| 6 | Scroll through the shift details if necessary | Content scrolls smoothly within the popup/panel without affecting the background calendar |
| 7 | Close the shift details by tapping the close button or tapping outside the panel | Popup/panel closes smoothly and calendar view remains displayed |
| 8 | Use swipe gesture or tap navigation arrows to move to the next month | Calendar transitions smoothly to next month with responsive layout maintained |
| 9 | Rotate the mobile device to landscape orientation | Calendar layout adjusts automatically to landscape mode, maintaining readability and usability |
| 10 | Rotate back to portrait orientation | Calendar layout adjusts back to portrait mode without errors or layout issues |

**Postconditions:**
- Employee remains logged in on mobile device
- Monthly view maintains responsive layout in both orientations
- All interactive elements remain functional and touch-friendly
- No layout breaks or rendering issues are present

---

## Story: As Employee, I want to navigate between different schedule views to choose the most useful format
**Story ID:** story-13

### Test Case: Validate switching between schedule views
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Employee account exists with valid credentials
- Employee has scheduled shifts for current day, current week, and current month
- Employee is logged in to the application
- All three view types (daily, weekly, monthly) are implemented and accessible
- A specific date (e.g., 15th of current month) is selected for context preservation testing

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | From the dashboard, navigate to the schedule section and select 'Daily View' option | Daily schedule is displayed showing shifts for the current day in a detailed list or timeline format with all shift information visible |
| 2 | Verify that the current date is highlighted and displayed in the view header | Current date is clearly indicated with proper formatting (e.g., 'Monday, January 15, 2024') and any shifts for today are listed |
| 3 | Navigate to a specific date (e.g., 15th of the month) using date picker or navigation controls in daily view | Daily view updates to show the selected date (15th) with corresponding shifts displayed |
| 4 | Click on 'Weekly View' button or tab in the view switcher controls | View transitions smoothly to weekly schedule without full page reload, displaying the week containing the 15th (previously selected date) with all days of that week visible in a grid or column format |
| 5 | Verify that the date context (15th) is preserved and highlighted in the weekly view | The 15th is highlighted or marked as the selected date within the weekly calendar, and the week containing this date is displayed |
| 6 | Verify that the transition occurred without full page reload by checking that the page header and navigation remain unchanged | Only the schedule content area updates; no browser refresh occurs, URL may update but page doesn't reload, transition time is under 1 second |
| 7 | Review the weekly schedule to ensure all shifts for the week are displayed correctly | All shifts for the entire week are visible with appropriate details, organized by day in a clear layout |
| 8 | Click on 'Monthly View' button or tab in the view switcher controls | View transitions smoothly to monthly schedule without full page reload, displaying the month containing the 15th (previously selected date) in a calendar grid format |
| 9 | Verify that the date context (15th) is preserved and highlighted in the monthly view | The 15th is highlighted or marked as the selected date within the monthly calendar, and all shifts for the month are displayed on their respective dates |
| 10 | Verify that the transition occurred without full page reload | Only the schedule content area updates; no browser refresh occurs, transition is smooth and completes in under 1 second |
| 11 | Switch back to daily view by clicking the 'Daily View' button | View transitions back to daily schedule showing the 15th (preserved date context) without page reload |

**Postconditions:**
- Employee remains logged in
- Selected date context (15th) is preserved across all view switches
- Daily view is currently displayed showing the 15th
- No errors are present in browser console
- All view transitions completed in under 1 second each

---

### Test Case: Verify access control consistency across views
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Two employee accounts exist (Employee A and Employee B)
- Employee A is logged in to the application
- Employee B has scheduled shifts in daily, weekly, and monthly views
- Access control is configured to restrict employees to their own schedules
- Employee A knows Employee B's employee ID

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | While logged in as Employee A, navigate to the daily schedule view | Employee A's daily schedule is displayed correctly with their own shifts |
| 2 | Attempt to access Employee B's daily schedule by modifying the URL or API endpoint to include Employee B's ID (e.g., /api/schedules/daily?employeeId={EmployeeB_ID}) | Access denied error is displayed with message such as 'Unauthorized access' or 'You do not have permission to view this schedule', and no schedule data for Employee B is shown |
| 3 | Navigate to the weekly schedule view using the view switcher | Employee A's weekly schedule is displayed correctly |
| 4 | Attempt to access Employee B's weekly schedule by modifying the URL or API endpoint to include Employee B's ID (e.g., /api/schedules/weekly?employeeId={EmployeeB_ID}) | Access denied error is displayed consistently with the same error message format as in daily view, and no schedule data for Employee B is shown |
| 5 | Navigate to the monthly schedule view using the view switcher | Employee A's monthly schedule is displayed correctly |
| 6 | Attempt to access Employee B's monthly schedule by modifying the URL or API endpoint to include Employee B's ID (e.g., /api/schedules/monthly?employeeId={EmployeeB_ID}) | Access denied error is displayed consistently with the same error message format as in previous views, and no schedule data for Employee B is shown |
| 7 | Verify that in all three views, the error handling is consistent and appropriate | All three views display the same type of access denied error with consistent messaging, HTTP 403 status code, and no data leakage |
| 8 | Verify that Employee A is automatically redirected back to their own schedule or an error page in each view | System handles unauthorized access consistently across all views by either redirecting to Employee A's schedule or displaying a proper error page |

**Postconditions:**
- Employee A remains logged in with access only to their own schedules
- Employee B's schedule data remains secure across all views
- Security events are logged in the system audit trail for all three unauthorized access attempts
- Access control is confirmed to be consistent across daily, weekly, and monthly views
- No unauthorized data exposure occurred in any view

---

## Story: As Employee, I want to receive clear error messages when schedule data is unavailable to understand system status
**Story ID:** story-16

### Test Case: Validate error message on data unavailability
- **ID:** tc-001
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Employee is logged into the system with valid credentials
- Employee has permission to access schedule page
- Test environment is configured to simulate API failures
- Network connectivity is available between client and server

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule page URL | Schedule page begins loading |
| 2 | Simulate schedule data API failure by disabling the schedule API endpoint or configuring mock failure response | API returns error status code (500, 503, or similar) |
| 3 | Observe the schedule page display after API failure | User-friendly error message is displayed on the page instead of schedule data. Message should be clear, non-technical, and explain that schedule data is currently unavailable |
| 4 | Review the error message content for clarity and helpfulness | Error message uses plain language (e.g., 'We're sorry, schedule information is temporarily unavailable') and provides guidance on next steps |
| 5 | Verify error message includes contact information for assistance | Contact information is visible and clear, including support phone number, email address, or help desk link |
| 6 | Check that the contact information is clickable/actionable (if email or phone) | Email links open default mail client and phone numbers are formatted as clickable links on mobile devices |
| 7 | Verify error is logged in the system error logs | Error entry appears in application logs with timestamp, error type, and relevant details for support team |

**Postconditions:**
- Error message remains displayed until API is restored or page is refreshed
- Error is logged in monitoring system for support team review
- Employee has clear path to get assistance
- No application crash or unhandled exceptions occur

---

### Test Case: Verify no sensitive info in error messages
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Employee is logged into the system with valid credentials
- Test environment is configured to trigger API errors with backend details
- Access to backend logs to verify actual error details
- Security testing tools or configuration available to simulate detailed error responses

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Configure the schedule API to return an error response that includes sensitive system details (e.g., database connection strings, internal server paths, stack traces, API keys) | Backend API error contains sensitive technical information |
| 2 | Navigate to the schedule page as an employee user | Schedule page attempts to load and encounters the configured API error |
| 3 | Observe the error message displayed to the employee on the frontend | Error message shown to user is generic and safe, containing no technical details, database information, server paths, or stack traces |
| 4 | Inspect the browser console for any exposed sensitive information | Console logs do not contain sensitive system details visible to end users |
| 5 | Check the network response in browser developer tools | API response to client contains sanitized error message without exposing internal system architecture or credentials |
| 6 | Verify that detailed error information is logged server-side only | Backend logs contain full error details including stack trace and system information for debugging purposes |
| 7 | Confirm the user-facing error message provides appropriate level of information | Message is helpful but generic (e.g., 'An error occurred while retrieving your schedule. Please try again later or contact support.') without revealing system vulnerabilities |

**Postconditions:**
- No sensitive information is exposed to the employee user interface
- Detailed error information is securely logged for authorized support personnel only
- Application security posture is maintained
- User receives actionable guidance without technical details

---

