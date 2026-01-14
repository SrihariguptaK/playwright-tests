# Manual Test Cases

## Story: As Employee, I want to filter my schedule by shift type to focus on relevant work periods
**Story ID:** story-3

### Test Case: Validate shift type filtering functionality
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee account exists in the system with valid credentials
- Employee has multiple shifts assigned with different shift types (Morning, Evening, Night)
- Application is accessible and running
- Test data includes at least 3 morning shifts, 2 evening shifts, and 2 night shifts for the employee

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the application login page and enter valid employee credentials (username and password), then click Login button | Employee is successfully authenticated and redirected to the dashboard/home page |
| 2 | Click on the Schedule section/menu item from the navigation menu | Schedule page loads and displays all shifts for the employee across all shift types (Morning, Evening, Night) with complete shift details including date, time, and shift type |
| 3 | Locate the shift type filter dropdown/selector and click to expand the filter options | Filter dropdown opens showing all available shift type options (Morning, Evening, Night) |
| 4 | Select 'Morning' from the shift type filter options | Schedule view updates within 2 seconds to display only morning shifts. All evening and night shifts are hidden. The filter indicator shows 'Morning' is selected. Shift count reflects only morning shifts |
| 5 | Verify the filtered results by checking each displayed shift has shift type 'Morning' | All displayed shifts show 'Morning' as the shift type. No evening or night shifts are visible in the schedule view |
| 6 | Click the 'Clear Filter' button or deselect the 'Morning' filter option | Filter is removed and the full schedule is displayed again showing all shift types (Morning, Evening, Night). All previously hidden shifts are now visible |
| 7 | Verify the schedule displays all shifts across all shift types | Complete schedule is visible with all morning, evening, and night shifts displayed as before filtering was applied |

**Postconditions:**
- Employee remains logged in
- Schedule displays full unfiltered view
- No filters are active
- System is ready for next operation

---

### Test Case: Ensure filter state persistence during navigation
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Employee account exists with valid credentials
- Employee has shifts assigned with multiple shift types
- Application is accessible and running
- Employee is not currently logged in
- Multiple schedule views are available (e.g., weekly view, monthly view, list view)

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Login to the application with valid employee credentials | Employee successfully logs in and is redirected to the dashboard |
| 2 | Navigate to the Schedule section | Schedule page loads displaying all shifts without any filters applied |
| 3 | Apply a shift type filter by selecting 'Evening' from the filter dropdown | Schedule updates within 2 seconds to show only evening shifts. Filter indicator displays 'Evening' as active filter |
| 4 | Navigate to a different schedule view (e.g., from weekly view to monthly view) within the schedule section | Schedule view changes to the selected view type (monthly view) and the 'Evening' filter remains applied. Only evening shifts are displayed in the new view |
| 5 | Navigate back to the original schedule view (weekly view) | Schedule returns to weekly view with the 'Evening' filter still active. Only evening shifts are displayed. Filter state is maintained |
| 6 | Navigate to another section of the application (e.g., Profile or Dashboard) and then return to the Schedule section | Upon returning to Schedule section, the 'Evening' filter remains applied and only evening shifts are displayed |
| 7 | Click the Logout button to log out of the application | Employee is successfully logged out and redirected to the login page. Session is terminated |
| 8 | Login again with the same employee credentials | Employee successfully logs in and is redirected to the dashboard |
| 9 | Navigate to the Schedule section | Schedule page loads with no filters applied (default state). All shifts across all shift types are displayed. Previous session's filter settings are not persisted |

**Postconditions:**
- Employee is logged in
- Schedule displays default unfiltered view
- No filters are active after fresh login
- Previous session data is cleared

---

### Test Case: Verify unauthorized access is blocked
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- Application is accessible and running
- User is not logged in (no active session)
- Direct URL to schedule filtering page is known
- Authentication mechanism is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open a web browser and ensure no user is currently logged into the application (clear cookies/session if needed) | Browser opens with no active session. User is in logged-out state |
| 2 | Attempt to directly access the schedule filtering page by entering the schedule URL (e.g., /schedule or /employee/schedule) in the browser address bar | Access is denied. User is automatically redirected to the login page with a message indicating authentication is required |
| 3 | Verify the current page is the login page and the schedule content is not accessible | Login page is displayed. Schedule filtering functionality and schedule data are not visible or accessible. URL may show login page or redirect parameter |
| 4 | Attempt to access the schedule API endpoint directly (GET /api/schedules?employeeId={id}&shiftType={type}) without authentication token using a REST client or browser | API returns 401 Unauthorized or 403 Forbidden status code. No schedule data is returned. Error message indicates authentication is required |

**Postconditions:**
- User remains unauthenticated
- No schedule data is exposed
- User is on the login page
- System security is maintained

---

## Story: As Employee, I want to search my schedule by date to find specific shifts quickly
**Story ID:** story-4

### Test Case: Validate schedule search by valid date
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Employee account exists with valid credentials
- Employee has shifts scheduled on specific dates (e.g., shifts on 2024-01-15 and 2024-01-20)
- Application is accessible and running
- Date picker/search functionality is enabled
- Test data includes at least 2 shifts on the target search date

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the application login page and enter valid employee credentials, then click Login button | Employee is successfully authenticated and redirected to the dashboard |
| 2 | Navigate to the Schedule section from the main navigation menu | Schedule page loads displaying the default schedule view (full schedule or current week/month) |
| 3 | Locate the schedule search interface with date picker/input field | Search interface is visible and accessible. Date input field or date picker is displayed and enabled for interaction |
| 4 | Click on the date input field to activate the date picker | Date picker calendar opens showing current month with selectable dates |
| 5 | Enter or select a valid date that has scheduled shifts (e.g., '2024-01-15' or select January 15, 2024 from the calendar) | Selected date is populated in the date input field in the correct format (YYYY-MM-DD or configured format) |
| 6 | Click the Search button or press Enter to execute the search | Search executes and results load within 2 seconds. Schedule view updates to display only shifts scheduled for the selected date (2024-01-15). All shifts shown have the matching date. Shift details include time, shift type, and location |
| 7 | Verify the displayed shifts match the searched date by checking the date field on each shift | All displayed shifts show the searched date (2024-01-15). No shifts from other dates are visible. Shift count matches expected number of shifts for that date |
| 8 | Clear the search input by clicking the Clear button or deleting the date from the input field | Date input field is cleared and empty. Schedule view automatically restores to the default view showing the full schedule or current period. All shifts are visible again |
| 9 | Verify the schedule displays the default view with all shifts | Full schedule is displayed with shifts from multiple dates visible as before the search was performed |

**Postconditions:**
- Employee remains logged in
- Schedule displays default full view
- Search field is cleared
- System is ready for next search operation

---

### Test Case: Verify handling of invalid date input
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Employee account exists with valid credentials
- Employee is logged into the application
- Employee has navigated to the Schedule section
- Schedule search interface is accessible
- Test data includes dates with no scheduled shifts

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Locate the date search input field on the schedule page | Date search input field is visible and ready for input |
| 2 | Enter an invalid date format in the date input field (e.g., '2023-13-01' which has invalid month 13) | Date input field accepts the text entry |
| 3 | Click the Search button or press Enter to attempt the search | Search is blocked and not executed. An inline error message is displayed near the date input field stating 'Invalid date format. Please enter a valid date (YYYY-MM-DD)' or similar message. Schedule view remains unchanged |
| 4 | Clear the invalid date and enter another invalid format (e.g., '32/01/2024' with invalid day) | Date input field accepts the text entry |
| 5 | Attempt to search with the invalid date | Search is blocked. Inline error message is displayed indicating invalid date format. No API call is made. Schedule remains unchanged |
| 6 | Clear the error and enter a valid date format for a date that has no scheduled shifts (e.g., '2024-12-25' assuming no shifts on this date) | Date is accepted and populated in the input field. No validation error is shown |
| 7 | Click the Search button to execute the search | Search executes successfully within 2 seconds. A user-friendly message is displayed stating 'No shifts found for the selected date' or 'You have no shifts scheduled on 2024-12-25'. The message is clearly visible and non-technical |
| 8 | Verify the schedule view shows the no-results message and no shift data is displayed | Schedule area displays the no-results message. No shift cards or entries are shown. The interface remains functional and does not show any error states |
| 9 | Clear the search to return to the default schedule view | Search is cleared and full schedule is restored with all shifts visible |

**Postconditions:**
- Employee remains logged in
- Schedule displays default view after clearing search
- No error states persist
- System is ready for valid search operations

---

### Test Case: Ensure unauthorized users cannot perform schedule search
- **ID:** tc-006
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Application is accessible and running
- User is not logged in (no active session)
- Direct URL to schedule search page is known
- Authentication mechanism is enabled and enforced

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open a web browser and ensure no user is currently logged into the application (clear all cookies and session data) | Browser opens with clean state. No active user session exists |
| 2 | Attempt to directly access the schedule search page by entering the schedule URL (e.g., /schedule or /employee/schedule/search) in the browser address bar | Access is denied. User is automatically redirected to the login page. A message may be displayed indicating 'Please log in to access this page' or similar authentication required message |
| 3 | Verify the current page is the login page and schedule search functionality is not accessible | Login page is displayed with username and password fields. Schedule search interface is not visible. No schedule data is displayed. URL shows login page path |
| 4 | Attempt to access the schedule search API endpoint directly (GET /api/schedules?employeeId={id}&date={date}) without authentication token using a REST client, Postman, or browser developer tools | API request is rejected. Response returns 401 Unauthorized or 403 Forbidden HTTP status code. Response body contains error message such as 'Authentication required' or 'Unauthorized access'. No schedule data is returned in the response |
| 5 | Verify no sensitive data is exposed in the error response | Error response does not contain any schedule data, employee information, or system details. Only generic authentication error message is provided |

**Postconditions:**
- User remains unauthenticated
- No schedule data is exposed or accessible
- User is on the login page
- System security and data protection is maintained

---

