# Manual Test Cases

## Story: As Employee, I want to view my daily schedule to plan my workday effectively
**Story ID:** story-11

### Test Case: Validate daily schedule display for logged-in employee
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Employee account exists in the system with valid credentials
- Employee has at least one shift scheduled for the current day
- Web portal is accessible and operational
- Backend API GET /api/schedules/daily is functional
- Test data is available in EmployeeSchedules table

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the web portal login page and enter valid employee credentials (username and password) | Login is successful and employee dashboard is displayed with navigation menu visible |
| 2 | Click on the 'Schedule' section from the navigation menu | Schedule section opens and displays schedule view options |
| 3 | Select 'Daily View' option from the schedule view menu | Daily schedule for the current day is displayed with all scheduled shifts visible |
| 4 | Verify that the current day is highlighted in the schedule view | Current day is visually highlighted (e.g., different color or border) |
| 5 | Review each shift displayed and note the shift start time, end time, location, and role | Each shift shows complete details: start time, end time, location name, and assigned role |
| 6 | Compare displayed shift details with backend data from EmployeeSchedules table for the logged-in employee | All shift times, locations, and roles match exactly with backend database records |
| 7 | Verify that the page load time is recorded from navigation to full display | Daily schedule loads and displays completely within 2 seconds |
| 8 | Check if active shifts (currently in progress) are highlighted differently | Active shifts are visually distinguished from upcoming or past shifts |

**Postconditions:**
- Employee remains logged in to the system
- Daily schedule view remains accessible for further navigation
- No errors are logged in the system
- Session remains active

---

### Test Case: Verify navigation between days in daily schedule view
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Employee is logged into the web portal
- Daily schedule view is already displayed
- Employee has shifts scheduled on multiple days
- At least one day in the range has no scheduled shifts
- Navigation buttons (Next Day, Previous Day) are visible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Locate and click the 'Next Day' button on the daily schedule view | Schedule view refreshes and displays the schedule for the next calendar day |
| 2 | Verify the date displayed in the schedule header updates to the next day | Date header shows the correct next day's date |
| 3 | Review the shifts displayed for the next day | All shifts scheduled for the next day are displayed with accurate details |
| 4 | Locate and click the 'Previous Day' button on the daily schedule view | Schedule view refreshes and displays the schedule for the previous calendar day (returning to original day) |
| 5 | Verify the date displayed in the schedule header updates to the previous day | Date header shows the correct previous day's date |
| 6 | Review the shifts displayed for the previous day | All shifts scheduled for the previous day are displayed with accurate details |
| 7 | Navigate to a date that has no scheduled shifts by clicking 'Next Day' or 'Previous Day' multiple times | Schedule view displays the selected date with a clear message 'No shifts scheduled' or similar |
| 8 | Verify that the empty schedule view still shows the correct date and navigation buttons remain functional | Date header is correct, no shift data is shown, and navigation buttons are still clickable |
| 9 | Verify that each navigation action completes without errors or delays | All navigation transitions occur smoothly within 2 seconds per action |

**Postconditions:**
- Employee remains on the daily schedule view
- Navigation buttons remain functional
- No system errors are generated
- Employee can continue navigating to other dates

---

### Test Case: Ensure unauthorized access is blocked
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Two employee accounts exist in the system (Employee A and Employee B)
- Employee A is logged into the web portal
- Employee B has scheduled shifts with a known schedule URL
- Audit logging is enabled in the system
- OAuth2 authentication and RBAC are properly configured

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | While logged in as Employee A, obtain the direct URL for Employee B's daily schedule (e.g., /schedules/daily?employeeId=B) | URL is constructed with Employee B's identifier |
| 2 | Attempt to access Employee B's daily schedule by entering the URL directly in the browser address bar | System denies access and displays an error message such as 'Access Denied: You are not authorized to view this schedule' |
| 3 | Verify that Employee A is redirected back to their own schedule or an error page | Employee A is redirected to their own schedule view or a generic error page, not Employee B's schedule |
| 4 | Verify that no schedule data for Employee B is displayed or leaked in the response | No shift details, times, locations, or any data belonging to Employee B is visible |
| 5 | Access the system audit log through admin interface or database query | Audit log is accessible and contains recent entries |
| 6 | Search the audit log for the unauthorized access attempt by Employee A | Audit log contains an entry recording the unauthorized access attempt |
| 7 | Verify the audit log entry includes timestamp, Employee A's user ID, attempted resource (Employee B's schedule), and access denied status | Audit log entry shows: timestamp of attempt, Employee A's user ID, target resource identifier, and 'Access Denied' or similar status |
| 8 | Attempt to access Employee B's schedule using API endpoint directly (e.g., GET /api/schedules/daily?employeeId=B) with Employee A's authentication token | API returns 403 Forbidden or 401 Unauthorized status code with appropriate error message |

**Postconditions:**
- Employee A remains logged in with access only to their own schedule
- Employee B's schedule data remains secure and inaccessible to Employee A
- Audit log contains complete record of unauthorized access attempt
- System security controls remain intact

---

## Story: As Employee, I want to view my weekly schedule to plan my workweek efficiently
**Story ID:** story-12

### Test Case: Validate weekly schedule display with accurate shifts
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Employee account exists with valid credentials
- Employee has multiple shifts scheduled across the current week
- Web portal is accessible and operational
- Backend API GET /api/schedules/weekly is functional
- Test data is populated in EmployeeSchedules table for the current week

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the web portal login page and enter valid employee credentials | Employee successfully logs in and dashboard is displayed with navigation options |
| 2 | Click on the 'Schedule' section from the main navigation menu | Schedule section opens displaying available schedule view options |
| 3 | Select 'Weekly View' option from the schedule view menu | Weekly schedule for the current week is displayed showing all seven days |
| 4 | Verify that the week start date and week end date are correctly displayed in the header | Week range is shown (e.g., 'Week of Jan 15 - Jan 21, 2024') with correct dates |
| 5 | Review the weekly schedule layout and verify all seven days of the week are visible | All days from Monday to Sunday (or Sunday to Saturday based on configuration) are displayed in the weekly view |
| 6 | For each day in the week, verify that all scheduled shifts are displayed with complete details | Each shift shows start time, end time, location, and role for every scheduled day |
| 7 | Identify and verify that weekend days (Saturday and Sunday) are visually highlighted or distinguished | Weekend days are highlighted with different background color or visual indicator |
| 8 | Locate the total hours summary section in the weekly view | Total scheduled hours for the week is displayed prominently |
| 9 | Manually calculate the total hours by summing all shift durations across the week | Manual calculation produces a total hours value |
| 10 | Compare the manually calculated total hours with the system-displayed total hours | System-displayed total hours matches the manually calculated total exactly |
| 11 | Cross-reference all displayed shift details with backend data from EmployeeSchedules table | All shift times, locations, roles, and total hours match backend database records with 100% accuracy |
| 12 | Measure and record the page load time from clicking 'Weekly View' to full display of all shifts | Weekly schedule loads and displays completely within 3 seconds |

**Postconditions:**
- Employee remains logged in to the system
- Weekly schedule view remains accessible
- No errors are logged in the system
- Employee can navigate to other weeks or views

---

### Test Case: Verify week navigation functionality
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Employee is logged into the web portal
- Weekly schedule view is currently displayed
- Employee has shifts scheduled in multiple weeks (past, current, and future)
- Navigation buttons (Next Week, Previous Week) are visible on the interface

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Note the current week date range displayed in the weekly schedule header | Current week date range is clearly visible (e.g., 'Week of Jan 15 - Jan 21, 2024') |
| 2 | Locate and click the 'Next Week' button on the weekly schedule view | Schedule view refreshes and displays the schedule for the next calendar week |
| 3 | Verify the week date range in the header updates to show the next week's dates | Header displays the next week's date range (e.g., 'Week of Jan 22 - Jan 28, 2024') |
| 4 | Review all shifts displayed for the next week and verify they correspond to the correct week | All displayed shifts fall within the next week's date range with accurate details |
| 5 | Verify the total hours calculation updates to reflect the next week's scheduled hours | Total hours displayed matches the sum of all shifts in the next week |
| 6 | Locate and click the 'Previous Week' button on the weekly schedule view | Schedule view refreshes and displays the schedule for the previous calendar week (returning to original week) |
| 7 | Verify the week date range in the header updates to show the previous week's dates | Header displays the previous week's date range, matching the original week viewed |
| 8 | Review all shifts displayed for the previous week and verify accuracy | All displayed shifts match the original week's schedule with correct details |
| 9 | Click 'Previous Week' button multiple times to navigate to earlier weeks | Each click navigates backward one week, updating the date range and displaying appropriate shifts |
| 10 | Click 'Next Week' button multiple times to navigate to future weeks | Each click navigates forward one week, updating the date range and displaying appropriate shifts |
| 11 | Verify that navigation to weeks with no scheduled shifts displays appropriate message | Weeks with no shifts show 'No shifts scheduled for this week' or similar message |
| 12 | Verify that each navigation action completes without errors and within acceptable time | All week navigation transitions occur smoothly within 3 seconds per action, with no errors |

**Postconditions:**
- Employee remains on the weekly schedule view
- Navigation buttons remain functional for continued use
- No system errors are generated
- Employee can continue navigating to any week

---

### Test Case: Ensure unauthorized access is prevented
- **ID:** tc-006
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Two employee accounts exist in the system (Employee A and Employee B)
- Employee A is logged into the web portal
- Employee B has scheduled shifts for the current week
- Direct URL format for weekly schedules is known (e.g., /schedules/weekly?employeeId=B&weekStart=2024-01-15)
- OAuth2 authentication and RBAC security controls are active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | While logged in as Employee A, construct the direct URL for Employee B's weekly schedule using Employee B's identifier | URL is properly formatted with Employee B's employee ID and a valid week start date |
| 2 | Attempt to access Employee B's weekly schedule by entering the constructed URL directly in the browser address bar | System blocks access and displays an error message such as 'Access Denied: You are not authorized to view this schedule' |
| 3 | Verify that Employee A is redirected to their own weekly schedule or an error page | Employee A is redirected away from Employee B's schedule to either their own schedule or a generic access denied page |
| 4 | Verify that no schedule data belonging to Employee B is displayed in the browser | No shifts, hours, locations, roles, or any data belonging to Employee B is visible on the screen |
| 5 | Check the browser network tab or developer tools for any API responses | No API responses contain Employee B's schedule data; only error responses are present |
| 6 | Attempt to access Employee B's weekly schedule using the API endpoint directly with Employee A's authentication token (e.g., GET /api/schedules/weekly?employeeId=B&weekStart=2024-01-15) | API returns 403 Forbidden or 401 Unauthorized HTTP status code with error message in response body |
| 7 | Verify the API error response contains appropriate security message without leaking system information | Error message is generic (e.g., 'Access denied') without revealing internal system details or confirming Employee B's existence |
| 8 | Verify that Employee A's session remains active and they can still access their own weekly schedule | Employee A can navigate back to their own weekly schedule without re-authentication |

**Postconditions:**
- Employee A remains logged in with access only to their own schedule
- Employee B's schedule data remains completely secure and inaccessible
- Security controls continue to function properly
- No data breach or unauthorized access occurred

---

## Story: As Employee, I want to view my monthly schedule to plan long-term commitments
**Story ID:** story-15

### Test Case: Validate monthly schedule display with accurate shifts
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Employee account exists in the system with valid credentials
- Employee has assigned shifts in the EmployeeSchedules table for the current month
- System is accessible and operational
- Browser is supported (Chrome, Firefox, Safari, Edge)
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the employee portal login page and enter valid employee credentials (username and password), then click the 'Login' button | Employee is successfully authenticated and redirected to the dashboard. Dashboard displays employee name and navigation menu including 'Schedule' option |
| 2 | Click on the 'Schedule' section from the navigation menu and select 'Monthly View' option | Monthly schedule view is displayed showing the current month's calendar. All assigned shifts for the logged-in employee are visible with dates, times, and shift types. Weekends and holidays are highlighted. Navigation controls for previous/next months are present |
| 3 | Review each shift entry displayed on the calendar and verify shift details (date, start time, end time, shift type). Check the summary section for total hours per week and total hours for the month | All shift details match the expected schedule data from the EmployeeSchedules table. Total hours per week are calculated correctly by summing all shift hours within each week. Total monthly hours are calculated correctly by summing all shift hours for the month. Calculations are accurate with no discrepancies |

**Postconditions:**
- Employee remains logged in to the system
- Monthly schedule view remains displayed
- No data has been modified in the system
- Session is active and valid

---

### Test Case: Verify month navigation functionality
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Employee is logged into the portal
- Monthly schedule view is currently displayed showing the current month
- Employee has shifts scheduled in previous and/or next months
- System has schedule data available for multiple months

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Locate and click the 'Next Month' button or navigation control on the monthly schedule view | The calendar view transitions to display the next month's schedule. The month and year header updates to show the correct next month. All shifts assigned to the employee for that month are displayed accurately. Total hours summary updates to reflect the new month's data. Page loads without errors or delays |
| 2 | Locate and click the 'Previous Month' button or navigation control on the monthly schedule view | The calendar view transitions back to display the previous month's schedule (returning to the original current month). The month and year header updates to show the correct previous month. All shifts assigned to the employee for that month are displayed accurately. Total hours summary updates to reflect the month's data. Navigation is smooth without errors |
| 3 | Continue clicking 'Previous Month' button multiple times to navigate to months in the past | Each click successfully navigates to the previous month. Historical schedule data is displayed correctly for each month. System handles navigation without performance degradation or errors |
| 4 | Click 'Next Month' button multiple times to navigate forward through months | Each click successfully navigates to the next month. Future schedule data (if available) is displayed correctly. System handles forward navigation without errors |

**Postconditions:**
- Employee can navigate freely between months
- Monthly schedule view remains functional
- No errors are logged in the system
- Employee session remains active

---

### Test Case: Ensure unauthorized access is prevented
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Employee is logged into the portal with valid credentials
- Another employee account exists in the system with a different employee ID
- OAuth2 and RBAC security mechanisms are enabled and configured
- API endpoint GET /api/schedules/monthly requires employee identity verification

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Attempt to manually modify the API request URL or parameters to access another employee's monthly schedule by changing the employee ID parameter (e.g., modify URL to include a different employee ID or manipulate browser developer tools to alter the request) | System detects unauthorized access attempt. Access is denied immediately. An error message is displayed stating 'Access Denied: You are not authorized to view this schedule' or similar security message. HTTP 403 Forbidden status code is returned. No schedule data from the other employee is displayed or accessible |
| 2 | Verify that the system logs the unauthorized access attempt and that the current employee's session remains valid | Unauthorized access attempt is logged in the system security logs with timestamp and employee ID. Current employee can still access their own monthly schedule without issues. Session is not terminated due to the failed access attempt |
| 3 | Attempt to use API testing tools (like Postman or curl) to directly call GET /api/schedules/monthly with another employee's ID while using the current employee's authentication token | API returns HTTP 403 Forbidden or HTTP 401 Unauthorized response. Response body contains error message indicating insufficient permissions. No schedule data is returned in the response payload |

**Postconditions:**
- Employee's own schedule access remains unaffected
- Security violation is logged in the system
- No unauthorized data was exposed
- Employee session remains active and valid

---

## Story: As Employee, I want to filter my schedule by shift type to focus on specific work assignments
**Story ID:** story-16

### Test Case: Validate shift type filtering functionality
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Employee is logged into the portal with valid credentials
- Employee has multiple shifts assigned with different shift types (morning, evening, night)
- Schedule view is accessible and displays the full schedule
- Filter controls are visible and functional in the schedule interface
- System has shift type data properly configured in EmployeeSchedules table

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule view section from the dashboard or main navigation menu | Full schedule is displayed showing all assigned shifts for the employee. All shift types (morning, evening, night) are visible in the schedule. Filter options panel or dropdown is visible with available shift type options. Total count of shifts is displayed |
| 2 | Locate the shift type filter control and select 'Evening' from the available shift type filter options | Filter is applied dynamically without page reload. Only shifts with shift type 'Evening' are displayed in the schedule view. All morning and night shifts are hidden from view. The schedule updates within 2 seconds. Total hours summary updates to reflect only evening shift hours. Filter indicator shows 'Evening' filter is active |
| 3 | Verify that all displayed shifts are indeed evening shifts by checking shift times and shift type labels | All visible shifts have 'Evening' shift type designation. Shift times correspond to evening hours as defined in the system. No morning or night shifts are present in the filtered view. Count of displayed shifts matches the expected number of evening shifts |
| 4 | Click the 'Clear Filter' button or remove the active filter selection | Filter is removed immediately. Full schedule is restored showing all shift types (morning, evening, night). All previously hidden shifts are now visible again. Total hours summary returns to showing all shifts. Filter indicator shows no active filters. Schedule displays the complete original view |

**Postconditions:**
- Schedule view returns to unfiltered state showing all shifts
- Filter controls remain available for future use
- No data has been modified in the system
- Employee session remains active

---

### Test Case: Ensure filtering respects employee identity
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Employee is logged into the portal with valid credentials and authentication token
- Another employee account exists in the system with different employee ID
- API endpoint GET /api/schedules with filter parameters requires employee identity validation
- Security mechanisms (OAuth2, RBAC) are properly configured
- API testing tool (Postman, curl, or browser developer tools) is available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Using API testing tools or browser developer tools, construct a GET request to /api/schedules endpoint with filter parameters for shift type, but modify the employee ID parameter to target another employee's shifts while using the current employee's authentication token | API request is sent with manipulated employee ID parameter. System validates the authentication token against the requested employee ID. Mismatch is detected between authenticated employee and requested employee data |
| 2 | Observe and verify the API response status code and response body | API returns HTTP 403 Forbidden or HTTP 401 Unauthorized status code. Response body contains error message such as 'Access Denied' or 'Unauthorized access to employee data'. No schedule data is returned in the response payload. Response does not contain any shifts belonging to the other employee |
| 3 | Attempt the same unauthorized access through the UI by manipulating browser session storage, cookies, or URL parameters to request another employee's filtered schedule | UI prevents unauthorized access. Error message is displayed to the user. No schedule data from another employee is rendered. Current employee's own schedule remains accessible. Security event is logged in the system |
| 4 | Verify that the current employee can still successfully filter their own schedule after the failed unauthorized access attempt | Employee's own schedule filtering functionality works normally. Filters can be applied and cleared without issues. Only the authenticated employee's shifts are displayed when filters are applied. System performance is not affected by the previous unauthorized access attempt |

**Postconditions:**
- No unauthorized data was accessed or exposed
- Security violation is logged in system audit logs
- Employee's own schedule access remains functional
- Authentication and authorization mechanisms remain intact
- Employee session is still valid

---

## Story: As Employee, I want to search my schedule by date to quickly find specific shifts
**Story ID:** story-17

### Test Case: Validate successful date search
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Employee is logged into the system
- Employee has access to the schedule section
- Employee has at least one scheduled shift in the database
- Test data includes dates with shifts and dates without shifts
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule section from the main dashboard | Schedule section loads successfully and displays the date search input field |
| 2 | Locate the date search input field on the schedule page | Date search input field is visible and enabled for input |
| 3 | Enter a valid date (e.g., 2024-03-15) that has scheduled shifts in the date search field | Date is accepted and displayed in the correct format in the input field |
| 4 | Click the search button or press Enter to execute the search | Search results load within 2 seconds and display all shifts scheduled for the entered date with shift time, location, and role information |
| 5 | Verify that only shifts for the searched date are displayed | All displayed shifts match the searched date and no other dates are shown |
| 6 | Clear the search field or click a clear/reset button | Search field is cleared and full schedule view is restored |
| 7 | Enter a valid date (e.g., 2024-04-20) that has no scheduled shifts in the date search field | Date is accepted and displayed in the correct format in the input field |
| 8 | Click the search button or press Enter to execute the search | Search completes within 2 seconds and displays 'No shifts found' message for the entered date |
| 9 | Verify that no shift data is displayed and the message is clear and user-friendly | 'No shifts found' message is prominently displayed with no shift records shown |
| 10 | Enter an invalid date format (e.g., '32/13/2024', 'abc123', '2024-13-45') in the date search field | System detects invalid format immediately |
| 11 | Attempt to execute the search with the invalid date format | Error message is displayed indicating invalid date format with guidance on correct format (e.g., 'Please enter date in YYYY-MM-DD format') |
| 12 | Verify that no search is executed and no shift data is displayed | Search is not executed, error message remains visible, and schedule view remains unchanged |

**Postconditions:**
- Employee remains logged in
- Schedule section remains accessible
- Search functionality is ready for next search
- No data has been modified in the system
- Full schedule view can be restored by clearing search

---

## Story: As Employee, I want to view schedule details including location and role to prepare for my shifts
**Story ID:** story-19

### Test Case: Validate shift detail display accuracy
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Employee is logged into the system
- Employee has at least one scheduled shift with complete details (location, role, notes)
- Test shift data exists in the database with known location, role, and notes values
- Employee has access to the schedule view
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule view from the main dashboard | Schedule view loads successfully and displays list of scheduled shifts |
| 2 | Identify a shift from the schedule list that has complete details (location, role, and notes) | Shift is visible in the schedule list with basic information displayed |
| 3 | Click or tap on the selected shift to open the shift detail view | Shift detail view opens within 2 seconds and displays detailed information panel |
| 4 | Verify that the shift location is displayed in the detail view | Location field is visible and shows the correct location value matching the backend data (e.g., 'Building A - Floor 3') |
| 5 | Verify that the assigned role is displayed in the detail view | Role field is visible and shows the correct role value matching the backend data (e.g., 'Senior Cashier') |
| 6 | Verify that shift notes are displayed if available | Notes section is visible and displays the correct notes content matching the backend data (e.g., 'Bring safety equipment') |
| 7 | Check if special instructions are highlighted or displayed prominently | Special instructions are clearly visible with appropriate visual emphasis (bold, colored, or in a highlighted section) |
| 8 | Cross-reference all displayed details with the backend data or test data sheet | All displayed information (location, role, notes, special instructions) matches exactly with the backend data |
| 9 | Click the back button or close button to return to schedule overview | Detail view closes and schedule overview is displayed with all shifts visible |

**Postconditions:**
- Employee remains logged in
- Schedule view is displayed
- No data has been modified
- Shift detail view is closed
- System is ready for next interaction

---

### Test Case: Ensure access control on shift details
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Employee is logged into the system
- At least two employee accounts exist in the system with different scheduled shifts
- Test data includes shift IDs belonging to other employees
- Employee does not have admin or manager privileges
- Security validation is enabled on the API endpoint

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in as Employee A and navigate to the schedule view | Employee A is logged in successfully and schedule view displays only Employee A's shifts |
| 2 | Obtain or identify a shift ID that belongs to Employee B (another employee) | Shift ID for Employee B is identified from test data |
| 3 | Attempt to access the shift detail view by directly manipulating the URL or API call with Employee B's shift ID (e.g., /api/schedules/details?shiftId={Employee_B_shift_id}) | System detects unauthorized access attempt |
| 4 | Observe the system response to the unauthorized access attempt | Access is denied with appropriate error message (e.g., 'Access Denied: You do not have permission to view this shift') and HTTP 403 Forbidden status code is returned |
| 5 | Verify that no shift details from Employee B are displayed to Employee A | No shift information is revealed, and Employee A cannot see any details of Employee B's shift |
| 6 | Verify that Employee A is redirected back to their own schedule view or an error page | Employee A remains on their schedule view or is shown an appropriate error page without access to unauthorized data |
| 7 | Check application logs or security logs for the unauthorized access attempt | Security event is logged with details of the unauthorized access attempt including timestamp, employee ID, and attempted shift ID |

**Postconditions:**
- Employee A remains logged in
- Employee A can only access their own shift details
- No unauthorized data was exposed
- Security event is logged
- System security integrity is maintained

---

