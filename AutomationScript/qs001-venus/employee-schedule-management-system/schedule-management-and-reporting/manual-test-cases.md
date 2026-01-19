# Manual Test Cases

## Story: As Manager, I want to view employee schedules in calendar format to monitor shift coverage
**Story ID:** story-5

### Test Case: Validate calendar displays employee schedules correctly
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with Manager role credentials
- Employee schedules exist in the system for current and next month
- At least one employee has assigned shifts
- Network connectivity is stable
- Browser is supported (Chrome, Firefox, Safari, Edge)

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule calendar page by clicking on 'Schedule Calendar' menu option | Calendar is displayed showing the current month with all employee shifts visible, calendar loads within 3 seconds, current date is highlighted |
| 2 | Click on the employee filter dropdown and select a specific employee from the list | Calendar updates immediately to show only the selected employee's shifts, other employees' shifts are hidden, filter selection is reflected in the UI |
| 3 | Click on the 'Next Month' navigation button or arrow to move to the next month | Calendar updates to display the next month's view without delay (under 3 seconds), selected employee filter remains applied, all shifts for the selected employee in the next month are displayed correctly |

**Postconditions:**
- Calendar remains on the next month view
- Employee filter remains active
- User session remains active
- No errors are logged in the system

---

### Test Case: Verify shift types and statuses are highlighted distinctly
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- User is logged in with Manager role credentials
- Multiple shift types exist in the system (e.g., Morning, Evening, Night, Overtime)
- Multiple shift statuses exist (e.g., Scheduled, Confirmed, Completed, Cancelled)
- Calendar page is accessible
- Test data includes various shift types and statuses for the current month

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule calendar page and view the calendar displaying multiple employees with different shift types and statuses | Calendar displays with multiple shifts visible, each shift type has a distinct visual indicator (different colors, icons, or patterns), each shift status has a distinct visual indicator, shifts are easily distinguishable from one another, legend or key is displayed showing shift type and status meanings |

**Postconditions:**
- All shift types remain visually distinct
- All shift statuses remain clearly identifiable
- Calendar view remains functional
- No visual rendering issues occur

---

### Test Case: Ensure unauthorized users cannot access calendar view
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- Test user account exists with non-Manager role (e.g., Employee, Viewer, or Guest role)
- Application security and role-based access control is configured
- Calendar page URL is known
- User is logged out initially

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Login to the application using non-Manager user credentials (username and password for Employee or other non-Manager role) | User successfully logs in and is redirected to their appropriate dashboard, Manager-specific menu options are not visible |
| 2 | Attempt to access the schedule calendar page by clicking on navigation menu or directly entering the calendar page URL | Access to calendar page is denied, user receives an error message indicating insufficient permissions (e.g., '403 Forbidden' or 'Access Denied'), user is redirected to their home page or an error page, calendar data is not displayed |

**Postconditions:**
- User remains logged in with their non-Manager role
- No unauthorized access to calendar data occurred
- Security event is logged in the system audit trail
- User session remains secure

---

## Story: As Manager, I want to generate reports on schedule adherence to analyze workforce compliance
**Story ID:** story-6

### Test Case: Validate schedule adherence report generation with filters
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in with Manager role credentials
- Schedule adherence data exists in the system for the selected date range
- Employee schedules and attendance records are available
- Reporting module is accessible
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the reporting page by clicking on 'Reports' menu option | Reporting UI is displayed with available report types listed, page loads successfully within 3 seconds, filter options are visible |
| 2 | Select 'Schedule Adherence Report' from the report type dropdown and apply filters (date range: last 30 days, department: Sales, employee: All) | Filters are accepted and displayed in the UI, selected values are shown in the filter fields, no validation errors occur, 'Generate Report' button becomes enabled |
| 3 | Click on 'Generate Report' button to create the schedule adherence report | Report is generated and displayed on screen within 5 seconds, report contains accurate schedule adherence data for the selected filters, report shows metrics such as adherence percentage, late arrivals, early departures, and absences, data is formatted clearly with headers and proper alignment |

**Postconditions:**
- Report remains displayed on screen
- Filter selections remain active
- Report data is accurate and matches database records
- User session remains active

---

### Test Case: Verify report export to PDF and Excel
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in with Manager role credentials
- Schedule adherence report has been generated and is displayed on screen
- Browser download settings allow file downloads
- Sufficient disk space is available for downloads
- PDF and Excel export functionality is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Generate a schedule adherence report with specific filters (date range: last 7 days, department: IT) | Report is displayed on screen with complete data, export options (PDF and Excel buttons) are visible and enabled |
| 2 | Click on 'Export to PDF' button | PDF file is generated and downloaded to the default download location, file name includes report type and timestamp, PDF opens successfully and displays all report data with proper formatting, headers, footers, and page numbers are present, all tables and charts are rendered correctly |
| 3 | Click on 'Export to Excel' button | Excel file is generated and downloaded to the default download location, file name includes report type and timestamp, Excel file opens successfully in spreadsheet application, all report data is present in structured format with proper columns and rows, data is editable and formulas are preserved if applicable, formatting (colors, borders, fonts) is maintained |

**Postconditions:**
- Both PDF and Excel files are saved in download folder
- Files are not corrupted and can be opened
- Report remains displayed on screen
- Export functionality remains available for additional exports

---

### Test Case: Ensure unauthorized users cannot access reports
- **ID:** tc-006
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- Test user account exists with non-Manager role (e.g., Employee, Contractor, or Viewer role)
- Application security and role-based access control is configured
- Reporting page URL is known
- User is logged out initially

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Login to the application using non-Manager user credentials (username and password for Employee or other non-Manager role) | User successfully logs in and is redirected to their appropriate dashboard, reporting menu options are not visible in the navigation menu |
| 2 | Attempt to access the reporting page by directly entering the reporting page URL in the browser address bar | Access to reporting page is denied, user receives an error message indicating insufficient permissions (e.g., '403 Forbidden', 'Access Denied', or 'You do not have permission to view this page'), user is redirected to their home page or an error page, no report data or reporting interface is displayed |

**Postconditions:**
- User remains logged in with their non-Manager role
- No unauthorized access to reporting functionality occurred
- Security event is logged in the system audit trail
- User session remains secure and active

---

## Story: As Scheduler, I want to view employee schedules in list format to quickly find and manage shifts
**Story ID:** story-9

### Test Case: Validate schedule list displays and filters correctly
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Scheduler role
- Employee schedules exist in the system
- Database contains schedules with various employees, dates, and shift types
- User has network connectivity
- Browser is supported (Chrome, Firefox, Safari, Edge)

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule list page by clicking on 'Schedules' menu and selecting 'List View' | Schedule list page loads within 3 seconds and displays all employee schedules in a table format with columns for employee name, date, shift type, and time |
| 2 | Verify the initial display of schedules without any filters applied | All schedules are displayed in the list with complete information visible for each schedule entry |
| 3 | Click on the 'Employee' filter dropdown and select a specific employee name from the list | Filter dropdown displays all available employees and the selected employee is highlighted |
| 4 | Click 'Apply Filter' button after selecting the employee | List updates to show only schedules for the selected employee, other schedules are filtered out |
| 5 | Click on the 'Date' filter and select a specific date range using the date picker | Date picker opens, allows selection of start and end dates, and selected dates are displayed in the filter field |
| 6 | Apply the date filter along with the existing employee filter | List updates to show only schedules for the selected employee within the specified date range, maintaining both filter criteria |
| 7 | Locate the search box at the top of the schedule list and enter a keyword related to shift type or employee name | Search box accepts text input and displays the entered keyword |
| 8 | Press Enter or click the search icon to execute the search | Search results are displayed showing only schedules that match the keyword, with matching text highlighted. Results are accurate and relevant to the search term |
| 9 | Verify the count of search results displayed matches the number of records shown in the list | Result count indicator shows the correct number of matching schedules (e.g., 'Showing 5 of 100 schedules') |

**Postconditions:**
- Schedule list displays filtered results based on applied criteria
- Filters remain active and visible on the page
- Search keyword remains in the search box
- User remains on the schedule list page
- No data is modified in the system

---

### Test Case: Verify sorting and selection of schedules
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in with Scheduler role
- Schedule list page is accessible
- Multiple employee schedules exist in the system with different dates
- Schedules are displayed in the list view
- No filters are currently applied

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule list page | Schedule list page loads successfully displaying all schedules in default order |
| 2 | Locate the 'Date' column header and click on it to sort by date | Column header shows a sort indicator (up or down arrow) and the list is sorted by date in ascending order (earliest to latest) |
| 3 | Click on the 'Date' column header again to reverse the sort order | Sort indicator changes direction and the list is now sorted by date in descending order (latest to earliest) |
| 4 | Verify the date sorting by checking the first and last entries in the list | Dates are correctly ordered with the most recent date at the top and oldest date at the bottom |
| 5 | Click on the 'Employee Name' column header to sort alphabetically | List is re-sorted alphabetically by employee name in ascending order (A to Z) |
| 6 | Locate the checkbox in the first row of the schedule list and click to select it | Checkbox is checked and the row is highlighted to indicate selection. Bulk action toolbar appears at the top or bottom of the list |
| 7 | Select two additional schedules by clicking their respective checkboxes | All three selected schedules are highlighted with checked checkboxes. Selection counter shows '3 schedules selected' |
| 8 | Click the 'Select All' checkbox in the table header | All visible schedules on the current page are selected with checked checkboxes and highlighted rows. Selection counter updates to show total number selected |
| 9 | Verify that bulk action buttons (such as 'Delete', 'Export', 'Modify') are enabled | Bulk action buttons are visible and enabled, ready for user interaction |
| 10 | Click the 'Select All' checkbox again to deselect all schedules | All checkboxes are unchecked, row highlighting is removed, and bulk action toolbar is hidden or disabled |

**Postconditions:**
- Schedule list is sorted according to the last sort action performed
- All schedules are deselected
- Bulk action toolbar is hidden or disabled
- User remains on the schedule list page
- No schedules are modified or deleted

---

### Test Case: Ensure unauthorized users cannot access schedule list
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Test user account exists with non-Scheduler role (e.g., Employee, Viewer, or Guest role)
- Schedule list page URL is known
- User is not currently logged in
- Role-based access control is configured in the system
- Authorization rules restrict schedule list access to Scheduler role only

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the application login page | Login page is displayed with username and password fields |
| 2 | Enter valid credentials for a user with non-Scheduler role (e.g., Employee role) in the username and password fields | Credentials are accepted in the input fields |
| 3 | Click the 'Login' button to authenticate | User is successfully authenticated and redirected to the appropriate dashboard for their role |
| 4 | Verify the user's role is displayed or indicated in the user profile section | User profile shows the non-Scheduler role (e.g., 'Employee' or 'Viewer') |
| 5 | Look for 'Schedules' menu or 'List View' option in the navigation menu | Schedule list menu option is either not visible or is disabled/grayed out in the navigation |
| 6 | Attempt to directly access the schedule list page by entering the URL in the browser address bar (e.g., /schedules/list) | Access is denied. System displays an error message such as '403 Forbidden - You do not have permission to access this page' or redirects to an unauthorized access page |
| 7 | Verify that no schedule data is displayed or accessible | No schedule information is visible. User remains on the error page or is redirected to their authorized dashboard |
| 8 | Check the browser console for any security-related messages or errors | Console shows authorization failure message confirming access was properly restricted |
| 9 | Log out and attempt to access the schedule list page without authentication | System redirects to login page with a message indicating authentication is required |

**Postconditions:**
- Non-Scheduler user remains logged in with their original role
- No unauthorized access to schedule data occurred
- Security logs record the unauthorized access attempt
- User is on either the error page or their authorized dashboard
- System security integrity is maintained

---

