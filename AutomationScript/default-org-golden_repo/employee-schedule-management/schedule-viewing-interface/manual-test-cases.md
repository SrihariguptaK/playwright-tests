# Manual Test Cases

## Story: As Employee, I want to view my daily schedule to plan my workday effectively
**Story ID:** story-11

### Test Case: Validate successful display of daily schedule
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee has valid login credentials
- Employee has at least one shift scheduled for the current day
- Web portal is accessible and operational
- Database contains valid schedule data for the employee
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the web portal login page using a supported browser | Login page is displayed with username and password fields |
| 2 | Enter valid employee credentials (username and password) and click the Login button | Employee is successfully authenticated and redirected to the dashboard page |
| 3 | Verify the dashboard is fully loaded and displays navigation menu | Dashboard is displayed with all navigation options visible including schedule section |
| 4 | Click on the 'Schedule' section from the navigation menu | Schedule section opens and displays view options (daily, weekly) |
| 5 | Select 'Daily View' option | Daily schedule for the current day is displayed within 3 seconds showing the date header |
| 6 | Review the displayed shift details including shift start time, shift end time, location, and role | All shift information is correctly displayed: shift times are in proper format (HH:MM AM/PM), location name is visible, and assigned role is shown accurately matching the database records |
| 7 | Verify the page layout and readability of schedule information | Schedule is displayed in a clear, organized format with proper spacing and readable fonts |

**Postconditions:**
- Employee remains logged into the system
- Daily schedule view remains active and accessible
- No errors are logged in the system
- Session remains valid for continued use

---

### Test Case: Verify navigation to previous and next days
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Employee is logged into the web portal
- Employee is on the daily schedule view page
- Current day schedule is displayed
- Schedule data exists for previous and next days
- Navigation buttons are visible and enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Verify the current date is displayed in the schedule header | Current date is clearly shown in the header (e.g., 'Monday, January 15, 2024') |
| 2 | Locate and click the 'Next Day' button or right arrow navigation control | Page refreshes or updates smoothly and displays the schedule for the next day (e.g., 'Tuesday, January 16, 2024') |
| 3 | Verify the date header has updated to show the next day's date | Date header displays the correct next day date and any scheduled shifts for that day are shown |
| 4 | Review the shift details for the next day | Shift information for the next day is displayed correctly with accurate times, location, and role |
| 5 | Click the 'Previous Day' button or left arrow navigation control | Page updates and displays the schedule for the previous day (returning to current day) |
| 6 | Verify the date header has updated to show the previous day's date | Date header displays the correct previous day date and original schedule is restored |
| 7 | Click 'Previous Day' button again to navigate to the day before current day | Schedule for the day before current day is displayed with correct date and shift information |
| 8 | Verify no errors occur during navigation and page load time remains under 3 seconds for each navigation action | All navigation actions complete successfully within performance requirements without error messages |

**Postconditions:**
- Employee can continue navigating between days
- System maintains session state
- Navigation history is maintained
- No data corruption or display errors occur

---

### Test Case: Ensure access is restricted to authenticated employees
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Web portal is accessible
- Daily schedule URL endpoint is known
- Test user has valid employee credentials available
- Browser session has no active authentication tokens
- Security and authentication services are operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open a new browser window or incognito/private browsing session | New browser session opens with no cached credentials or active sessions |
| 2 | Directly navigate to the daily schedule URL (e.g., https://portal.company.com/schedules/daily) without logging in | Access is denied and user is redirected to the login page or an access denied page is displayed |
| 3 | Verify that an appropriate error message is displayed | User-friendly error message is shown such as 'Access Denied: Please log in to view your schedule' or 'Authentication Required' |
| 4 | Verify that no schedule data is visible or accessible in the page source or network responses | No sensitive schedule information is exposed; API returns 401 Unauthorized or 403 Forbidden status |
| 5 | Navigate to the login page and enter valid employee credentials | Login form accepts credentials and authentication process initiates |
| 6 | Click the Login button to authenticate | Employee is successfully authenticated and redirected to the dashboard or daily schedule page |
| 7 | Verify that the daily schedule is now accessible and displays correctly | Daily schedule page loads successfully within 3 seconds showing complete schedule information with shift times, location, and role |
| 8 | Verify the authentication token is present in the session | Valid OAuth 2.0 token is stored in session and used for API requests |

**Postconditions:**
- Authenticated employee has full access to daily schedule
- Security logs record the unauthorized access attempt
- Session is established and valid for the authenticated user
- System maintains proper access control for subsequent requests

---

## Story: As Employee, I want to view my weekly schedule to plan my workweek efficiently
**Story ID:** story-12

### Test Case: Validate display of weekly schedule
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Employee has valid login credentials
- Employee has shifts scheduled for the current week
- Web portal is accessible and operational
- Database contains valid weekly schedule data
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the web portal login page using a supported browser (Chrome, Firefox, Safari, or Edge) | Login page is displayed with username and password input fields and login button |
| 2 | Enter valid employee credentials (username and password) and click the Login button | Employee is successfully authenticated and redirected to the dashboard page |
| 3 | Verify the dashboard loads completely with all navigation elements visible | Dashboard is displayed with navigation menu including schedule section and all UI elements are rendered properly |
| 4 | Click on the 'Schedule' section from the navigation menu | Schedule section opens displaying available view options (daily view and weekly view) |
| 5 | Select 'Weekly View' or 'Weekly Schedule' option | Weekly schedule view loads within 4 seconds displaying a 7-day calendar grid for the current week |
| 6 | Verify the week date range is displayed in the header (e.g., 'January 15 - January 21, 2024') | Week date range is clearly shown in the header indicating the start and end dates of the displayed week |
| 7 | Verify all 7 days of the week are displayed (Sunday through Saturday or Monday through Sunday based on configuration) | All 7 days are shown in the weekly view with day names and dates clearly labeled |
| 8 | Review shifts for each day of the week, checking Monday's schedule | Monday's shifts are displayed with complete details including shift start time, end time, location, and role assignment |
| 9 | Review shifts for Tuesday through Sunday, verifying each day's schedule information | All shifts for each day of the week are correctly displayed with accurate shift times, location names, and role assignments matching database records |
| 10 | Verify that days with no scheduled shifts display appropriately (e.g., 'No shifts scheduled' or empty state) | Days without shifts show a clear indication such as 'No shifts' or 'Day off' rather than appearing broken or empty |
| 11 | Verify the current day is highlighted or visually distinguished from other days | Current day is highlighted with a different background color, border, or visual indicator making it easily identifiable |

**Postconditions:**
- Employee remains logged into the system
- Weekly schedule view remains active and accessible
- No errors are logged in the system
- Session remains valid for continued navigation

---

### Test Case: Verify navigation between weeks
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Employee is logged into the web portal
- Employee is on the weekly schedule view page
- Current week schedule is displayed
- Schedule data exists for previous and next weeks
- Week navigation buttons are visible and enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Verify the current week date range is displayed in the header | Current week date range is clearly shown (e.g., 'January 15 - January 21, 2024') |
| 2 | Note the shifts displayed for the current week for comparison after navigation | Current week's schedule is visible with all shift details for reference |
| 3 | Locate and click the 'Next Week' button or right arrow navigation control | Page updates smoothly and displays the schedule for the next week with updated date range in header |
| 4 | Verify the week date range header has updated to show next week's dates (e.g., 'January 22 - January 28, 2024') | Date range header displays the correct next week dates spanning 7 consecutive days |
| 5 | Review the shifts displayed for the next week | All shifts for the next week are displayed correctly with accurate times, locations, and roles for each day |
| 6 | Verify the page load time is within 4 seconds | Weekly schedule for next week loads completely within the 4-second performance requirement |
| 7 | Click the 'Previous Week' button or left arrow navigation control | Page updates and displays the schedule for the previous week (returning to current week) |
| 8 | Verify the week date range has updated back to the current week dates | Date range header displays the original current week dates and the original schedule is restored |
| 9 | Verify the shifts match the originally displayed current week schedule | All shift information matches the initial current week display confirming accurate navigation |
| 10 | Click 'Previous Week' button again to navigate to the week before current week | Schedule for the previous week is displayed with correct date range and shift information |
| 11 | Verify the week date range shows dates prior to the current week | Date range header displays the correct previous week dates (e.g., 'January 8 - January 14, 2024') |
| 12 | Verify no errors occur during any navigation action and all transitions are smooth | All navigation actions complete successfully without error messages, broken layouts, or performance degradation |

**Postconditions:**
- Employee can continue navigating between weeks
- System maintains session state
- Navigation history is preserved
- No data corruption or display errors occur
- Current day highlighting updates appropriately when navigating to weeks containing current date

---

### Test Case: Ensure access control for weekly schedule
- **ID:** tc-006
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Web portal is accessible
- Weekly schedule URL endpoint is known
- Test user has valid employee credentials available
- Browser session has no active authentication tokens
- Security and authentication services are operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open a new browser window or incognito/private browsing session to ensure no cached credentials | New browser session opens with no stored authentication data or active sessions |
| 2 | Directly navigate to the weekly schedule URL (e.g., https://portal.company.com/schedules/weekly) without logging in | Access is denied and user is automatically redirected to the login page or an access denied error page is displayed |
| 3 | Verify that an appropriate access denied or authentication required message is displayed | User-friendly error message is shown such as 'Access Denied: Authentication Required' or 'Please log in to view your weekly schedule' |
| 4 | Open browser developer tools and check the network tab for API responses | API request to GET /api/schedules/weekly returns 401 Unauthorized or 403 Forbidden status code |
| 5 | Verify that no schedule data is visible in the page content or accessible in the page source code | No sensitive schedule information is exposed; page shows only error message or login prompt without any schedule data |
| 6 | Navigate to the login page (if not already redirected) and locate the username and password fields | Login page is displayed with input fields for credentials and a login button |
| 7 | Enter valid employee credentials (username and password) | Credentials are accepted in the input fields without validation errors |
| 8 | Click the Login button to authenticate | Employee is successfully authenticated via OAuth 2.0 and redirected to the dashboard or weekly schedule page |
| 9 | Verify that the weekly schedule is now accessible and displays correctly | Weekly schedule page loads successfully within 4 seconds showing the complete 7-day schedule with all shift details including times, locations, and roles |
| 10 | Verify the authentication token is present and valid in the session | Valid OAuth 2.0 authentication token is stored in the session and included in API request headers |
| 11 | Check the network tab to confirm API request now returns 200 OK status | GET /api/schedules/weekly request returns 200 OK status with schedule data in response body |

**Postconditions:**
- Authenticated employee has full access to weekly schedule
- Security logs record the unauthorized access attempt and subsequent successful authentication
- Valid session is established for the authenticated user
- System maintains proper access control and authorization for all subsequent requests
- Employee can navigate to other schedule views and features

---

## Story: As Employee, I want to export my schedule to PDF to have an offline copy
**Story ID:** story-17

### Test Case: Validate successful PDF export of schedule
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Employee is logged into the system
- Employee has an active schedule with assigned shifts
- Employee has access to the schedule view page
- Browser has download permissions enabled
- PDF generation service is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule page and select daily view | Schedule is displayed in daily view showing all shifts for the selected day with times, locations, and roles |
| 2 | Click the 'Export to PDF' button | System initiates PDF generation process and displays a loading indicator |
| 3 | Wait for PDF generation to complete | PDF is generated and download link is provided within 5 seconds, loading indicator disappears |
| 4 | Click the download link to save the PDF file | PDF file downloads successfully to the default download location |
| 5 | Open the downloaded PDF file using a PDF reader | PDF opens successfully and displays the schedule in daily view format |
| 6 | Verify all shift details in the PDF including shift times, locations, and assigned roles | PDF contains accurate and complete schedule details matching the web view, all text is readable and properly formatted |
| 7 | Return to schedule page and switch to weekly view | Schedule is displayed in weekly view showing all shifts for the selected week |
| 8 | Click the 'Export to PDF' button for weekly view | PDF is generated and download link is provided within 5 seconds |
| 9 | Download and open the weekly view PDF | PDF contains accurate weekly schedule with all shift details properly formatted |
| 10 | Return to schedule page and switch to monthly view | Schedule is displayed in monthly view showing all shifts for the selected month |
| 11 | Click the 'Export to PDF' button for monthly view | PDF is generated and download link is provided within 5 seconds |
| 12 | Download and open the monthly view PDF | PDF contains accurate monthly schedule with all shift details properly formatted and readable |

**Postconditions:**
- Three PDF files (daily, weekly, monthly) are successfully downloaded
- All PDFs contain accurate schedule information
- Employee remains logged in and on the schedule page
- No error messages are displayed
- System is ready for additional export operations

---

### Test Case: Verify error handling during export
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Employee is logged into the system
- Employee has access to the schedule view page
- Test environment allows simulation of backend failures
- PDF generation service can be toggled or simulated to fail

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule page and verify schedule is displayed | Schedule page loads successfully with current schedule view displayed |
| 2 | Configure test environment to simulate PDF generation service failure | Backend PDF generation service is set to return an error response |
| 3 | Click the 'Export to PDF' button | System attempts to generate PDF and initiates the export request |
| 4 | Observe the system response after backend failure | User-friendly error message is displayed such as 'Unable to generate PDF. Please try again later.' or 'PDF export failed. Please contact support if the issue persists.' |
| 5 | Verify that the error message does not expose technical details or stack traces | Error message is clear, non-technical, and appropriate for end users |
| 6 | Verify that the schedule page remains functional after the error | Schedule view is still accessible and all other functionality works normally |
| 7 | Check that no partial or corrupted PDF file was downloaded | No file download occurred, download folder does not contain any incomplete PDF files |
| 8 | Restore PDF generation service to normal operation | Backend service is functioning normally again |
| 9 | Click the 'Export to PDF' button again | PDF is generated successfully and download link is provided, confirming system recovery |

**Postconditions:**
- User-friendly error message was displayed during failure
- No corrupted or partial files were downloaded
- Schedule page functionality remains intact
- System successfully recovers and can perform exports after service restoration
- Error is logged appropriately for troubleshooting

---

