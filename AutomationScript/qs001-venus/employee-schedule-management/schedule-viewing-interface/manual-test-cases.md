# Manual Test Cases

## Story: As Employee, I want to view my daily schedule to plan my workday effectively
**Story ID:** story-7

### Test Case: Validate successful daily schedule display for authenticated employee
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee has valid login credentials
- Employee has at least one shift scheduled for the current day
- Web portal is accessible and operational
- Employee schedules database is populated with test data
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the web portal login page using a supported browser | Login page is displayed with username and password fields |
| 2 | Enter valid employee credentials (username and password) and click Login button | Authentication is successful and employee dashboard is displayed with navigation menu visible |
| 3 | Locate and click on the 'Schedule' section in the navigation menu | Schedule section opens showing schedule view options |
| 4 | Select 'Daily View' option from the schedule menu | Daily schedule for current day is displayed showing shift start time, end time, location, and role assignment. Current day is highlighted clearly |
| 5 | Verify all shift details are accurate by comparing with expected schedule data | All displayed shift information matches the employee's scheduled shifts including correct times, location, and role |
| 6 | Click the refresh button or use browser refresh to reload the schedule view | Schedule view reloads successfully and displays the latest schedule updates without errors or data loss |
| 7 | Verify the page load time is acceptable | Schedule refresh completes within 2 seconds |

**Postconditions:**
- Employee remains logged into the portal
- Daily schedule view remains accessible
- No errors are logged in the system
- Session remains active for further navigation

---

### Test Case: Verify access restriction to own schedule only
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Employee is logged into the web portal
- Multiple employee accounts exist in the system
- Employee knows or can construct URL pattern for schedule access
- Authorization and authentication mechanisms are enabled
- Test employee has valid schedule data

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | While logged in as Employee A, note the current schedule URL in the browser address bar | URL is visible and contains employee-specific identifier or session token |
| 2 | Attempt to modify the URL to access another employee's schedule by changing employee ID or relevant parameter (e.g., change employeeId=123 to employeeId=456) | System detects unauthorized access attempt |
| 3 | Press Enter to navigate to the modified URL | Access is denied and an appropriate error message is displayed (e.g., 'Access Denied: You are not authorized to view this schedule' or HTTP 403 Forbidden) |
| 4 | Verify that no schedule data from the other employee is visible on the screen | No unauthorized schedule information is displayed; only error message is shown |
| 5 | Navigate back to the schedule section using the navigation menu | Navigation is successful and schedule menu is displayed |
| 6 | Select daily view to access own schedule through normal navigation | Employee's own daily schedule is displayed correctly with all shift details visible |
| 7 | Verify all displayed information belongs to the logged-in employee | Schedule shows only the authenticated employee's shifts with correct employee name and details |

**Postconditions:**
- Employee remains logged in with valid session
- Security logs record the unauthorized access attempt
- Employee can continue to access their own schedule
- No data breach or unauthorized data exposure occurred

---

### Test Case: Test performance of daily schedule loading
- **ID:** tc-003
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Employee is logged into the web portal
- Employee has schedule data available for the current day
- Network conditions are stable and normal
- Performance monitoring tools are available (browser developer tools or stopwatch)
- System is under normal load conditions

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open browser developer tools and navigate to the Network tab to monitor request timing | Developer tools are open and Network tab is active with timeline visible |
| 2 | Clear browser cache and existing network logs to ensure accurate measurement | Cache is cleared and network log is empty |
| 3 | Navigate to the schedule section from the dashboard | Schedule section menu is displayed |
| 4 | Click on 'Daily View' option and start timing the page load | Daily schedule view begins loading and network requests are initiated |
| 5 | Monitor the Network tab and note the time taken for the GET /api/schedules/daily API call to complete | API request completes and returns schedule data |
| 6 | Verify the total page load time from click to full schedule display | Daily schedule is fully loaded and displayed within 2 seconds. All shift details are visible and page is interactive |
| 7 | Record the actual load time from the Network tab timing information | Recorded time is at or below 2 seconds threshold |
| 8 | Repeat the test by refreshing the daily schedule view 2 more times to verify consistent performance | Each subsequent load also completes within 2 seconds, demonstrating consistent performance |

**Postconditions:**
- Performance metrics are documented
- Daily schedule remains accessible and functional
- Employee session remains active
- System performance meets defined SLA of under 2 seconds

---

## Story: As Employee, I want to view my weekly schedule to plan my workweek efficiently
**Story ID:** story-8

### Test Case: Validate weekly schedule display and navigation
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Employee has valid login credentials and is authenticated
- Employee has shifts scheduled across multiple weeks
- Weekly schedule data includes both working days and off days
- Web portal is accessible and operational
- Database contains schedule data for current, previous, and next weeks

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the web portal login page and enter valid employee credentials | Employee is successfully authenticated and dashboard is displayed |
| 2 | Click on the 'Schedule' section in the navigation menu | Schedule section opens with available view options |
| 3 | Select 'Weekly View' option from the schedule menu | Weekly schedule for the current week is displayed showing all 7 days with shift details including start time, end time, location, and role for each scheduled shift |
| 4 | Verify that all shifts for the current week are displayed accurately | All scheduled shifts for the week are visible with complete and accurate information. Off days are clearly marked |
| 5 | Verify that weekends and off days are highlighted or displayed distinctly from working days | Weekends (Saturday and Sunday) and off days are visually distinguished using different colors, icons, or styling |
| 6 | Locate and click the 'Next Week' navigation button or arrow | Schedule view transitions to display the next week's schedule (7 days forward from current week) |
| 7 | Verify that the next week's schedule displays correctly with all shifts and dates | Next week's schedule is displayed with correct dates, all scheduled shifts, and off days. Week identifier or date range is updated |
| 8 | Click the 'Previous Week' navigation button twice to go back to the week before the current week | Schedule view navigates backward and displays the previous week's schedule (7 days before current week) |
| 9 | Verify that the previous week's schedule displays correctly with historical shift data | Previous week's schedule is displayed accurately with all shifts, dates, and off days. Historical data is preserved and correct |
| 10 | Navigate back to the current week using the 'Next Week' button | Current week's schedule is displayed again with all original information intact |

**Postconditions:**
- Employee remains logged into the portal
- Weekly schedule view remains functional
- Navigation state is preserved for continued use
- No errors are logged during navigation

---

### Test Case: Verify access control for weekly schedule
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Employee is logged into the web portal as Employee A
- Multiple employee accounts exist with different schedule data
- Authorization mechanisms are properly configured
- Employee A has valid weekly schedule data
- Another employee (Employee B) exists with different schedule data

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | While logged in as Employee A, navigate to the weekly schedule view | Employee A's weekly schedule is displayed correctly |
| 2 | Note the URL pattern in the browser address bar for the weekly schedule | URL is visible and contains employee-specific identifier or parameters |
| 3 | Attempt to modify the URL to access Employee B's weekly schedule by changing the employee identifier in the URL (e.g., change employeeId=123 to employeeId=789) | URL is modified in the address bar |
| 4 | Press Enter to navigate to the modified URL | System detects unauthorized access attempt and denies access |
| 5 | Verify that an appropriate error message is displayed | Error message is shown indicating access denial (e.g., 'Access Denied: You are not authorized to view this schedule', 'Unauthorized Access', or HTTP 403 Forbidden error) |
| 6 | Verify that no schedule data from Employee B is visible on the screen | No unauthorized employee schedule information is displayed. Only error message or access denied page is shown |
| 7 | Use browser back button or navigate to schedule section again through the menu | Navigation is successful and Employee A is returned to their own schedule view |
| 8 | Verify that Employee A can still access their own weekly schedule normally | Employee A's weekly schedule is displayed correctly with all shifts and off days visible |

**Postconditions:**
- Employee A remains logged in with active session
- Security event is logged for the unauthorized access attempt
- Employee A retains access to their own schedule
- No unauthorized data was exposed or accessed
- System security integrity is maintained

---

### Test Case: Test weekly schedule loading performance
- **ID:** tc-006
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Employee is logged into the web portal
- Employee has weekly schedule data available
- Network conditions are stable and normal
- Performance monitoring tools are available (browser developer tools)
- System is under normal operational load
- Browser cache is cleared for accurate measurement

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open browser developer tools (F12) and navigate to the Network tab | Developer tools are open with Network tab active and ready to record |
| 2 | Clear browser cache and existing network activity logs | Cache is cleared and network log is empty for fresh measurement |
| 3 | From the employee dashboard, navigate to the Schedule section | Schedule menu is displayed with view options |
| 4 | Click on 'Weekly View' option and simultaneously start monitoring the load time in the Network tab | Weekly schedule view begins loading and GET /api/schedules/weekly API request is initiated |
| 5 | Monitor the Network tab and observe the API request completion time | API request to GET /api/schedules/weekly completes and returns schedule data |
| 6 | Wait for the weekly schedule to fully render on screen with all 7 days visible | Complete weekly schedule is displayed with all shifts, off days, and weekends properly rendered |
| 7 | Check the total page load time from the Network tab timing information (from initial click to DOMContentLoaded or Load event) | Total load time is recorded and is at or below 3 seconds. Weekly schedule is fully interactive |
| 8 | Record the actual load time and verify it meets the performance requirement | Recorded time is within the 3-second threshold as specified in acceptance criteria |
| 9 | Refresh the weekly schedule view and measure load time again | Subsequent load also completes within 3 seconds, confirming consistent performance |
| 10 | Navigate to next week and measure the load time for the new week's data | Navigation to next week completes within 3 seconds with all schedule data displayed |

**Postconditions:**
- Performance metrics are documented and meet requirements
- Weekly schedule remains accessible and functional
- Employee session remains active
- System performance meets defined SLA of under 3 seconds
- No performance degradation is observed

---

## Story: As Employee, I want to view my monthly schedule to overview my work commitments
**Story ID:** story-9

### Test Case: Validate monthly schedule calendar display and navigation
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Employee account exists in the system with valid credentials
- Employee has scheduled shifts assigned in the database
- Employee portal application is accessible and running
- Test data includes shifts in current, previous, and next months

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the employee portal login page | Login page is displayed with username and password fields |
| 2 | Enter valid employee credentials and click Login button | Employee is successfully authenticated and redirected to the dashboard |
| 3 | Navigate to the schedule section from the main menu | Schedule section is accessible and displays schedule view options |
| 4 | Select the monthly schedule view option | Monthly calendar is displayed showing the current month with all days visible, shift indicators appear on scheduled days, weekends and holidays are highlighted distinctly |
| 5 | Click the next month navigation button or arrow | Calendar updates to display the next month's schedule with correct shift indicators, month and year labels update accordingly |
| 6 | Click the previous month navigation button or arrow twice | Calendar updates to display the previous month's schedule (one month before current month) with correct shift indicators, month and year labels update accordingly |
| 7 | Verify that weekends are visually distinct from weekdays | Weekend days (Saturday and Sunday) are highlighted with different background color or styling |
| 8 | Verify that company holidays are visually distinct | Company holidays are marked with special indicators or different styling from regular days |

**Postconditions:**
- Employee remains logged in to the portal
- Monthly schedule view is displayed
- No data has been modified in the system
- Navigation history is maintained

---

### Test Case: Verify access control for monthly schedule
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Two employee accounts exist in the system (Employee A and Employee B)
- Employee A is logged into the portal
- Employee B has scheduled shifts in the database
- Authorization and authentication mechanisms are active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in as Employee A with valid credentials | Employee A is successfully authenticated and logged into the portal |
| 2 | Navigate to the monthly schedule view | Employee A's monthly schedule is displayed correctly |
| 3 | Attempt to access Employee B's monthly schedule by manipulating URL parameters or using direct API endpoint with Employee B's ID | Access is denied with an appropriate error message such as 'Unauthorized access' or 'You do not have permission to view this schedule' |
| 4 | Verify that Employee A's schedule view remains unchanged and only shows their own data | Only Employee A's schedule data is visible, no data from Employee B is displayed |
| 5 | Check system logs for unauthorized access attempt | Security event is logged indicating unauthorized access attempt |

**Postconditions:**
- Employee A remains logged in with access only to their own schedule
- Employee B's schedule data remains secure and inaccessible to Employee A
- Security logs contain record of access attempt
- No unauthorized data exposure occurred

---

### Test Case: Test monthly schedule loading performance
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee account exists with valid credentials
- Employee has a full month of scheduled shifts (at least 20 shifts)
- Network connection is stable
- Performance monitoring tools are available to measure load time
- Browser cache is cleared to ensure accurate timing

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Clear browser cache and cookies | Browser cache is cleared successfully |
| 2 | Log in to the employee portal with valid credentials | Employee is successfully authenticated and logged in |
| 3 | Start performance timer and navigate to the monthly schedule view | Monthly schedule view begins loading |
| 4 | Measure the time from clicking monthly schedule view until the complete calendar with all shift indicators is fully rendered and interactive | Monthly schedule loads completely within 4 seconds, all shift indicators are visible, calendar is fully interactive |
| 5 | Record the actual load time | Load time is documented and is less than or equal to 4 seconds |
| 6 | Repeat the test by navigating to a different month and back to verify consistent performance | Subsequent loads also complete within 4 seconds |

**Postconditions:**
- Monthly schedule is fully loaded and functional
- Performance metrics are recorded
- Employee remains logged in
- System performance meets the 4-second requirement

---

## Story: As Employee, I want to filter my schedule by shift type to quickly find relevant shifts
**Story ID:** story-13

### Test Case: Validate shift type filtering in schedule views
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Employee account exists with valid credentials
- Employee has multiple shifts assigned with different shift types (morning, evening, night)
- Employee is logged into the portal
- Schedule view (daily, weekly, or monthly) is accessible
- Shift type filter options are configured in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the employee portal and log in with valid credentials | Employee is successfully logged in and dashboard is displayed |
| 2 | Navigate to the schedule view section | Schedule view is displayed showing all scheduled shifts with shift type filter options visible |
| 3 | Verify that shift type filter dropdown or options are available | Shift type filter control is visible with options such as 'Morning', 'Evening', 'Night', or other configured shift types |
| 4 | Note the total number of shifts displayed before applying any filter | All shifts across all shift types are visible in the schedule view |
| 5 | Select 'Morning' shift type from the filter options | Schedule view updates dynamically to display only morning shifts, other shift types are hidden, shift count decreases to show only morning shifts |
| 6 | Verify that only morning shifts are displayed in the filtered view | All visible shifts are confirmed to be morning shift type, no evening or night shifts are shown |
| 7 | Change the filter selection to 'Evening' shift type | Schedule view updates to display only evening shifts, morning shifts are no longer visible |
| 8 | Verify that only evening shifts are displayed | All visible shifts are confirmed to be evening shift type |
| 9 | Click the 'Clear filter' button or select 'All shifts' option | Schedule view updates to display all shifts regardless of shift type, total shift count matches the original unfiltered count |
| 10 | Verify that all shift types are now visible in the schedule | Morning, evening, and night shifts are all displayed, filter is successfully cleared |

**Postconditions:**
- Employee remains logged in
- Schedule view displays all shifts with filter cleared
- Filter functionality is ready for subsequent use
- No data has been modified

---

### Test Case: Test performance of filtered schedule retrieval
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Employee account exists with valid credentials
- Employee has a large dataset of shifts (minimum 50 shifts) with various shift types
- Employee is logged into the portal
- Performance monitoring tools are available
- Network connection is stable
- Browser cache is cleared

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Clear browser cache and cookies | Browser cache is successfully cleared |
| 2 | Log in to the employee portal with valid credentials | Employee is successfully authenticated and logged in |
| 3 | Navigate to the schedule view section | Schedule view is displayed with all shifts visible |
| 4 | Start performance timer and select a shift type filter (e.g., 'Morning') | Filter selection is registered and filtering process begins |
| 5 | Measure the time from applying the filter until the filtered schedule is completely rendered and interactive | Filtered schedule loads and displays within 2 seconds, only selected shift type is shown, schedule is fully interactive |
| 6 | Record the actual load time for the filtered results | Load time is documented and is less than or equal to 2 seconds |
| 7 | Apply a different shift type filter (e.g., 'Evening') and measure performance again | Second filter application also completes within 2 seconds |
| 8 | Clear the filter and measure the time to return to unfiltered view | Clearing filter and displaying all shifts completes within 2 seconds |

**Postconditions:**
- Filtered schedule is fully loaded and functional
- Performance metrics are recorded and meet the 2-second requirement
- Employee remains logged in
- Schedule view is ready for further interactions

---

## Story: As Employee, I want to refresh my schedule view to see the latest updates
**Story ID:** story-14

### Test Case: Validate schedule refresh updates data correctly
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- Employee is logged into the system with valid credentials
- Employee has navigated to the schedule view
- Schedule data exists in the database
- Network connection is stable
- Backend API is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Verify that the refresh button is visible in the schedule view | Refresh button is displayed and enabled in the schedule view interface |
| 2 | Note the current schedule data displayed (shifts, times, dates) | Current schedule data is visible and documented for comparison |
| 3 | Click the refresh button in the schedule view | Loading indicator appears and refresh process initiates |
| 4 | Observe the schedule view during refresh | Schedule updates with latest data within 2 seconds without full page reload |
| 5 | Verify that the system displays a confirmation message | Success notification message is displayed confirming schedule has been refreshed |
| 6 | Compare the refreshed schedule data with the previously noted data | Schedule displays the most current data from the database, reflecting any recent changes |

**Postconditions:**
- Schedule view displays the latest data from the database
- Success confirmation message is visible to the user
- Employee remains logged in and authenticated
- UI is responsive and ready for further interactions

---

### Test Case: Test refresh failure handling
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee is logged into the system with valid credentials
- Employee has navigated to the schedule view
- Test environment allows simulation of backend failures
- Ability to disconnect or simulate API failure is available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Verify that the refresh button is visible in the schedule view | Refresh button is displayed and enabled in the schedule view interface |
| 2 | Simulate a backend failure (disconnect API, stop backend service, or use mock failure response) | Backend is unavailable or configured to return error response |
| 3 | Click the refresh button in the schedule view | Refresh request is initiated and attempts to fetch data from backend |
| 4 | Observe the system response to the failed refresh attempt | Error message is displayed to the user indicating refresh failed |
| 5 | Verify that the UI remains stable and functional | UI does not crash, freeze, or become unresponsive; previous schedule data remains visible |
| 6 | Verify that the error message is user-friendly and informative | Error message clearly communicates the failure and suggests possible actions (e.g., 'Unable to refresh schedule. Please try again later.') |
| 7 | Restore backend connectivity and click refresh button again | Schedule refreshes successfully and displays updated data with success confirmation |

**Postconditions:**
- UI remains stable without crashes or errors
- Employee remains logged in and authenticated
- Previous schedule data is still visible if refresh fails
- System is ready to retry refresh operation when backend is restored

---

## Story: As Employee, I want to view shift details including location and role to understand my assignments
**Story ID:** story-15

### Test Case: Validate display of shift location and role
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- Employee is logged into the system with valid credentials
- Employee has scheduled shifts in the database
- Shift data includes location and role information
- Employee has navigated to the schedule view
- Schedule view is fully loaded and displaying shifts

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Locate a scheduled shift in the schedule view | At least one shift is visible in the schedule view with basic information displayed |
| 2 | Select or click on the shift to view detailed information | Shift details interface opens (tooltip, modal, or expandable section) |
| 3 | Verify that shift location is displayed in the details | Shift location is clearly visible and accurately reflects the database information |
| 4 | Verify that assigned role is displayed in the details | Assigned role is clearly visible and accurately reflects the database information |
| 5 | Check if additional shift notes are present (if applicable) | If shift notes exist in the database, they are displayed; if not, no notes section appears or shows 'No notes available' |
| 6 | Verify the formatting and readability of the shift details | All shift details are well-formatted, easy to read, and properly labeled |
| 7 | Close the shift details view | Shift details close and schedule view returns to normal state |

**Postconditions:**
- Shift details are successfully displayed with location and role information
- Employee has viewed the necessary shift information
- Schedule view remains functional and responsive
- Employee remains logged in and authenticated

---

### Test Case: Verify access control for shift details
- **ID:** tc-004
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee is logged into the system with valid credentials
- Multiple employees exist in the system with their own schedules
- Another employee has scheduled shifts in the database
- Access control mechanisms are implemented in the system
- Employee has navigated to the schedule view

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Attempt to navigate to or access another employee's schedule view (via URL manipulation, direct link, or UI if available) | System detects unauthorized access attempt |
| 2 | Try to view shift details of another employee's shift | Access is denied by the system |
| 3 | Verify that an appropriate error message is displayed | Error message is shown indicating 'Access denied' or 'You do not have permission to view this shift' or similar security message |
| 4 | Verify that no sensitive shift details of the other employee are exposed | No location, role, or other shift details of another employee are visible to the logged-in employee |
| 5 | Confirm that the employee is redirected back to their own schedule or appropriate page | Employee is redirected to their own schedule view or remains on a safe page without unauthorized data |
| 6 | Verify that the employee's session remains active and authenticated | Employee remains logged in and can continue to access their own schedule normally |

**Postconditions:**
- Access to other employees' shift details is successfully blocked
- Appropriate error message has been displayed
- No unauthorized data has been exposed
- Employee remains logged in and can access their own schedule
- Security audit log records the unauthorized access attempt (if logging is implemented)

---

