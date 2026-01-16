# Manual Test Cases

## Story: As Employee, I want to filter my schedule by shift type to focus on relevant work periods
**Story ID:** story-9

### Test Case: Validate filtering by single shift type
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee is logged into the system with valid credentials
- Employee has an active schedule with multiple shift types (Morning, Evening, Night)
- Employee is on the schedule view page
- Schedule contains at least one Morning shift and one non-Morning shift
- Browser supports dynamic content updates

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule view page | Schedule view page loads successfully displaying all shifts for the employee |
| 2 | Locate and click on the shift type filter dropdown/option | Filter options panel opens showing available shift types (Morning, Evening, Night) |
| 3 | Select 'Morning' shift type from the filter options | Morning shift type is selected and highlighted in the filter interface |
| 4 | Observe the schedule display update | Schedule updates dynamically without page reload to show only Morning shifts. All Evening and Night shifts are hidden. Filter response time is under 2 seconds |
| 5 | Verify that only Morning shifts are displayed in the schedule | All displayed shifts have shift type 'Morning'. No Evening or Night shifts are visible |
| 6 | Click the 'Clear filter' button or option | Clear filter action is triggered and filter selection is removed |
| 7 | Observe the schedule display after clearing filter | Full schedule is displayed showing all shift types (Morning, Evening, Night). Schedule returns to default view without page reload |

**Postconditions:**
- Schedule view displays all shifts without any filters applied
- Filter interface is reset to default state
- Employee remains logged in and on the schedule view page
- No error messages are displayed

---

### Test Case: Validate filtering by multiple shift types
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Employee is logged into the system with valid credentials
- Employee has an active schedule with multiple shift types (Morning, Evening, Night)
- Employee is on the schedule view page
- Schedule contains at least one Morning shift, one Evening shift, and one Night shift
- Multi-select filter functionality is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule view page | Schedule view page loads successfully displaying all shifts for the employee |
| 2 | Locate and click on the shift type filter dropdown/option | Filter options panel opens showing available shift types with multi-select capability |
| 3 | Select 'Morning' shift type from the filter options | Morning shift type is selected and highlighted. Filter remains open for additional selections |
| 4 | Select 'Evening' shift type from the filter options while Morning is still selected | Both Morning and Evening shift types are selected and highlighted in the filter interface |
| 5 | Apply the filter or observe automatic update | Schedule updates dynamically without page reload to show shifts matching either Morning or Evening type |
| 6 | Verify that only Morning and Evening shifts are displayed | All displayed shifts have shift type 'Morning' or 'Evening'. Night shifts are hidden. Filter response time is under 2 seconds |
| 7 | Count the total number of shifts displayed and verify against expected count | Total number of displayed shifts equals the sum of Morning and Evening shifts in the employee's schedule |

**Postconditions:**
- Schedule view displays only Morning and Evening shifts
- Filter interface shows both Morning and Evening as selected
- Employee remains logged in and on the schedule view page
- Night shifts remain in the database but are filtered from view

---

### Test Case: Test handling of invalid shift type filter
- **ID:** tc-003
- **Type:** error-case
- **Priority:** Medium
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee is logged into the system with valid credentials
- Employee has an active schedule with shifts
- Employee has access to browser URL bar or developer tools
- System has validation rules for shift type parameters
- Valid shift types are: Morning, Evening, Night

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule view page | Schedule view page loads successfully displaying all shifts for the employee |
| 2 | Note the current URL in the browser address bar | URL is visible and follows the pattern /api/schedules?employeeId={id} |
| 3 | Manually modify the URL to include an invalid shift type parameter (e.g., /api/schedules?employeeId={id}&shiftType=InvalidType) | Modified URL is entered in the address bar |
| 4 | Press Enter to navigate to the modified URL | System processes the request with invalid shift type parameter |
| 5 | Observe the system response and error handling | System returns a validation error message indicating invalid shift type. Error message is clear and user-friendly (e.g., 'Invalid shift type. Please select from: Morning, Evening, Night') |
| 6 | Verify the schedule display after validation error | System defaults to full schedule view showing all shifts without any filter applied. No shifts are incorrectly filtered or hidden |
| 7 | Verify that the filter interface is in default state | No shift type filters are selected. Filter dropdown shows default/unselected state |

**Postconditions:**
- Schedule displays all shifts in default view
- Validation error message is displayed to the user
- No invalid data is processed or stored
- Employee remains logged in and can continue using the system
- System logs the validation error for security monitoring

---

## Story: As Employee, I want to search my schedule by date to quickly find shifts on specific days
**Story ID:** story-10

### Test Case: Validate successful search by valid date
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee is logged into the system with valid credentials
- Employee has an active schedule with shifts on multiple dates
- Employee is on the schedule page
- At least one shift exists for the date to be searched
- Date picker or search field is visible and functional
- System accepts date format YYYY-MM-DD or MM/DD/YYYY

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule page | Schedule page loads successfully displaying the employee's full schedule |
| 2 | Locate the date search field or date picker input | Date search field is visible and enabled for input |
| 3 | Click on the date search field to activate it | Date search field is focused and ready for input. Date picker calendar may appear if applicable |
| 4 | Enter a valid date that has scheduled shifts (e.g., 2024-03-15 or 03/15/2024) | Date is entered successfully in the search field. Date format is accepted by the system |
| 5 | Press Enter or click the Search button to execute the search | Search request is submitted to the system |
| 6 | Observe the schedule display update | Schedule updates dynamically without page reload to show only shifts for the searched date. Search response time is under 2 seconds |
| 7 | Verify that only shifts for the searched date are displayed | All displayed shifts have the date matching the searched date. Shifts from other dates are hidden. Shift details (time, type, location) are accurate |
| 8 | Locate and click the 'Clear search' button or option | Clear search action is triggered |
| 9 | Observe the schedule display after clearing search | Full schedule view is restored showing all shifts across all dates. Schedule updates dynamically without page reload. Date search field is cleared |

**Postconditions:**
- Schedule view displays all shifts without any search filters applied
- Date search field is empty and ready for new input
- Employee remains logged in and on the schedule page
- No error messages are displayed
- System state is reset to default schedule view

---

### Test Case: Validate rejection of invalid date input
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- Employee is logged into the system with valid credentials
- Employee is on the schedule page
- Date search field is visible and functional
- System has date format validation rules in place
- Expected valid date formats are documented (e.g., YYYY-MM-DD, MM/DD/YYYY)

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule page | Schedule page loads successfully displaying the employee's full schedule |
| 2 | Locate the date search field | Date search field is visible and enabled for input |
| 3 | Click on the date search field to activate it | Date search field is focused and ready for input |
| 4 | Enter an invalid date format (e.g., '32/13/2024', 'invalid-date', '2024-13-45', or 'abc123') | Invalid date string is entered in the search field |
| 5 | Press Enter or click the Search button to attempt the search | System validates the date input |
| 6 | Observe the system response to invalid date input | System displays a clear error message indicating invalid date format (e.g., 'Invalid date format. Please use YYYY-MM-DD or MM/DD/YYYY'). Error message is displayed near the search field or in a notification area |
| 7 | Verify that the search was not performed | Schedule display remains unchanged showing the full schedule. No API call is made to search with invalid date. Search field retains the invalid input for user correction |
| 8 | Verify that the schedule data is still accessible | Full schedule remains visible and functional. No data loss or corruption occurred |

**Postconditions:**
- Error message is displayed to the user
- Schedule displays full schedule without any search applied
- Invalid date input remains in the search field for correction
- Employee remains logged in and can continue using the system
- No invalid search is logged or processed
- System is ready to accept corrected date input

---

### Test Case: Test access control on search results
- **ID:** tc-006
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Employee is logged into the system with valid credentials
- Employee has a known employee ID (e.g., employeeId=123)
- Another employee exists in the system with a different ID (e.g., employeeId=456)
- Employee is on the schedule page
- Employee has access to browser URL bar or developer tools
- System has authentication and authorization controls in place

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule page | Schedule page loads successfully displaying the logged-in employee's schedule |
| 2 | Note the current URL in the browser address bar (e.g., /api/schedules?employeeId=123&date=2024-03-15) | URL is visible and contains the logged-in employee's ID |
| 3 | Manually modify the URL to change the employeeId parameter to another employee's ID (e.g., /api/schedules?employeeId=456&date=2024-03-15) | Modified URL with different employee ID is entered in the address bar |
| 4 | Press Enter to navigate to the modified URL | System processes the request with unauthorized employee ID |
| 5 | Observe the system response to unauthorized access attempt | System detects authorization violation and denies access. Access denied error message is displayed (e.g., 'Access Denied: You are not authorized to view this employee's schedule' or HTTP 403 Forbidden) |
| 6 | Verify that no schedule data for the other employee is displayed | No shifts or schedule information for the unauthorized employee ID is shown. Other employee's data remains protected and inaccessible |
| 7 | Verify redirection or error page display | User is either redirected back to their own schedule page or shown an error page. Logged-in employee's own schedule may be displayed, or a blank schedule with error message |
| 8 | Check that the session remains valid | Employee remains logged in. Session is not terminated due to authorization failure |

**Postconditions:**
- Access denied error is displayed to the user
- No unauthorized schedule data is exposed
- Employee is redirected to their own schedule or error page
- Employee remains logged in with valid session
- Security event is logged for audit purposes
- System maintains data privacy and access control integrity

---

