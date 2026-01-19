# Manual Test Cases

## Story: As Employee, I want to filter my schedule by shift type to quickly find relevant shifts
**Story ID:** story-9

### Test Case: Validate filtering by single shift type
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee is logged into the system with valid credentials
- Employee has access to the schedule section
- Schedule contains shifts of multiple types (Morning, Afternoon, Night, etc.)
- At least one Morning shift exists in the employee's schedule
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule section from the main dashboard | Schedule section loads successfully displaying all assigned shifts |
| 2 | Locate and click on the filter panel or filter icon | Filter panel opens showing available shift type options |
| 3 | Select 'Morning' shift type from the available filter options | 'Morning' shift type is highlighted/selected in the filter panel |
| 4 | Click 'Apply' or confirm the filter selection | Schedule refreshes and displays only shifts with 'Morning' shift type. All other shift types are hidden from view |
| 5 | Verify the filtered results show only Morning shifts | All displayed shifts are confirmed to be Morning shifts. No Afternoon, Night, or other shift types are visible |
| 6 | Click the 'Clear filter' button or option | Filter is removed and schedule refreshes to display all shifts regardless of type |
| 7 | Verify all shifts are now visible | Schedule displays all shift types (Morning, Afternoon, Night, etc.) that were previously assigned |

**Postconditions:**
- Filter is cleared and no filters are active
- Schedule displays all shifts in their original state
- System is ready for next filter operation

---

### Test Case: Validate filtering by multiple shift types
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Employee is logged into the system with valid credentials
- Employee has access to the schedule section
- Schedule contains shifts of multiple types including Morning and Night shifts
- At least one Morning shift and one Night shift exist in the employee's schedule
- Filter panel supports multi-select functionality
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule section from the main dashboard | Schedule section loads successfully displaying all assigned shifts |
| 2 | Open the filter panel by clicking on the filter icon or button | Filter panel opens showing all available shift type options with multi-select capability |
| 3 | Select 'Morning' shift type from the filter options | 'Morning' shift type is highlighted/checked indicating selection |
| 4 | Select 'Night' shift type from the filter options while keeping 'Morning' selected | Both 'Morning' and 'Night' shift types are highlighted/checked indicating multiple selections are active |
| 5 | Click 'Apply' button to apply the multiple filters | Schedule refreshes and displays only shifts that are either 'Morning' or 'Night' shift types |
| 6 | Verify the filtered results contain only Morning and Night shifts | All displayed shifts are confirmed to be either Morning or Night shifts. No Afternoon or other shift types are visible in the schedule |
| 7 | Scroll through the filtered schedule to confirm consistency | All visible shifts throughout the schedule are either Morning or Night type with no exceptions |

**Postconditions:**
- Schedule displays only Morning and Night shifts
- Filter remains active showing selected shift types
- Other shift types remain hidden until filter is cleared

---

### Test Case: Verify filter performance under 2 seconds
- **ID:** tc-003
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Employee is logged into the system with valid credentials
- Employee has access to the schedule section
- Large dataset of schedule shifts is available (minimum 500+ shifts across multiple months)
- Performance monitoring tool or browser developer tools are available to measure response time
- Network connectivity is stable with normal bandwidth
- System is under normal load conditions

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule section containing the large dataset | Schedule section loads displaying the large dataset of shifts |
| 2 | Open browser developer tools and navigate to the Network tab to monitor API calls | Network monitoring is active and ready to capture API response times |
| 3 | Open the filter panel | Filter panel opens showing available shift type options |
| 4 | Note the current timestamp or start the performance timer | Timer is ready to measure the filter operation duration |
| 5 | Select a shift type filter (e.g., 'Morning') and click Apply | Filter request is sent to the server and processing begins |
| 6 | Monitor the API call to GET /api/schedules?shiftType={type} in the Network tab | API request is visible in Network tab with response time metrics |
| 7 | Measure the total time from clicking Apply until filtered results are fully displayed on screen | Filtered results are displayed and total response time is recorded |
| 8 | Verify the measured response time is under 2 seconds | Total time from filter application to results display is less than 2 seconds (meeting the performance requirement) |
| 9 | Repeat the test with different shift type filters to ensure consistent performance | All filter operations complete within 2 seconds regardless of shift type selected |

**Postconditions:**
- Filter performance meets the 2-second requirement
- Filtered results are accurately displayed
- System performance metrics are documented
- Schedule remains functional after performance test

---

## Story: As Employee, I want to search my schedule by date to quickly locate specific shifts
**Story ID:** story-11

### Test Case: Validate search by single date
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee is logged into the system with valid credentials
- Employee has access to the schedule section
- Schedule contains shifts across multiple dates
- At least one shift exists on the target search date
- Search panel is accessible from the schedule view
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule section from the main dashboard | Schedule section loads successfully displaying all assigned shifts across various dates |
| 2 | Locate and click on the search panel or search icon | Search panel opens displaying date input field(s) and calendar picker option |
| 3 | Click on the date input field to activate the calendar picker | Calendar picker interface opens showing current month and selectable dates |
| 4 | Select a valid date (e.g., '2024-03-15') from the calendar picker that has scheduled shifts | Selected date appears in the date input field in the correct format |
| 5 | Click 'Search' or 'Submit' button to execute the search | Search request is processed and schedule view refreshes |
| 6 | Verify the displayed schedule shows only shifts for the selected date | Schedule displays only shifts scheduled for the searched date (2024-03-15). No shifts from other dates are visible |
| 7 | Check that all displayed shifts match the searched date | All visible shift entries show the date '2024-03-15' confirming accurate search results |
| 8 | Verify the shift count matches expected number for that date | Number of displayed shifts corresponds to the actual shifts scheduled for that specific date |

**Postconditions:**
- Schedule displays only shifts for the searched date
- Search criteria remains active in the search panel
- Other dates' shifts are hidden from view
- Search can be cleared to restore full schedule view

---

### Test Case: Validate search by date range
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Employee is logged into the system with valid credentials
- Employee has access to the schedule section
- Schedule contains shifts across multiple dates
- Shifts exist within the target date range to be searched
- Search panel supports date range input (start date and end date)
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule section from the main dashboard | Schedule section loads successfully displaying all assigned shifts |
| 2 | Open the search panel by clicking the search icon or button | Search panel opens showing separate input fields for start date and end date with calendar picker options |
| 3 | Click on the 'Start Date' input field | Calendar picker opens for start date selection |
| 4 | Select a valid start date (e.g., '2024-03-01') from the calendar | Start date '2024-03-01' appears in the start date input field |
| 5 | Click on the 'End Date' input field | Calendar picker opens for end date selection |
| 6 | Select a valid end date (e.g., '2024-03-15') that is after the start date | End date '2024-03-15' appears in the end date input field |
| 7 | Verify both start and end dates are correctly displayed in the search panel | Search panel shows Start Date: 2024-03-01 and End Date: 2024-03-15 |
| 8 | Click 'Search' or 'Submit' button to execute the date range search | Search request is processed and schedule view refreshes with filtered results |
| 9 | Verify the schedule displays only shifts within the specified date range | Schedule displays all shifts with dates between 2024-03-01 and 2024-03-15 (inclusive). No shifts outside this range are visible |
| 10 | Scroll through the results and verify date boundaries | All displayed shifts have dates >= 2024-03-01 and <= 2024-03-15. No shifts from February or after March 15 are shown |
| 11 | Verify the total count of shifts matches expected shifts within the date range | Number of displayed shifts corresponds to all shifts scheduled between the start and end dates |

**Postconditions:**
- Schedule displays only shifts within the specified date range
- Search criteria (start and end dates) remain visible in search panel
- Shifts outside the date range are hidden
- Search can be modified or cleared as needed

---

### Test Case: Verify error handling for invalid date input
- **ID:** tc-006
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Employee is logged into the system with valid credentials
- Employee has access to the schedule section
- Search panel is accessible and functional
- System has validation rules for date format
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule section from the main dashboard | Schedule section loads successfully displaying all assigned shifts |
| 2 | Open the search panel by clicking the search icon or button | Search panel opens with date input field(s) ready for input |
| 3 | Click on the date input field to enable manual text entry (bypass calendar picker if possible) | Date input field is active and accepts keyboard input |
| 4 | Enter an invalid date format such as '32/13/2024' (invalid day and month) | Invalid date text appears in the input field |
| 5 | Click 'Search' or 'Submit' button to attempt the search | System validates the input and detects the invalid date format |
| 6 | Verify that an error message is displayed | Clear error message appears stating 'Invalid date format. Please enter a valid date.' or similar user-friendly message |
| 7 | Verify that the search operation is blocked | Search is not executed. Schedule view remains unchanged showing all shifts |
| 8 | Test with another invalid format such as 'abc123' (non-date characters) | Error message is displayed again and search is blocked |
| 9 | Test with invalid date value like '2024-02-30' (February 30th does not exist) | Error message is displayed indicating invalid date value and search is blocked |
| 10 | Clear the invalid input and enter a valid date format | Error message disappears and valid date is accepted in the input field |
| 11 | Verify that search can now proceed with valid date | Search button is enabled and search executes successfully with valid date input |

**Postconditions:**
- Invalid date inputs are rejected with appropriate error messages
- Schedule view is not affected by invalid search attempts
- System validation is functioning correctly
- User can correct the input and proceed with valid search

---

