# Manual Test Cases

## Story: As Employee, I want to filter my schedule by shift type to focus on relevant shifts
**Story ID:** story-14

### Test Case: Validate shift type filter application
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee account exists and is active in the system
- Employee is logged into the portal with valid credentials
- Employee has multiple shifts assigned with different shift types (morning, afternoon, night)
- Employee is on the schedule view page
- Shift type filter options are visible and accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Locate the shift type filter dropdown/checkbox section on the schedule view | Shift type filter options (Morning, Afternoon, Night) are displayed and available for selection |
| 2 | Click or select the 'Morning' shift filter option | The 'Morning' filter is visually marked as selected (checked/highlighted) and the schedule view updates within 2 seconds to display only shifts with shift type 'Morning'. All other shift types are hidden from view |
| 3 | While 'Morning' filter is still active, click or select the 'Night' shift filter option in addition to the existing selection | Both 'Morning' and 'Night' filters are visually marked as selected. The schedule view updates within 2 seconds to display shifts with shift types 'Morning' and 'Night' only. Afternoon shifts remain hidden |
| 4 | Click the 'Clear filters' button or deselect all active shift type filters | All shift type filters are deselected/unchecked. The schedule view updates within 2 seconds to display the full schedule showing all shift types (Morning, Afternoon, and Night shifts) |

**Postconditions:**
- All filters are cleared and the full schedule is displayed
- The schedule view shows all shift types without any active filters
- The system is ready for the next filter operation
- No error messages are displayed

---

### Test Case: Test filter persistence during navigation
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- Employee account exists and is active in the system
- Employee is logged into the portal with valid credentials
- Employee has shifts scheduled across multiple weeks
- Employee is on the schedule view page showing the current week
- Shift type filter options are visible and accessible
- Schedule navigation controls (next week/previous week) are available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Select the 'Morning' shift type filter from the available filter options | The 'Morning' filter is marked as selected and the schedule view updates within 2 seconds to display only morning shifts for the current week |
| 2 | Verify the filtered schedule is displaying correctly with only morning shifts visible | Only shifts with shift type 'Morning' are displayed in the schedule view. Other shift types are not visible |
| 3 | Click the 'Next Week' navigation button or arrow to move to the following week's schedule | The schedule view navigates to the next week and the 'Morning' filter remains active (still visually selected). The schedule displays only morning shifts for the next week within 2 seconds |
| 4 | Verify the filter state is maintained and the correct filtered data is displayed for the new week | The 'Morning' filter indicator remains selected/highlighted. Only morning shifts for the next week are displayed. The filter has persisted through the navigation action |

**Postconditions:**
- The shift type filter remains active after navigation
- The schedule displays the next week with the filter still applied
- The filter state is maintained in the system session
- The employee can continue navigating with the filter active or clear it as needed

---

## Story: As Employee, I want to search my schedule by date to quickly find specific shifts
**Story ID:** story-15

### Test Case: Validate schedule search with valid date
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee account exists and is active in the system
- Employee is logged into the portal with valid credentials
- Employee has shifts scheduled on various dates
- Employee is on the schedule view page
- Date search field/date picker is visible and accessible
- At least one shift exists on the date that will be searched

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Locate the date search field or date picker input on the schedule page | The date search field or date picker is displayed and ready for input |
| 2 | Enter a valid date in the correct format (e.g., MM/DD/YYYY or select from date picker) for a date that has scheduled shifts | The date is accepted and displayed in the search field without any validation errors |
| 3 | Submit the search by clicking the search button or pressing Enter | The system processes the search within 2 seconds and displays only the shifts scheduled for the entered date. The schedule view updates to show the search results with shift details (time, type, location) for that specific date |
| 4 | Verify that only shifts for the searched date are displayed and belong to the logged-in employee | All displayed shifts match the searched date and are assigned to the logged-in employee only. No shifts from other dates or other employees are shown |
| 5 | Click the 'Clear search' button or clear the date input field | The date search field is cleared and the schedule view returns to the full schedule display showing all upcoming shifts across all dates |

**Postconditions:**
- The search is cleared and the full schedule view is restored
- The date search field is empty and ready for a new search
- All employee shifts are visible in the default schedule view
- No error messages are displayed

---

### Test Case: Verify handling of invalid date input
- **ID:** tc-004
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Employee account exists and is active in the system
- Employee is logged into the portal with valid credentials
- Employee is on the schedule view page
- Date search field/date picker is visible and accessible
- System has defined valid date format requirements

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Locate the date search field on the schedule page | The date search field is displayed and ready for input |
| 2 | Enter an invalid date format in the search field (e.g., '99/99/9999', 'abc123', '13/45/2024', or other malformed date) | The system detects the invalid date format |
| 3 | Attempt to submit the search by clicking the search button or pressing Enter | The search is blocked and not executed. A clear error message is displayed indicating 'Invalid date format. Please enter a valid date (MM/DD/YYYY)' or similar. The schedule view remains unchanged |
| 4 | Clear the invalid input and enter a valid date that is outside the employee's schedule range (e.g., a date far in the past before employment or far in the future beyond scheduled shifts) | The date format is accepted as valid |
| 5 | Submit the search for the out-of-range date | The system processes the search within 2 seconds and displays an informative message 'No shifts found for the selected date' or similar. The message is clear and non-technical. No error styling is shown, just an informational message |
| 6 | Verify that the schedule view shows the 'No shifts found' message without displaying any shift data | The schedule area displays only the informative message. No shifts are shown. The interface remains functional and the employee can perform another search |

**Postconditions:**
- The system has properly validated and handled invalid date inputs
- Appropriate error or informational messages were displayed
- The schedule view remains stable without crashes or unexpected behavior
- The date search field is ready for new valid input

---

