# Manual Test Cases

## Story: As Employee, I want to filter my schedule by shift type to focus on relevant shifts
**Story ID:** story-14

### Test Case: Validate filtering by single shift type
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee account exists and is active in the system
- Employee is logged into the application
- Employee has multiple shifts of different types assigned in their schedule
- Schedule page is accessible and loads successfully
- At least one predefined shift type exists in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule page from the main dashboard | Schedule page loads displaying all assigned shifts for the employee |
| 2 | Locate the shift type filter control on the schedule page | Shift type filter dropdown/selector is visible and accessible |
| 3 | Click on the shift type filter control to view available shift types | List of predefined shift types is displayed (e.g., Morning, Evening, Night, Weekend) |
| 4 | Select a specific shift type from the filter options | Selected shift type is highlighted or marked as active in the filter control |
| 5 | Observe the schedule display update | Schedule updates dynamically without full page reload to show only shifts matching the selected type within 3 seconds |
| 6 | Verify that only shifts of the selected type are displayed | All displayed shifts match the selected shift type; shifts of other types are hidden |
| 7 | Locate and click the 'Clear filter' button or option | Clear filter option is visible and clickable |
| 8 | Observe the schedule display after clearing the filter | Full schedule is displayed again showing all shifts of all types without page reload |

**Postconditions:**
- Employee remains logged in
- Schedule displays all shifts without any active filters
- Filter control is reset to default state
- No error messages are displayed
- System state is ready for next filter operation

---

### Test Case: Verify rejection of invalid shift type filter
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- Employee account exists and is active in the system
- Employee is logged into the application
- Employee has access to the schedule page
- Schedule page is loaded and displaying shifts
- System has validation rules for shift type inputs

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule page | Schedule page loads successfully with all assigned shifts visible |
| 2 | Locate the shift type filter input field or control | Shift type filter control is visible and accessible |
| 3 | Attempt to input an invalid shift type (e.g., 'InvalidType123', special characters, or non-existent shift type) | System accepts the input for validation processing |
| 4 | Submit or apply the invalid shift type filter | System validates the input and detects it as invalid |
| 5 | Observe the system response | Clear error message is displayed indicating the shift type is invalid (e.g., 'Invalid shift type. Please select from available options.') |
| 6 | Verify that the filter was not applied to the schedule | Schedule remains unchanged showing all shifts; invalid filter is not applied |
| 7 | Verify the filter control state | Filter control remains in its previous valid state or is cleared |

**Postconditions:**
- Employee remains logged in
- Schedule displays all shifts without invalid filter applied
- Error message is visible to guide the user
- System remains stable with no crashes or unexpected behavior
- Filter control is ready for valid input

---

## Story: As Employee, I want to search my schedule by date to quickly find specific shifts
**Story ID:** story-15

### Test Case: Validate search by valid date
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee account exists and is active in the system
- Employee is logged into the application
- Employee has shifts scheduled on various dates
- Schedule page is accessible and functional
- Date search functionality is enabled
- At least one shift exists on the date to be searched

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule page from the main menu or dashboard | Schedule page loads successfully displaying all assigned shifts |
| 2 | Locate the date search field on the schedule page | Date search input field is visible and accessible with placeholder text indicating expected format (YYYY-MM-DD) |
| 3 | Click on the date search field to activate it | Search field is focused and ready for input; cursor appears in the field |
| 4 | Enter a valid date in the correct format YYYY-MM-DD (e.g., '2024-03-15') that has scheduled shifts | Date is entered successfully in the search field and displayed correctly |
| 5 | Submit the search by pressing Enter or clicking the search button | Search request is initiated and processed |
| 6 | Observe the schedule display update | Schedule updates dynamically without full page reload to show only shifts scheduled on the entered date within 3 seconds |
| 7 | Verify that only shifts matching the searched date are displayed | All displayed shifts have the date matching the search criteria; shifts on other dates are hidden |
| 8 | Locate and click the clear search button or delete the date from the search field | Clear search option is available and functional |
| 9 | Observe the schedule after clearing the search | Full schedule is displayed showing all shifts across all dates without page reload |

**Postconditions:**
- Employee remains logged in
- Schedule displays all shifts without any active search filters
- Search field is cleared and ready for new input
- No error messages are displayed
- System is ready for subsequent search operations

---

### Test Case: Verify rejection of invalid date input
- **ID:** tc-004
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- Employee account exists and is active in the system
- Employee is logged into the application
- Schedule page is loaded and accessible
- Date search field is visible and functional
- System has date format validation implemented (YYYY-MM-DD)

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule page | Schedule page loads successfully with all shifts displayed |
| 2 | Locate the date search input field | Date search field is visible and accessible |
| 3 | Click on the date search field to activate it | Search field is focused and ready for input |
| 4 | Enter an invalid date format (e.g., 'DD/MM/YYYY' as '15/03/2024', 'MM-DD-YYYY', 'invalid-date', or '2024-13-45') | Invalid date input is entered in the search field |
| 5 | Attempt to submit the search by pressing Enter or clicking the search button | System validates the date format |
| 6 | Observe the system response to the invalid input | Clear error message is displayed indicating invalid date format (e.g., 'Invalid date format. Please use YYYY-MM-DD format.') |
| 7 | Verify that the search was not performed | Schedule remains unchanged showing all shifts; invalid search is not executed |
| 8 | Verify the search field state | Search field either retains the invalid input for correction or is cleared, with error message still visible |

**Postconditions:**
- Employee remains logged in
- Schedule displays all shifts without invalid search applied
- Error message is visible providing guidance on correct format
- System remains stable with no crashes
- Search field is ready for valid date input

---

