# Manual Test Cases

## Story: As Employee, I want to filter my schedule by shift type to focus on relevant work periods
**Story ID:** story-14

### Test Case: Validate schedule filtering by single shift type
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee account exists and is active in the system
- Employee is logged into the application
- Employee has multiple shift types scheduled (Morning, Evening, Night)
- Schedule section is accessible and contains shift data
- Filter options are visible on the schedule page

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule section from the main dashboard | Schedule page loads successfully displaying all scheduled shifts with various shift types |
| 2 | Locate the shift type filter control on the schedule page | Filter control is visible and displays all available shift type options (Morning, Evening, Night, etc.) |
| 3 | Select 'Morning' from the shift type filter options | Filter is applied and schedule view updates within 2 seconds to display only shifts with 'Morning' shift type |
| 4 | Verify that only morning shifts are displayed in the schedule view | All displayed shifts are of type 'Morning' and no other shift types are visible |
| 5 | Note the number of shifts displayed after filtering | Count of displayed shifts matches the expected number of morning shifts |
| 6 | Click the 'Clear filter' button or deselect the 'Morning' filter | Filter is removed and full schedule is restored within 2 seconds showing all shift types |
| 7 | Verify that all shift types are now visible in the schedule | Schedule displays all shifts including Morning, Evening, Night, and any other shift types |

**Postconditions:**
- Employee remains logged in
- Schedule view displays full unfiltered schedule
- Filter state is cleared
- System is ready for next operation

---

### Test Case: Validate schedule filtering by multiple shift types
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Employee account exists and is active in the system
- Employee is logged into the application
- Employee has multiple shift types scheduled including Morning, Evening, and Night shifts
- Schedule section is accessible and contains shift data
- Filter options support multiple selections

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule section from the main dashboard | Schedule page loads successfully displaying all scheduled shifts |
| 2 | Locate the shift type filter control on the schedule page | Filter control is visible with all available shift type options |
| 3 | Select 'Morning' from the shift type filter options | 'Morning' filter is applied and visually indicated as selected |
| 4 | While keeping 'Morning' selected, also select 'Evening' from the shift type filter options | Both 'Morning' and 'Evening' filters are applied and visually indicated as selected |
| 5 | Observe the schedule view update | Schedule updates within 2 seconds to display shifts matching either 'Morning' OR 'Evening' shift types |
| 6 | Verify that only Morning and Evening shifts are displayed | All displayed shifts are either 'Morning' or 'Evening' type, and no Night or other shift types are visible |
| 7 | Count the total number of shifts displayed | Total count equals the sum of Morning shifts plus Evening shifts |

**Postconditions:**
- Employee remains logged in
- Multiple filters remain applied to the schedule view
- Schedule displays only Morning and Evening shifts
- System maintains filter state

---

### Test Case: Test no matching shifts message
- **ID:** tc-003
- **Type:** edge-case
- **Priority:** Medium
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee account exists and is active in the system
- Employee is logged into the application
- Employee has scheduled shifts but none of a specific shift type (e.g., no 'Weekend' shifts)
- Schedule section is accessible
- Filter options include shift types with no scheduled shifts

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule section from the main dashboard | Schedule page loads successfully displaying all currently scheduled shifts |
| 2 | Identify a shift type that has no scheduled shifts (e.g., 'Weekend' or 'Holiday') | Shift type option is available in the filter but employee has no shifts of this type |
| 3 | Select the shift type filter for which no shifts are scheduled | Filter is applied and schedule view updates within 2 seconds |
| 4 | Observe the schedule display area | Schedule area is empty with no shift entries displayed |
| 5 | Verify that a message is displayed to the user | System displays the message 'No shifts match the selected filters' or similar informative text |
| 6 | Verify that the message is clearly visible and appropriately positioned | Message is displayed in a prominent location within the schedule view area with appropriate styling |
| 7 | Clear the filter or select a different shift type with scheduled shifts | Schedule updates to show matching shifts or full schedule, and the 'no matches' message disappears |

**Postconditions:**
- Employee remains logged in
- Filter can be cleared or modified
- System correctly handles empty result sets
- User is informed when no data matches filter criteria

---

## Story: As Employee, I want to search my schedule by keyword to quickly find specific shifts or notes
**Story ID:** story-16

### Test Case: Validate schedule search with matching keyword
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Employee account exists and is active in the system
- Employee is logged into the application
- Employee has scheduled shifts with notes containing searchable keywords
- Schedule section is accessible and contains shift data with notes
- Search input field is visible on the schedule page

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule section from the main dashboard | Schedule page loads successfully displaying all scheduled shifts with their associated notes |
| 2 | Locate the search input field on the schedule page | Search input field is visible and accessible with placeholder text indicating search functionality |
| 3 | Identify a keyword that exists in one or more shift notes (e.g., 'training', 'meeting', 'urgent') | Keyword is confirmed to exist in at least one shift note in the current schedule |
| 4 | Click into the search input field and enter the identified keyword | Keyword is entered into the search field and is visible to the user |
| 5 | Observe the schedule view as the keyword is entered or after pressing Enter/Search | Schedule updates dynamically within 2 seconds to display only shifts containing the keyword in their notes |
| 6 | Verify that all displayed shifts contain the searched keyword in their notes | Each displayed shift has the keyword present in its notes field, and shifts without the keyword are hidden |
| 7 | Verify that the search supports partial matches by entering only part of a word | Schedule displays shifts where notes contain words that include the partial keyword |
| 8 | Test case-insensitive search by entering the keyword in different case (uppercase, lowercase, mixed) | Search results remain consistent regardless of the case used in the search input |
| 9 | Click the clear button (X) in the search input or delete all text from the search field | Search input is cleared and becomes empty |
| 10 | Observe the schedule view after clearing the search | Full schedule view is restored within 2 seconds showing all shifts regardless of notes content |

**Postconditions:**
- Employee remains logged in
- Search input is cleared
- Full schedule is displayed
- System is ready for next search operation

---

### Test Case: Validate schedule search with no matching keyword
- **ID:** tc-005
- **Type:** edge-case
- **Priority:** Medium
- **Estimated Time:** 6 mins

**Preconditions:**
- Employee account exists and is active in the system
- Employee is logged into the application
- Employee has scheduled shifts with notes
- Schedule section is accessible
- Search input field is visible on the schedule page

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule section from the main dashboard | Schedule page loads successfully displaying all scheduled shifts |
| 2 | Locate the search input field on the schedule page | Search input field is visible and accessible |
| 3 | Enter a keyword that does not exist in any shift notes (e.g., 'xyz123', 'nonexistent', random string) | Keyword is entered into the search field and is visible |
| 4 | Press Enter or trigger the search functionality | Search is executed and schedule view updates within 2 seconds |
| 5 | Observe the schedule display area | Schedule area is empty with no shift entries displayed |
| 6 | Verify that an appropriate message is displayed to the user | System displays the message 'No matching shifts found' or similar informative text |
| 7 | Verify that the message is clearly visible and user-friendly | Message is displayed prominently in the schedule view area with appropriate styling and clear wording |
| 8 | Verify that the search input still contains the entered keyword | Search input field retains the keyword allowing user to modify the search |
| 9 | Clear the search input by clicking the clear button or deleting the text | Search input is cleared and full schedule view is restored showing all shifts |
| 10 | Verify that the 'no matching shifts' message disappears | Message is no longer displayed and normal schedule view is shown |

**Postconditions:**
- Employee remains logged in
- Search input is cleared
- Full schedule is displayed
- System correctly handles no-match scenarios
- User is informed when search yields no results

---

