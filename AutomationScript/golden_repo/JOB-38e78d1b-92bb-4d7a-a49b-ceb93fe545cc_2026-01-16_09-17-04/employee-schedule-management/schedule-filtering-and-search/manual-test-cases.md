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
| 4 | Verify that only morning shifts are displayed in the schedule view | All displayed shifts are of 'Morning' type, no other shift types are visible |
| 5 | Click the 'Clear filter' button or deselect the 'Morning' filter | Filter is removed and full schedule is displayed showing all shift types within 2 seconds |
| 6 | Verify that all shift types are now visible in the schedule | Schedule displays all shifts including Morning, Evening, Night, and any other shift types |

**Postconditions:**
- Employee remains logged in
- Schedule displays full unfiltered view
- Filter state is cleared
- System is ready for next filter operation

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
| 3 | Select 'Morning' from the shift type filter options | 'Morning' filter is selected and visually indicated as active |
| 4 | Additionally select 'Evening' from the shift type filter options while keeping 'Morning' selected | Both 'Morning' and 'Evening' filters are selected and visually indicated as active |
| 5 | Observe the schedule view update | Schedule updates within 2 seconds to display only shifts that match either 'Morning' or 'Evening' shift types |
| 6 | Verify that displayed shifts include both Morning and Evening shifts | All displayed shifts are either 'Morning' or 'Evening' type, no Night or other shift types are visible |
| 7 | Count the total number of shifts displayed and verify against expected count | Total displayed shifts equals the sum of Morning shifts plus Evening shifts |

**Postconditions:**
- Employee remains logged in
- Multiple filters remain active on the schedule view
- Only Morning and Evening shifts are displayed
- System maintains filter state for navigation

---

### Test Case: Test no matching shifts message
- **ID:** tc-003
- **Type:** edge-case
- **Priority:** Medium
- **Estimated Time:** 4 mins

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
| 2 | Identify a shift type that has no scheduled shifts (e.g., 'Weekend' or 'Holiday') | Shift type option is available in the filter but employee has no shifts of this type scheduled |
| 3 | Select the shift type filter for which no shifts are scheduled | Filter is applied and schedule view updates within 2 seconds |
| 4 | Observe the schedule display area | Schedule area is empty with no shift entries displayed |
| 5 | Verify that the system displays the message 'No shifts match the selected filters' | Message 'No shifts match the selected filters' is clearly displayed in the schedule area |
| 6 | Clear the filter or select a different shift type with scheduled shifts | Schedule updates to show shifts matching the new filter or full schedule if filter is cleared |

**Postconditions:**
- Employee remains logged in
- Filter can be cleared or modified
- System returns to normal operation
- No error state persists

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
| 2 | Locate the search input field on the schedule page | Search input field is visible and ready for text entry |
| 3 | Identify a keyword that exists in one or more shift notes (e.g., 'training', 'meeting', 'urgent') | Keyword is confirmed to exist in at least one shift note in the current schedule |
| 4 | Enter the identified keyword into the search input field | Keyword is entered and visible in the search input field |
| 5 | Observe the schedule view update as the keyword is entered | Schedule updates dynamically within 2 seconds to display only shifts containing the keyword in their notes |
| 6 | Verify that all displayed shifts contain the searched keyword in their notes | All visible shifts have notes that include the searched keyword, shifts without the keyword are hidden |
| 7 | Test partial match by entering only part of a word (e.g., 'train' for 'training') | Schedule displays shifts with notes containing words that partially match the search term |
| 8 | Test case-insensitive search by entering the keyword in different case (e.g., 'TRAINING', 'Training') | Schedule displays the same results regardless of the case used in the search term |
| 9 | Click the clear button or delete all text from the search input field | Search input is cleared and becomes empty |
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
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee account exists and is active in the system
- Employee is logged into the application
- Employee has scheduled shifts with various notes
- Schedule section is accessible
- Search input field is visible on the schedule page

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule section from the main dashboard | Schedule page loads successfully displaying all scheduled shifts |
| 2 | Locate the search input field on the schedule page | Search input field is visible and ready for text entry |
| 3 | Enter a keyword that does not exist in any shift notes (e.g., 'xyz123', 'nonexistent') | Keyword is entered and visible in the search input field |
| 4 | Observe the schedule view update after entering the non-matching keyword | Schedule updates within 2 seconds and the schedule display area becomes empty |
| 5 | Verify that the system displays the message 'No matching shifts found' | Message 'No matching shifts found' is clearly displayed in the schedule area |
| 6 | Verify that no shift entries are visible in the schedule | Schedule area shows no shift entries, only the 'No matching shifts found' message |
| 7 | Clear the search input by clicking the clear button or deleting the text | Search input is cleared and full schedule view is restored showing all shifts |

**Postconditions:**
- Employee remains logged in
- Search input is cleared
- Full schedule is displayed
- No error state persists
- System is ready for next search operation

---

