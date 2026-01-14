# Manual Test Cases

## Story: As Employee, I want to filter my schedule by shift type to quickly find relevant shifts
**Story ID:** story-15

### Test Case: Validate shift type filtering updates schedule display
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee account exists and is active in the system
- Employee has valid login credentials
- Employee has assigned shifts of multiple types (morning, evening, night) in the schedule
- Scheduling database is accessible and populated with test data
- Browser is supported and up to date

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the application login page and enter valid employee credentials (username and password), then click the Login button | Employee is successfully authenticated and redirected to the schedule dashboard. The dashboard displays all assigned shifts without any filters applied. Filter options are visible on the interface. |
| 2 | Locate the shift type filter dropdown/checkbox options and select 'Morning' shift type filter | The schedule display updates dynamically to show only morning shifts. All other shift types (evening, night) are hidden from view. The morning filter indicator shows as active/selected. The filtered results load within 3 seconds. |
| 3 | While the morning filter is still active, additionally select the 'Evening' shift type filter | The schedule display updates to show both morning and evening shifts. Night shifts remain hidden. Both morning and evening filter indicators show as active/selected. The schedule updates within 3 seconds. The combined filter results display accurately. |

**Postconditions:**
- Multiple filters (morning and evening) remain active on the schedule
- Only morning and evening shifts are visible in the schedule display
- Filter state is maintained and can be modified or cleared
- System performance metrics are logged for response time validation

---

### Test Case: Verify filter state persistence during navigation
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- Employee is logged into the schedule dashboard
- Employee has assigned shifts of multiple types in the schedule
- Multiple schedule views are available for navigation (e.g., weekly view, monthly view, list view)
- Shift type filters are available and functional

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | From the schedule dashboard, select one or more shift type filters (e.g., select 'Morning' and 'Night' shift types) | The schedule display updates to show only the selected shift types (morning and night shifts). The filter indicators show as active. Filtered schedule loads within 3 seconds. |
| 2 | Navigate away from the current schedule view to another schedule view (e.g., switch from weekly view to monthly view or navigate to a different date range) | The navigation completes successfully and the new schedule view is displayed. The applied filters (morning and night) remain active and visible as selected. The new view shows only the filtered shift types. |
| 3 | Navigate back to the original schedule view | The original schedule view is displayed with the same filters still applied (morning and night shifts). The filter state has persisted throughout the navigation. Only the filtered shift types are displayed. Filter indicators remain active. |

**Postconditions:**
- Filter state remains persistent across different schedule views
- Selected filters continue to be applied until manually changed or cleared by the employee
- Schedule displays only the filtered shift types consistently across all views
- Navigation history is maintained in the browser

---

## Story: As Employee, I want to search my schedule by keywords to find specific shifts or notes
**Story ID:** story-16

### Test Case: Validate keyword search returns matching shifts
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee account exists and is active in the system
- Employee has valid login credentials
- Employee has assigned shifts with various notes, locations, and roles in the schedule
- Test data includes shifts with specific keywords in notes (e.g., 'training', 'inventory', 'meeting')
- Scheduling database is accessible and populated with searchable test data
- Search functionality is enabled on the schedule dashboard

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the application login page and enter valid employee credentials (username and password), then click the Login button | Employee is successfully authenticated and redirected to the schedule dashboard. The dashboard displays all assigned shifts. A search input box is visible and accessible on the interface. |
| 2 | Locate the search input box and enter a complete keyword that exists in one or more shift notes (e.g., type 'training') | The schedule display updates to show only shifts that contain the keyword 'training' in their notes, locations, or roles. Non-matching shifts are hidden from view. Search results load within 3 seconds. The number of matching results is clearly indicated. |
| 3 | Clear the previous search and enter a partial keyword with mixed case (e.g., type 'TrAi' for shifts containing 'training') | The schedule display updates to show shifts matching the partial keyword 'TrAi', ignoring case sensitivity. Shifts containing 'training', 'Training', 'TRAINING', or any case variation are displayed. The search performs case-insensitive matching. Results load within 3 seconds. |

**Postconditions:**
- Search results accurately reflect the keyword criteria
- Only matching shifts are displayed in the schedule
- Search input remains populated with the last entered keyword
- Employee can clear search or enter new keywords to refine results
- Full schedule can be restored by clearing the search input

---

### Test Case: Verify dynamic update of search results
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- Employee is logged into the schedule dashboard
- Employee has assigned shifts with searchable content in notes, locations, and roles
- Search input box is visible and functional on the dashboard
- Test data includes shifts with keywords that can be searched progressively (e.g., 'meeting', 'inventory', 'maintenance')

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Click into the search input box and begin typing a keyword character by character (e.g., type 'm', then 'e', then 'e', then 't' to spell 'meet') | With each keystroke, the search results update dynamically in real-time. After typing 'm', all shifts containing 'm' are shown. After 'me', results narrow to shifts containing 'me'. After 'mee', results further narrow. After 'meet', only shifts containing 'meet' are displayed. Each update occurs within 3 seconds. The interface provides visual feedback during the search process. |
| 2 | Select all text in the search input box and delete it or click a clear/reset button if available | The search input box is cleared and becomes empty. The schedule display immediately updates to show the full unfiltered schedule with all assigned shifts visible. The transition from filtered to full view is smooth and completes within 3 seconds. No search criteria remain applied. |

**Postconditions:**
- Search input is cleared and ready for new search queries
- Full schedule is displayed without any search filters applied
- All employee shifts are visible in the schedule view
- Search functionality remains available for subsequent searches
- System returns to the default schedule display state

---

