# Manual Test Cases

## Story: As Scheduler, I want to view all active scheduling conflicts in a single interface to manage resolutions efficiently
**Story ID:** story-13

### Test Case: Verify display of active conflicts with details
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with Scheduler role
- At least 3 active conflicts exist in the system
- User has permissions to access conflict management interface
- Test data includes conflicts with complete details (date, resource, severity, priority)

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to conflict management interface from the main dashboard menu | Conflict management interface loads successfully and displays a list of all active conflicts with columns showing conflict ID, date, resource, severity, and status |
| 2 | Select a specific conflict from the displayed list by clicking on it | Detailed conflict information panel opens showing complete details including conflict ID, creation time, involved bookings, resource details, severity level, priority, and current status |
| 3 | Verify conflict details displayed in the interface against backend data by comparing with database records or API response | All conflict details match backend data exactly including timestamps, resource names, booking IDs, severity levels, and status information with no discrepancies |

**Postconditions:**
- Conflict management interface remains open and functional
- No data modifications have occurred
- User session remains active

---

### Test Case: Test filtering and sorting of conflicts
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in with Scheduler role
- Multiple active conflicts exist with varying resources, dates, and priorities
- At least 5 conflicts are present with different resource assignments
- Conflicts have different priority levels (High, Medium, Low)
- Conflict management interface is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to conflict management interface and locate the filter section | Interface displays with filter options visible including resource, date, and severity filters |
| 2 | Apply filter by selecting a specific resource from the resource dropdown filter | Conflict list updates to display only conflicts related to the selected resource, other conflicts are hidden from view |
| 3 | Click on the priority column header or select 'Sort by Priority' option | Conflicts are reordered and displayed from highest to lowest priority (High, Medium, Low) while maintaining the resource filter |
| 4 | Click 'Clear filters' button or reset icon to remove all applied filters and sorting | Full conflict list is restored showing all active conflicts in default order without any filters applied |

**Postconditions:**
- All filters and sorting are cleared
- Full conflict list is visible
- Interface is ready for new filter/sort operations

---

### Test Case: Ensure conflict status updates in real-time
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with Scheduler role
- At least one active conflict exists in the system
- User has permissions to mark conflicts as resolved
- Conflict management interface is open and displaying active conflicts

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Select an active conflict from the list and click 'Mark as Resolved' button or change status to 'Resolved' | Conflict status updates immediately in the interface showing 'Resolved' status without requiring page refresh, and the conflict is visually distinguished (grayed out or moved to resolved section) |
| 2 | Click the refresh button or reload the conflict management interface page | The previously resolved conflict is no longer listed in the active conflicts section and does not appear in the main conflict list |
| 3 | Navigate to conflict history or resolved conflicts section if available | The resolved conflict appears in the history with updated status, timestamp of resolution, and resolver information |

**Postconditions:**
- Conflict status is permanently updated to 'Resolved' in the database
- Active conflicts count is decremented by one
- Conflict history log contains the resolution entry

---

## Story: As Scheduler, I want to modify or reschedule conflicting bookings directly from the conflict resolution interface to quickly resolve issues
**Story ID:** story-17

### Test Case: Verify booking modification and validation in conflict interface
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in with Scheduler role
- At least one active conflict exists with two or more conflicting bookings
- User has permissions to modify bookings
- Conflict resolution interface is accessible
- Available non-conflicting time slots exist in the schedule
- Real-time validation service is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open conflict resolution interface from the main menu and select a specific conflict from the list | Conflict details page opens displaying all conflicting bookings with editable fields including booking time, date, resource, and duration fields enabled for modification |
| 2 | Click on the booking time field of one conflicting booking and modify it to a non-conflicting time slot using the time picker or calendar widget | System performs real-time validation and displays a success indicator (green checkmark or 'Valid' message) confirming the new time slot does not create conflicts |
| 3 | Click 'Save' or 'Apply Changes' button to commit the booking modification | Booking is successfully updated in the system, confirmation message appears, conflict status automatically changes to 'Resolved', and the conflict is removed from active conflicts list |
| 4 | Verify the updated booking appears correctly in the main scheduling view with the new time slot | Modified booking displays with updated time in the schedule, no conflicts are shown, and all related data is consistent |

**Postconditions:**
- Booking is permanently updated in the scheduling database
- Conflict is marked as resolved
- Schedule reflects the new booking time
- No new conflicts are created by the modification

---

### Test Case: Test undo functionality for booking changes
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Scheduler role
- At least one active conflict exists
- User has permissions to modify bookings
- Conflict resolution interface is open
- Undo functionality is enabled for the current session

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Select a conflict from the list and modify one of the conflicting booking details (change time or resource) | Booking modification fields accept the changes and display the updated values |
| 2 | Click 'Save' button to apply the booking changes | Changes are successfully applied, confirmation message displays, booking is updated in the system, and 'Undo' button or option becomes visible and enabled |
| 3 | Click the 'Undo' button or select 'Undo Changes' option within the same session | Booking immediately reverts to its previous state with original time/resource values restored, and confirmation message indicates successful undo operation |
| 4 | Verify the conflict status updates to reflect the reverted changes | Conflict status returns to 'Active' or original state since the resolution was undone, and the conflict reappears in the active conflicts list with original details |
| 5 | Check the main scheduling view to confirm booking shows original values | Booking displays with original time and resource allocation matching the pre-modification state |

**Postconditions:**
- Booking is restored to original state in the database
- Conflict status reflects the undone changes
- Schedule shows original booking details
- Undo action is logged in system history

---

## Story: As Scheduler, I want the conflict resolution interface to support filtering and sorting of conflicts to prioritize my work effectively
**Story ID:** story-19

### Test Case: Verify filtering by date, resource, and severity
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as a Scheduler with appropriate permissions
- Conflict resolution interface is accessible
- Multiple conflicts exist in the system with varying dates, resources, and severity levels
- Test data includes conflicts spanning at least 30 days with different resources and severity levels

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the conflict resolution interface | Conflict resolution interface loads successfully displaying all existing conflicts |
| 2 | Locate and click on the date range filter control | Date range filter dialog or input fields are displayed |
| 3 | Enter a start date (e.g., 01/01/2024) and end date (e.g., 01/15/2024) in the date range filter | Date values are accepted and displayed in the filter fields |
| 4 | Apply the date range filter | Only conflicts with dates between 01/01/2024 and 01/15/2024 are displayed in the conflict list. Conflicts outside this range are not shown |
| 5 | Clear the date range filter and locate the resource filter dropdown | All conflicts are displayed again. Resource filter dropdown shows available resources |
| 6 | Select a specific resource (e.g., 'Conference Room A') from the resource filter dropdown | Resource is selected and highlighted in the dropdown |
| 7 | Apply the resource filter | Only conflicts related to 'Conference Room A' are displayed. Other resource conflicts are filtered out |
| 8 | Clear the resource filter and locate the severity filter control | All conflicts are displayed again. Severity filter options are visible |
| 9 | Select a severity level (e.g., 'High') from the severity filter | Severity level 'High' is selected |
| 10 | Apply the severity filter | Only conflicts with 'High' severity are displayed. Medium and Low severity conflicts are filtered out |
| 11 | Verify the count of displayed conflicts matches the filter criteria | Conflict count indicator shows the correct number of filtered conflicts |

**Postconditions:**
- Filters can be cleared to return to the full conflict list
- Applied filters remain active until manually cleared or changed
- System maintains filter state during the session

---

### Test Case: Test sorting by priority and creation time
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in as a Scheduler with appropriate permissions
- Conflict resolution interface is accessible
- Multiple conflicts exist with different priority levels (High, Medium, Low)
- Conflicts have different creation timestamps spanning multiple days
- At least 10 conflicts are available for sorting verification

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the conflict resolution interface | Conflict resolution interface loads with the default conflict list displayed |
| 2 | Locate the sort options and identify the priority sort control | Sort controls are visible with priority sorting option available |
| 3 | Click on the priority column header or select 'Sort by Priority - Descending' option | Sort indicator (arrow or icon) appears showing descending order is selected |
| 4 | Observe the order of conflicts in the list | Conflicts are ordered from highest to lowest priority (High priority conflicts appear first, followed by Medium, then Low priority conflicts) |
| 5 | Verify the first 3 conflicts displayed are all High priority | First three conflicts in the list show 'High' priority label or indicator |
| 6 | Scroll to the bottom of the list and verify the last conflicts are Low priority | Last conflicts in the list show 'Low' priority label or indicator |
| 7 | Locate and click on the creation time sort control or column header | Sort indicator changes to show creation time sorting is active |
| 8 | Select 'Sort by Creation Time - Ascending' option | Sort indicator shows ascending order for creation time |
| 9 | Observe the order of conflicts in the list | Conflicts are ordered from oldest to newest based on creation timestamp |
| 10 | Verify the first conflict has the earliest creation date/time | First conflict displays the oldest timestamp (e.g., created 30 days ago) |
| 11 | Verify the last conflict has the most recent creation date/time | Last conflict displays the newest timestamp (e.g., created today or yesterday) |
| 12 | Toggle the creation time sort to descending order | Conflicts are reordered with newest conflicts appearing first and oldest appearing last |

**Postconditions:**
- Sort order persists until changed by the user
- Conflicts remain sorted according to the last selected criteria
- Sort indicators clearly show the active sorting method

---

### Test Case: Ensure filter input validation and feedback
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in as a Scheduler with appropriate permissions
- Conflict resolution interface is accessible
- Filter controls are enabled and functional
- System has validation rules configured for filter inputs

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the conflict resolution interface | Conflict resolution interface loads successfully with filter controls visible |
| 2 | Click on the date range filter control to open date input fields | Date range filter input fields are displayed and ready for input |
| 3 | Enter an invalid date format in the start date field (e.g., '99/99/9999' or 'abc123') | Date field shows the invalid input |
| 4 | Attempt to apply the filter or move focus away from the date field | Validation error message is displayed indicating 'Invalid date format. Please use MM/DD/YYYY format' or similar message. Error styling (red border or highlight) appears on the date field |
| 5 | Clear the invalid date and enter a valid start date (e.g., '01/15/2024') and an end date earlier than the start date (e.g., '01/01/2024') | Both dates are entered in the fields |
| 6 | Attempt to apply the date range filter | Validation error message is displayed indicating 'End date must be after start date' or similar message. Filter is not applied and conflict list remains unchanged |
| 7 | Enter a future date range (e.g., start date: '01/01/2025', end date: '12/31/2025') | Dates are accepted in the input fields |
| 8 | Apply the future date range filter | Filter is applied successfully. If no conflicts exist in the future date range, a message displays 'No conflicts found for the selected date range' or the list shows zero results |
| 9 | Clear date filters and enter a valid date range (e.g., '01/01/2024' to '01/31/2024') | Valid dates are entered and accepted |
| 10 | Select a valid resource from the resource filter dropdown | Resource is selected successfully |
| 11 | Select a valid severity level from the severity filter | Severity level is selected successfully |
| 12 | Apply all valid filters together | All filters are applied successfully. Filtered conflict list is displayed showing only conflicts matching all criteria (date range, resource, and severity). Success feedback or confirmation message may appear. Page loads within 3 seconds |
| 13 | Verify the conflict count and displayed conflicts match the applied filter criteria | Conflict count is accurate and all displayed conflicts meet the filter criteria. No conflicts outside the filter parameters are shown |

**Postconditions:**
- Invalid filter inputs are rejected with clear error messages
- Valid filters are applied and conflicts are filtered correctly
- Error messages are cleared when valid input is provided
- System maintains data integrity and does not display incorrect results

---

