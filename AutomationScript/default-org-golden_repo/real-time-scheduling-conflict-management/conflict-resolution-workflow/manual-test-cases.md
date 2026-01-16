# Manual Test Cases

## Story: As Scheduler, I want to reschedule conflicting appointments to resolve scheduling conflicts efficiently
**Story ID:** story-6

### Test Case: Reschedule conflicting appointment successfully
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as a Scheduler with rescheduling permissions
- At least one appointment conflict exists in the system
- Conflict alert is visible and accessible to the user
- Available time slots exist in the calendar for rescheduling
- Appointment database is accessible and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the conflict alert dashboard and locate a conflicting appointment | Conflict alert is displayed with appointment details and available action options |
| 2 | Click on the 'Reschedule' option from the conflict alert | Calendar view opens displaying available time slots without conflicts, current appointment details are visible |
| 3 | Review the available time slots in the calendar view | Calendar shows available slots clearly marked, conflicting slots are disabled or marked as unavailable |
| 4 | Select a new time slot that does not have any conflicts | Selected time slot is highlighted, system begins validation process |
| 5 | Wait for system to validate the selected time slot | System validates the new time slot successfully, displays confirmation message that the slot is available, validation completes within 3 seconds |
| 6 | Click the 'Confirm Reschedule' button to finalize the change | Confirmation dialog appears asking user to verify the rescheduling action |
| 7 | Confirm the rescheduling action in the confirmation dialog | Appointment is successfully updated with new time, success message is displayed, operation completes within 3 seconds |
| 8 | Verify the conflict status in the conflict alert dashboard | Conflict is automatically cleared from the alert list, appointment shows updated time, conflict status is marked as resolved |

**Postconditions:**
- Appointment is rescheduled to the new time slot
- Conflict alert is removed from the dashboard
- Conflict status is updated to 'Resolved' in the database
- Appointment database reflects the updated time
- No new conflicts are created by the rescheduling

---

### Test Case: Prevent rescheduling to conflicting time
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in as a Scheduler with rescheduling permissions
- At least one appointment conflict exists in the system
- Conflict alert is visible and accessible to the user
- Multiple appointments exist creating potential conflicts
- Calendar view is accessible with both available and conflicting time slots

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the conflict alert dashboard and select a conflicting appointment | Conflict alert details are displayed with reschedule option available |
| 2 | Click on the 'Reschedule' option from the conflict alert | Calendar view opens showing available and unavailable time slots |
| 3 | Attempt to select a time slot that already has a conflicting appointment scheduled | Time slot is selected and highlighted, system initiates validation |
| 4 | Wait for system validation of the selected conflicting time slot | System detects the conflict and displays a validation error message indicating the selected time conflicts with another appointment |
| 5 | Review the error message details | Error message clearly states the conflict reason, shows conflicting appointment details, and prevents the reschedule action from proceeding |
| 6 | Verify that the 'Confirm Reschedule' button is disabled or unavailable | Confirm button is disabled or not clickable, preventing user from completing the invalid reschedule |
| 7 | Attempt to click the disabled 'Confirm Reschedule' button | No action occurs, button remains disabled, error message persists |
| 8 | Verify the original appointment remains unchanged | Original appointment time is unchanged, conflict status remains active, no updates are made to the database |

**Postconditions:**
- Original appointment time remains unchanged
- Conflict alert remains active in the dashboard
- No database updates are performed
- Error message is displayed to guide user to select valid time slot
- System maintains data integrity by preventing invalid reschedule

---

## Story: As Scheduler, I want to override scheduling conflicts with permission to handle exceptional cases
**Story ID:** story-7

### Test Case: Authorized user overrides conflict successfully
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in with authorized role that has override permissions
- User role is configured in the system with override access rights
- At least one scheduling conflict exists in the system
- Conflict alert is visible and accessible
- Audit logging system is operational and accessible
- Conflict database is accessible for updates

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the conflict alert dashboard and locate a conflict that requires override | Conflict alert is displayed with conflict details and available action options including 'Override' button |
| 2 | Click on the 'Override' option on the conflict alert | System initiates permission check, validates user has override authorization |
| 3 | Wait for system to complete permission validation | System confirms user has required permissions, displays confirmation dialog prompting user to confirm the override action |
| 4 | Review the confirmation dialog details including conflict information and override implications | Confirmation dialog displays conflict details, warning about override action, and options to 'Confirm' or 'Cancel' |
| 5 | Click the 'Confirm' button in the override confirmation dialog | System processes the override request, operation completes within 2 seconds, success message is displayed |
| 6 | Verify the conflict status has been updated in the conflict alert dashboard | Conflict is marked as 'Overridden', conflict alert is removed or status updated, appointments remain scheduled despite conflict |
| 7 | Navigate to the audit log section or access audit log records | Audit log interface is accessible and displays recent entries |
| 8 | Search for the override action entry in the audit log using conflict ID or timestamp | Audit log entry is found with complete details |
| 9 | Verify the audit log entry contains all required information | Log entry includes user ID/name who performed override, timestamp of action, conflict ID, appointment details, and override reason if applicable |

**Postconditions:**
- Conflict is successfully overridden in the system
- Conflict status is updated to 'Overridden'
- Both conflicting appointments remain scheduled
- Audit log contains complete record of override action with user details and timestamp
- Override action is traceable for compliance purposes
- System maintains audit trail for future reference

---

### Test Case: Unauthorized user cannot override conflict
- **ID:** tc-004
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with a role that does NOT have override permissions
- User role is configured without override access rights in the system
- At least one scheduling conflict exists in the system
- Conflict alert is visible and accessible to the user
- Role-based access control is properly configured and enforced
- Security permissions are active and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the conflict alert dashboard as an unauthorized user | Conflict alert dashboard is displayed with existing conflicts |
| 2 | Locate a conflict alert and check for available action options | Conflict details are visible, override option may be hidden or disabled based on permissions |
| 3 | Attempt to click on the 'Override' option if visible, or attempt to access override functionality through any available means | System initiates permission check for the user attempting the override action |
| 4 | Wait for system to validate user permissions | System detects user lacks required override permissions, denies the override request |
| 5 | Observe the system response to the unauthorized override attempt | System displays clear error message stating 'You do not have permission to override conflicts' or similar authorization error, operation is blocked |
| 6 | Verify that no confirmation dialog appears for the override action | No confirmation dialog is displayed, user cannot proceed with override |
| 7 | Check the conflict status in the dashboard | Conflict status remains unchanged, no override is recorded, conflict remains active |
| 8 | Verify no audit log entry is created for the failed override attempt | No override action is logged since the action was denied at permission check, or a failed attempt may be logged for security purposes |

**Postconditions:**
- Conflict remains in its original state
- No override action is performed
- Conflict status is unchanged
- User receives clear error message about insufficient permissions
- System security is maintained by preventing unauthorized overrides
- No unauthorized changes are made to the database
- Role-based access control is enforced successfully

---

## Story: As Scheduler, I want to track conflict resolution status to monitor scheduling health
**Story ID:** story-8

### Test Case: Track and update conflict resolution status
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Scheduler role
- Conflict database is accessible and operational
- At least one scheduling conflict exists in the system
- User has permissions to view and resolve conflicts
- Dashboard is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the scheduling system and trigger a conflict detection by attempting to schedule overlapping resources or time slots | System detects the conflict and automatically sets the conflict status to 'pending' in the conflict database |
| 2 | Verify the conflict status is recorded by querying GET /conflicts/status API endpoint or checking the conflict record in the database | Conflict record exists with status='pending', timestamp of detection, and conflict details are accurately recorded |
| 3 | Access the conflict resolution interface and select the pending conflict from the list | Conflict details are displayed with current status showing as 'pending' and resolution options are available |
| 4 | Apply a resolution action by either rescheduling one of the conflicting items or selecting an override option, then submit the resolution | System processes the resolution action and updates the conflict status to 'resolved' via PUT /conflicts/{id}/status API endpoint |
| 5 | Navigate to the conflict dashboard by clicking on the dashboard menu or accessing the dashboard URL | Dashboard loads within 3 seconds and displays all conflicts including the recently resolved conflict |
| 6 | Locate the previously resolved conflict in the dashboard view and verify its status display | The conflict is displayed with status='resolved', shows resolution timestamp, resolution method applied, and user who resolved it |

**Postconditions:**
- Conflict status is updated to 'resolved' in the database
- Conflict resolution is recorded in historical data
- Dashboard reflects the updated conflict status
- Audit trail of status change is logged

---

### Test Case: Filter and sort conflicts on dashboard
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in with Scheduler role
- Conflict dashboard is accessible
- Multiple conflicts exist with different statuses (pending, resolved, overridden)
- Conflicts have different creation dates
- User has permissions to view conflict data
- Dashboard has loaded successfully

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the conflict dashboard and wait for the initial load to complete | Dashboard loads within 3 seconds displaying all conflicts with various statuses and dates |
| 2 | Locate the status filter dropdown or filter panel on the dashboard interface | Filter options are visible and include all available status values: 'pending', 'resolved', and 'overridden' |
| 3 | Select 'pending' from the status filter dropdown and apply the filter | Dashboard refreshes and displays only conflicts with status='pending', all other status conflicts are hidden from view |
| 4 | Verify the filtered results by checking each displayed conflict's status field | All displayed conflicts show status='pending', count of displayed conflicts matches the number of pending conflicts, no resolved or overridden conflicts are visible |
| 5 | Clear the status filter or select 'All' to display all conflicts again | Dashboard displays all conflicts regardless of status |
| 6 | Locate the sort options and click on the 'Date' column header or select 'Sort by Date' from the sort dropdown | Sort control is activated and sort direction indicator (ascending/descending arrow) is displayed |
| 7 | Apply ascending date sort and verify the order of conflicts displayed | Conflicts are sorted by date in ascending order (oldest first), with dates progressing chronologically from top to bottom of the list |
| 8 | Click the date sort control again to reverse the sort order to descending | Conflicts are re-sorted by date in descending order (newest first), with most recent conflicts appearing at the top of the list |
| 9 | Combine filters by applying status filter 'pending' while maintaining the date sort | Dashboard displays only pending conflicts sorted by date in the selected order, both filter and sort are applied simultaneously |

**Postconditions:**
- Dashboard maintains the applied filters and sort preferences
- Filter and sort selections are preserved during the session
- No data integrity issues occur from filtering and sorting operations
- Dashboard performance remains within 3 seconds for filter/sort operations

---

