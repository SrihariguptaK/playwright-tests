# Manual Test Cases

## Story: As Scheduler, I want to view a calendar showing resource availability to avoid scheduling conflicts
**Story ID:** story-5

### Test Case: Verify calendar displays accurate resource availability
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User has valid scheduler credentials and is logged into the system
- At least one resource exists in the system with scheduled appointments
- Resource scheduling database contains both booked and free time slots
- Network connection is stable and meets standard requirements
- User has appropriate permissions to view resource availability calendar

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the resource availability calendar section from the main dashboard | Calendar interface loads and displays within 2 seconds showing the current month view with resource availability grid |
| 2 | Select a specific resource from the resource dropdown or list | Calendar refreshes and displays the selected resource's schedule with clearly distinguished booked slots (marked/colored) and free slots (unmarked/different color) for the current time period |
| 3 | Verify the accuracy of displayed time slots by comparing with known scheduled appointments | All booked time slots match existing appointments in the system, and free slots are correctly shown as available |
| 4 | Using a separate session or admin panel, create a new appointment for the selected resource or modify an existing schedule | External schedule change is successfully saved in the system |
| 5 | Return to the calendar view and observe the resource availability display without manually refreshing | Calendar automatically updates in real-time to reflect the new booking or schedule change, showing the previously free slot as now booked or vice versa |

**Postconditions:**
- Calendar displays current and accurate resource availability
- Real-time updates are functioning correctly
- No system errors or performance issues occurred
- User session remains active and stable

---

### Test Case: Test filtering by resource type
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged into the system with scheduler privileges
- Resource availability calendar is accessible
- Multiple resource types exist in the system (e.g., Conference Rooms, Equipment, Personnel)
- Each resource type has at least one resource with scheduled availability
- Calendar view is already loaded and displaying all resources

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Locate and click on the resource type filter dropdown or filter panel on the calendar interface | Filter options panel opens displaying all available resource types as selectable options |
| 2 | Select a specific resource type from the filter options (e.g., 'Conference Rooms') | Filter is applied successfully and calendar view refreshes to display only resources belonging to the selected type |
| 3 | Verify that only the filtered resource type is visible by checking resource names and availability slots | Calendar shows only resources of the selected type with their respective booked and free slots; resources of other types are hidden from view |
| 4 | Click the remove filter button, clear filter option, or deselect the resource type filter | Filter is removed and calendar view refreshes to display all resource types and their availability |
| 5 | Verify that all resources across all types are now visible in the calendar | Calendar displays complete resource availability for all resource types with accurate booked and free time slots |

**Postconditions:**
- Calendar is displaying all resources without any active filters
- Filter functionality is working correctly
- No data loss or display errors occurred during filtering operations
- System performance remained within acceptable limits

---

## Story: As Scheduler, I want to override scheduling conflicts with authorization to handle exceptional cases
**Story ID:** story-6

### Test Case: Validate authorized override of scheduling conflict
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged into the system with scheduler role
- User has valid authorization credentials for override functionality
- A scheduling conflict scenario exists (overlapping resource booking or time slot conflict)
- Audit logging system is active and functioning
- Override feature is enabled in the system configuration

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Attempt to create or modify a schedule that triggers a scheduling conflict with an existing appointment | System detects the conflict and displays a conflict alert message with details of the conflicting schedules |
| 2 | Click on the 'Override' or 'Override Conflict' button displayed in the conflict alert dialog | System displays an authorization prompt requesting credentials (username/password or additional authentication) for override approval |
| 3 | Enter valid authorization credentials in the authentication fields and submit | System validates the credentials within 2 seconds and displays a success message indicating override has been applied |
| 4 | Verify that the conflicting schedule has been successfully created or modified despite the conflict | The new or modified schedule is saved in the system and appears in the calendar view, overriding the previous conflict restriction |
| 5 | Navigate to the audit logs or override history section of the system | Audit log interface loads and displays recent system activities |
| 6 | Search for or filter the override action that was just performed using timestamp or user filters | Override entry is present in the audit logs with correct user identity, timestamp, conflict details, and override action recorded |

**Postconditions:**
- Scheduling conflict has been successfully overridden
- Override action is permanently logged in audit trail
- System remains stable with no errors
- Conflicting schedules are both active in the system
- User session remains authenticated

---

### Test Case: Verify prevention of unauthorized override
- **ID:** tc-004
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged into the system with scheduler role
- A scheduling conflict scenario exists in the system
- User has invalid or no override authorization credentials
- Security and authentication systems are functioning properly
- Override attempt logging is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Attempt to create or modify a schedule that triggers a scheduling conflict | System detects the conflict and displays a conflict alert with override option available |
| 2 | Click on the 'Override' button in the conflict alert dialog | System displays authorization prompt requesting credentials for override approval |
| 3 | Enter invalid authorization credentials (incorrect username, password, or unauthorized user credentials) and submit | System denies the override request within 2 seconds and displays an error message such as 'Invalid credentials' or 'Unauthorized access' |
| 4 | Verify that the scheduling conflict remains unresolved and the conflicting schedule was not created or modified | Original conflict restriction remains in place; no new schedule is saved; calendar shows no changes |
| 5 | Close the authorization prompt and click the override button again | System displays the authorization prompt again |
| 6 | Click cancel or close the authorization prompt without entering any credentials | System denies the override attempt, closes the authorization dialog, and returns to the conflict alert screen without applying any override |
| 7 | Verify the conflict alert is still displayed and the schedule remains unchanged | Conflict alert remains visible; no schedule changes were saved; system maintains data integrity |

**Postconditions:**
- Scheduling conflict remains unresolved and enforced
- No unauthorized override was applied
- System security measures functioned correctly
- Failed override attempts may be logged for security monitoring
- User session remains active without lockout (unless security policy dictates otherwise)

---

## Story: As Scheduler, I want the system to provide a dashboard summarizing scheduling conflicts and alerts for quick overview
**Story ID:** story-12

### Test Case: Verify dashboard displays current conflicts and alerts
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User has Scheduler role with dashboard access permissions
- User is logged into the system
- Active scheduling conflicts exist in the system
- Alerts have been generated and are in various acknowledgment states
- Standard network connection is available (minimum bandwidth requirements met)
- Test data includes at least 5 active conflicts and 10 alerts with mixed statuses

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the scheduling dashboard URL or click on the Dashboard menu item | Dashboard page begins loading and displays loading indicator |
| 2 | Measure the time from navigation initiation to complete dashboard render | Dashboard loads completely within 3 seconds, displaying all UI components including conflict counts, alert statuses, and data tables |
| 3 | Review the conflict count displayed on the dashboard summary section | Conflict count matches the actual number of active conflicts in the system (verify against database or admin panel) |
| 4 | Review the alert statuses section showing acknowledged vs unacknowledged alerts | Alert acknowledgment statuses are displayed correctly with accurate counts for each status category (acknowledged, pending, unacknowledged) |
| 5 | Verify the details of displayed conflicts including conflict type, affected resources, and timestamps | All conflict details are accurate, complete, and match the source data with current timestamps |
| 6 | Check the real-time update functionality by creating a new conflict in another session or having another user create one | Dashboard automatically updates within 5 seconds to reflect the new conflict without requiring manual refresh |
| 7 | Apply a filter to show only high-priority conflicts using the filter dropdown or checkbox options | Dashboard immediately updates to display only high-priority conflicts, with conflict count adjusting accordingly |
| 8 | Apply a filter to show only unacknowledged alerts | Dashboard filters the alert list to show only unacknowledged alerts, updating the visible count |
| 9 | Sort the conflicts list by date in ascending order by clicking the date column header | Conflicts are reordered with oldest conflicts appearing first, sort indicator shows ascending order |
| 10 | Sort the conflicts list by date in descending order by clicking the date column header again | Conflicts are reordered with newest conflicts appearing first, sort indicator shows descending order |
| 11 | Sort the alerts by acknowledgment status | Alerts are grouped and sorted by status (e.g., unacknowledged first, then acknowledged), maintaining data accuracy |
| 12 | Clear all applied filters using the 'Clear Filters' or 'Reset' button | Dashboard returns to default view showing all conflicts and alerts with original sorting |
| 13 | Verify the data accuracy by comparing displayed metrics with backend data source | Dashboard data shows 95% or higher accuracy when compared to actual conflict and alert logs |

**Postconditions:**
- Dashboard remains in functional state with all filters and sorting options available
- No errors or warnings are displayed in the UI or browser console
- User session remains active and authenticated
- Dashboard data reflects the most current state of conflicts and alerts
- All applied filters and sorting can be cleared to return to default view

---

