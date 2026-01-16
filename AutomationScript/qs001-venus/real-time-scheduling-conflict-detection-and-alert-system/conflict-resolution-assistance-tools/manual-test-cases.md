# Manual Test Cases

## Story: As Scheduler, I want to view a dashboard of scheduling conflicts to manage them efficiently
**Story ID:** story-15

### Test Case: Validate real-time display of scheduling conflicts
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Scheduler role
- Conflict dashboard is accessible
- At least one active scheduling conflict exists in the system
- User has necessary permissions to view conflict dashboard
- System is connected to conflict detection logs

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the conflict dashboard URL or menu option | Conflict dashboard page loads successfully |
| 2 | Observe the dashboard display | Dashboard displays all current active scheduling conflicts with conflict details including resource names, time slots, and conflict types |
| 3 | Note the timestamp of dashboard load | Dashboard loads within 3 seconds with real-time conflict data |
| 4 | Create a new scheduling conflict by double-booking a resource in the scheduling system | New conflict is successfully created in the scheduling system |
| 5 | Monitor the conflict dashboard for updates | Dashboard automatically refreshes and displays the newly created conflict within 3 seconds without manual page refresh |
| 6 | Verify the new conflict appears with all relevant details | New conflict is visible with accurate information including resource, time, and conflict type |

**Postconditions:**
- Dashboard displays updated conflict list including the newly created conflict
- All conflicts are visible and accessible for further action
- System maintains real-time synchronization with conflict detection logs

---

### Test Case: Verify filtering and sorting functionality
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in with Scheduler role
- Conflict dashboard is loaded and displaying conflicts
- Multiple conflicts exist with different resources, times, and severity levels
- Filter and sort controls are visible on the dashboard
- Test data includes conflicts across different resources and time periods

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Locate the filter section on the conflict dashboard | Filter controls for resource, time, and type are visible and accessible |
| 2 | Select a specific resource from the resource filter dropdown | Resource filter is applied and dropdown shows selected resource |
| 3 | Observe the dashboard conflict list | Dashboard displays only conflicts associated with the selected resource, other conflicts are hidden |
| 4 | Apply a time filter by selecting a specific date range | Time filter is applied successfully |
| 5 | Verify the displayed conflicts | Dashboard shows only conflicts that match both the selected resource and time range filters, conflict count updates accordingly |
| 6 | Clear the applied filters | All conflicts are displayed again without any filters applied |
| 7 | Locate the sort control and click on 'Sort by Severity' | Sort option is activated and visual indicator shows sorting is applied |
| 8 | Review the order of conflicts displayed | Conflicts are sorted correctly by severity level (e.g., High to Low or Low to High) with severity indicators clearly visible |
| 9 | Verify the sorting order by checking severity levels of consecutive conflicts | Each conflict in the list has equal or lower severity than the previous one, confirming correct sort order |

**Postconditions:**
- Dashboard maintains filter and sort settings until cleared by user
- Filtered and sorted data is accurate and matches applied criteria
- Dashboard remains responsive and functional after filtering and sorting operations

---

### Test Case: Test export of conflict reports
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in with Scheduler role
- Conflict dashboard is loaded with active conflicts displayed
- Export button is visible on the dashboard
- User has permissions to export conflict reports
- Browser allows file downloads
- At least one conflict exists in the system for export

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Locate the export button on the conflict dashboard | Export button is visible and enabled on the dashboard interface |
| 2 | Click the export button | Export process initiates and browser shows download prompt or automatic download begins |
| 3 | Wait for the file download to complete | CSV file is successfully generated and downloaded to the default download location with a meaningful filename (e.g., conflict_report_YYYY-MM-DD.csv) |
| 4 | Navigate to the download location and locate the exported CSV file | CSV file is present in the download folder with correct file extension and non-zero file size |
| 5 | Open the exported CSV file using a spreadsheet application or text editor | CSV file opens successfully without errors |
| 6 | Review the CSV file structure and headers | CSV contains appropriate column headers such as Conflict ID, Resource, Time, Type, Severity, Status, etc. |
| 7 | Verify the conflict data in the CSV file against the dashboard display | All conflicts visible on the dashboard are present in the CSV file with accurate and complete data including resource names, timestamps, conflict types, and severity levels |
| 8 | Check data formatting and readability in the CSV | Data is properly formatted, dates and times are readable, and no data truncation or corruption is present |

**Postconditions:**
- CSV file remains available in download location for future reference
- Dashboard remains functional and unchanged after export
- Export action is logged in system audit trail
- User can perform additional exports if needed

---

## Story: As Resource Manager, I want to visualize double booking conflicts to prioritize resolution
**Story ID:** story-16

### Test Case: Validate visual display of double booking conflicts
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 9 mins

**Preconditions:**
- User is logged in with Resource Manager role
- Resource conflict dashboard is accessible
- At least one active double booking conflict exists in the system
- User has necessary permissions to view resource conflict dashboard
- System is connected to double booking conflict logs
- Visual indicators and severity markers are configured

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the resource conflict dashboard URL or menu option | Resource conflict dashboard page loads successfully |
| 2 | Observe the visual display of the dashboard | Dashboard displays current double booking conflicts in a visual format (e.g., timeline, calendar view, or graphical representation) |
| 3 | Review the conflict details shown on the dashboard | Each conflict displays resource details, timing information, severity indicators, and priority markers clearly |
| 4 | Verify the visual indicators for conflict severity | Conflicts are color-coded or marked with visual indicators (e.g., red for high severity, yellow for medium, green for low) that are easily distinguishable |
| 5 | Note the timestamp when dashboard is fully loaded | Dashboard loads completely within 3 seconds with all visual elements rendered |
| 6 | Create a new double booking conflict by scheduling the same resource for overlapping time slots | New double booking conflict is successfully created in the system |
| 7 | Monitor the resource conflict dashboard for automatic updates | Dashboard automatically refreshes without manual intervention |
| 8 | Verify the newly created conflict appears on the dashboard | New double booking conflict is displayed visually on the dashboard within 3 seconds with appropriate severity and priority indicators |
| 9 | Confirm all conflict details are accurate for the new conflict | New conflict shows correct resource name, overlapping time slots, conflict type, and visual severity markers |

**Postconditions:**
- Dashboard displays updated conflict list including the newly created double booking
- All visual indicators are functioning correctly
- System maintains real-time synchronization with double booking conflict logs
- Dashboard remains responsive for further interactions

---

### Test Case: Verify filtering by resource type and date
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Resource Manager role
- Resource conflict dashboard is loaded and displaying conflicts
- Multiple double booking conflicts exist with different resource types and dates
- Filter controls for resource type and date are visible on the dashboard
- Test data includes conflicts across various resource types (e.g., rooms, equipment, personnel) and date ranges

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Locate the filter controls on the resource conflict dashboard | Filter options for resource type and date are visible and accessible |
| 2 | Click on the resource type filter dropdown | Dropdown menu opens showing available resource types (e.g., Conference Rooms, Medical Equipment, Staff) |
| 3 | Select a specific resource type from the dropdown (e.g., 'Conference Rooms') | Selected resource type is highlighted and filter is applied |
| 4 | Observe the conflicts displayed on the dashboard | Dashboard shows only double booking conflicts for the selected resource type, other resource types are filtered out |
| 5 | Verify the conflict count updates to reflect filtered results | Conflict counter or summary shows the reduced number matching the filter criteria |
| 6 | Locate the date filter control and click to open date picker | Date picker or date range selector opens |
| 7 | Select a specific date or date range for filtering | Selected date range is applied and displayed in the filter control |
| 8 | Review the displayed conflicts after applying date filter | Dashboard displays only conflicts that match both the selected resource type and date range, all displayed conflicts fall within the specified date parameters |
| 9 | Verify each displayed conflict matches the applied filter criteria | All visible conflicts are of the selected resource type and occur within the selected date range, no conflicts outside the criteria are shown |
| 10 | Clear one filter (e.g., resource type) while keeping the date filter active | Dashboard updates to show conflicts of all resource types within the selected date range |
| 11 | Clear all filters | Dashboard returns to showing all double booking conflicts without any filtering applied |

**Postconditions:**
- Filter settings can be reapplied or modified as needed
- Dashboard maintains accurate conflict display based on filter criteria
- System performance remains within acceptable limits during filtering operations
- All conflicts remain accessible when filters are cleared

---

### Test Case: Test integration with resolution tools
- **ID:** tc-006
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in with Resource Manager role
- Resource conflict dashboard is loaded with visible double booking conflicts
- Resolution tools are configured and accessible
- User has permissions to initiate resolution workflows
- At least one double booking conflict is available for selection
- Integration between dashboard and resolution tools is properly configured

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Identify a double booking conflict on the dashboard | Conflict is visible with all details including resource, time, and severity |
| 2 | Click or select the identified conflict | Conflict is highlighted or selected, showing it is active for further action |
| 3 | Locate the resolution action button or option (e.g., 'Resolve', 'Manage', or 'Open Resolution Tool') | Resolution action button is visible and enabled for the selected conflict |
| 4 | Click the resolution action button to initiate the resolution workflow | System processes the request and begins launching the resolution tool |
| 5 | Wait for the resolution tool to open | Resolution tool interface launches successfully in a new window, modal, or panel within 3 seconds |
| 6 | Verify the resolution tool displays the selected conflict data | Resolution tool is pre-populated with the selected conflict information including resource name, conflicting time slots, parties involved, and conflict details |
| 7 | Check that all relevant conflict data is accurately transferred | All data fields in the resolution tool match the conflict information displayed on the dashboard with no data loss or corruption |
| 8 | Verify resolution options are available in the tool | Resolution tool provides appropriate options for managing the conflict (e.g., reschedule, reassign resource, cancel booking) |
| 9 | Confirm the integration maintains context and user session | User remains logged in, session is maintained, and navigation back to dashboard is available |

**Postconditions:**
- Resolution tool is active and ready for conflict management
- Selected conflict data is accurately loaded in the resolution tool
- Dashboard remains accessible for returning after resolution
- Integration between dashboard and resolution tools is confirmed functional
- User can proceed with conflict resolution workflow

---

