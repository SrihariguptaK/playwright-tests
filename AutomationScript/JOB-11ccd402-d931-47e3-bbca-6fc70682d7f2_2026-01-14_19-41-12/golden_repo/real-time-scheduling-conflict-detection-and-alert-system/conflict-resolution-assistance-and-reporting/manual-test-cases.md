# Manual Test Cases

## Story: As Scheduler, I want to view a dashboard of current scheduling conflicts to monitor and manage issues proactively
**Story ID:** story-15

### Test Case: Verify dashboard displays active conflicts with details
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Scheduler role
- At least 3 active scheduling conflicts exist in the system
- User has permission to access conflict dashboard
- Backend conflict database is populated with test data

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the scheduling conflict dashboard from the main menu | Dashboard page loads successfully and displays a list of all active conflicts with columns showing conflict ID, resource name, time slot, severity level, and conflict description |
| 2 | Select a specific conflict from the displayed list by clicking on it | Detailed conflict information panel opens showing complete details including affected appointments, resources involved, conflict type, timestamp, and resolution options |
| 3 | Compare the displayed conflict data with the backend conflict records by querying the database directly | All displayed data (conflict ID, resource names, time slots, severity, status) matches exactly with the backend conflict database records |

**Postconditions:**
- Dashboard remains open and functional
- No data inconsistencies detected
- User session remains active

---

### Test Case: Test filtering and sorting functionality on dashboard
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in with Scheduler role
- Dashboard contains conflicts for multiple resources with varying priorities
- At least 5 conflicts exist with different severity levels and dates
- Filter and sort controls are visible on the dashboard

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Click on the resource filter dropdown and select a specific resource (e.g., 'Conference Room A') | Dashboard refreshes and displays only conflicts associated with the selected resource, hiding all other conflicts. Conflict count updates to reflect filtered results |
| 2 | Click on the 'Priority' column header to sort conflicts by priority in descending order | Conflicts are reordered with highest priority conflicts appearing at the top, followed by medium and low priority conflicts in correct sequence |
| 3 | Click the 'Clear Filters' button or reset icon to remove all applied filters and sorting | Dashboard returns to default view showing the complete list of all active conflicts in original order without any filters applied |

**Postconditions:**
- All filters are cleared
- Dashboard shows full unfiltered conflict list
- Filter controls are reset to default state

---

### Test Case: Ensure dashboard refreshes data within 2 seconds
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in with Scheduler role
- Dashboard is open and displaying current conflicts
- System has capability to create and resolve conflicts programmatically
- Performance monitoring tools are available to measure refresh time

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Create a new scheduling conflict in the system through the scheduling interface or API while monitoring the dashboard with a timer | Dashboard automatically refreshes and displays the newly created conflict within 2 seconds. The new conflict appears in the list with all relevant details populated correctly |
| 2 | Resolve an existing conflict from the dashboard by selecting it and applying a resolution action, then monitor the dashboard refresh time | Dashboard updates within 2 seconds and the resolved conflict is removed from the active conflicts list or moved to resolved status. Conflict count decreases accordingly |
| 3 | Verify the timestamp of the last refresh and compare conflict data with real-time database queries | Dashboard displays current timestamp showing recent refresh. All conflict data matches the current state in the database with no stale or outdated information visible |

**Postconditions:**
- Dashboard shows accurate real-time data
- No stale conflicts are displayed
- Refresh performance meets 2-second requirement
- System logs show successful refresh operations

---

## Story: As Scheduler, I want the system to suggest alternative scheduling options when conflicts occur to facilitate quick resolution
**Story ID:** story-16

### Test Case: Validate generation of alternative scheduling options
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in with Scheduler role
- Multiple resources are available in the system
- Alternative time slots exist for conflicting appointments
- Scheduling interface is accessible and functional

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Create a scheduling conflict by attempting to book a resource that is already reserved for the same time slot | System detects the conflict and automatically generates a list of alternative options including at least 3 alternative time slots and 2 alternative available resources with similar characteristics |
| 2 | Review the suggestions displayed in the UI, checking for clarity of presentation, time slot details, and resource information | Suggestions are displayed in a clear, organized format showing each alternative with complete details: date, time, duration, resource name, resource type, and availability status. All information is accurate and easy to understand |
| 3 | Select one of the suggested alternative time slots or resources and confirm the selection to update the schedule | Schedule is successfully updated with the selected alternative. The new appointment is created without any conflicts. Confirmation message is displayed and the conflict is resolved |

**Postconditions:**
- Original conflict is resolved
- New appointment is scheduled successfully
- No new conflicts are created
- Schedule reflects the updated booking

---

### Test Case: Test suggestion generation performance
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 9 mins

**Preconditions:**
- User is logged in with Scheduler role
- System has sufficient resources and time slots for generating suggestions
- Performance monitoring tools are configured
- Multiple scheduling conflicts can be triggered simultaneously

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Trigger 5 scheduling conflicts simultaneously by attempting to book multiple overlapping appointments at the same time, while measuring response time with a timer | System generates alternative suggestions for each of the 5 conflicts within 2 seconds per conflict. All suggestion sets are complete and displayed without delay |
| 2 | Interact with the UI during suggestion generation by scrolling, clicking, and navigating between conflicts | UI remains fully responsive throughout the suggestion generation process. No lag, freezing, or unresponsive elements are observed. User can interact with all dashboard elements smoothly |
| 3 | Review system logs and error logs for the time period when suggestions were generated | System logs show successful suggestion generation for all conflicts. No error messages, exceptions, timeouts, or failures are recorded. All API calls completed successfully |

**Postconditions:**
- All conflicts have generated suggestions
- System performance remains stable
- No errors logged in system
- UI is responsive and functional

---

### Test Case: Ensure suggestions are conflict-free and valid
- **ID:** tc-006
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Scheduler role
- A scheduling conflict exists in the system
- System has generated alternative suggestions
- Resource availability data is current and accurate

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Review each suggested time slot and resource by cross-referencing with the current schedule and resource availability database | All suggested time slots are genuinely available with no existing bookings. All suggested resources are available during the proposed time slots and meet the requirements. No conflicts exist with any suggestion |
| 2 | Attempt to manually select a suggestion that has become unavailable (simulate by booking it through another session before selection) | System detects that the suggestion is no longer valid and prevents the selection. An error message is displayed stating 'This option is no longer available. Please select another alternative or refresh suggestions' |
| 3 | Select a valid, conflict-free suggestion from the list and confirm the booking | Schedule updates successfully with the selected alternative. The appointment is created without any conflicts. System confirms the booking and displays success message. The resolved conflict is removed from the conflict list |

**Postconditions:**
- Valid suggestion is successfully booked
- No conflicts exist in the updated schedule
- Invalid suggestions are properly handled
- Conflict is marked as resolved

---

## Story: As Scheduler, I want to generate historical reports on scheduling conflicts to analyze trends and improve scheduling practices
**Story ID:** story-17

### Test Case: Verify generation of historical conflict reports with filters
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Scheduler role and authorized permissions
- Historical conflict data exists in the system database for at least 3 months
- Multiple resources and conflict types are available in the system
- Reporting module is accessible and functional
- Browser supports PDF and Excel file downloads

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the reporting module from the main dashboard | Reporting module page loads successfully with report generation options displayed |
| 2 | Select 'Historical Conflict Reports' from the report type dropdown | Filter options for date range, resource, and conflict type are displayed |
| 3 | Set the date range filter to last 30 days using the date picker | Start and end dates are populated correctly in the date range fields |
| 4 | Select a specific resource from the resource filter dropdown | Selected resource is displayed in the filter field |
| 5 | Select a conflict type from the conflict type filter dropdown | Selected conflict type is displayed in the filter field |
| 6 | Click the 'Generate Report' button | Report is generated and displayed on screen showing conflict data filtered by the selected parameters within 10 seconds |
| 7 | Review the generated report data tables for conflict entries | Data tables display only conflicts matching the selected date range, resource, and conflict type with accurate details including dates, resources, and conflict descriptions |
| 8 | Review the visual trend charts in the report | Charts accurately visualize conflict trends over the selected time period with proper labels, legends, and data points corresponding to the filtered data |
| 9 | Click the 'Export to PDF' button | PDF file is generated and download prompt appears with filename containing report type and date |
| 10 | Open the downloaded PDF file | PDF opens successfully and contains all report data, charts, and filters applied with proper formatting |
| 11 | Return to the report page and click the 'Export to Excel' button | Excel file is generated and download prompt appears with filename containing report type and date |
| 12 | Open the downloaded Excel file | Excel file opens successfully with data in structured columns, charts included, and all filtered conflict data present |

**Postconditions:**
- Report remains displayed on screen for further review
- PDF and Excel files are saved in the downloads folder
- Report generation is logged in system audit logs
- No data is modified in the system
- User session remains active

---

### Test Case: Test report generation performance
- **ID:** tc-002
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in with Scheduler role and authorized permissions
- Large dataset of historical conflicts exists (minimum 10,000 conflict records)
- System monitoring tools are available to track performance metrics
- Reporting module is accessible and functional
- Network connection is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the reporting module from the main dashboard | Reporting module page loads successfully |
| 2 | Select 'Historical Conflict Reports' from the report type dropdown | Filter options are displayed |
| 3 | Set the date range filter to cover the maximum available historical period (e.g., last 12 months) to include large dataset | Date range is set to include all available historical data |
| 4 | Leave resource and conflict type filters set to 'All' to maximize data volume | All filters are configured to retrieve maximum dataset |
| 5 | Open system monitoring tool to track CPU, memory usage, and response time | Monitoring tool is active and displaying baseline system metrics |
| 6 | Note the current timestamp and click the 'Generate Report' button | Report generation process initiates and loading indicator is displayed |
| 7 | Monitor the report generation time until completion | Report is generated and fully displayed within 10 seconds with complete data and charts |
| 8 | Review system resource usage metrics during report generation | CPU and memory usage remain within acceptable limits (below 80%), system remains stable and responsive to user interactions |
| 9 | Verify the total number of conflict records displayed in the report summary | Record count matches the expected number from the database query with no data truncation |
| 10 | Scroll through all pages or sections of the report data | All data is present, no missing records, no error messages, and pagination works correctly |
| 11 | Verify all trend charts are rendered completely with all data points | Charts display all data points accurately without truncation or rendering errors |
| 12 | Check system logs for any errors or warnings during report generation | No errors or warnings are logged, report generation completed successfully |

**Postconditions:**
- Report with large dataset is successfully displayed
- System performance metrics return to baseline levels
- No data corruption or loss occurred
- System remains stable and available for other operations
- Performance metrics are logged for analysis

---

### Test Case: Ensure report access control
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Two user accounts are available: one with Scheduler role (authorized) and one without Scheduler role (unauthorized)
- Historical conflict data exists in the system
- Reporting module has role-based access control configured
- Audit logging is enabled and functional
- Both user accounts have valid credentials

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in to the system using unauthorized user credentials (non-Scheduler role) | User is successfully logged in and main dashboard is displayed |
| 2 | Attempt to navigate to the reporting module URL directly or through navigation menu | Access is denied with an appropriate error message such as 'Access Denied: You do not have permission to view reports' and user is redirected to appropriate page |
| 3 | Attempt to access the report generation API endpoint directly using the unauthorized user session (GET /reports/conflicts) | API returns 403 Forbidden status code with error message indicating insufficient permissions |
| 4 | Log out from the unauthorized user account | User is successfully logged out and redirected to login page |
| 5 | Log in to the system using authorized Scheduler user credentials | Scheduler user is successfully logged in and main dashboard is displayed |
| 6 | Navigate to the reporting module from the main dashboard | Reporting module page loads successfully with all report generation options accessible |
| 7 | Select 'Historical Conflict Reports' and set basic filter parameters (date range: last 7 days) | Filter options are displayed and parameters are set successfully |
| 8 | Click the 'Generate Report' button | Report is generated successfully and displayed with conflict data, charts, and export options available |
| 9 | Verify all report functionality is accessible including viewing data tables and charts | All report features are functional and data is displayed correctly |
| 10 | Export the report to PDF format | PDF file is generated and downloaded successfully |
| 11 | Navigate to the system audit logs section | Audit logs page is accessible and displays recent activity |
| 12 | Search audit logs for report access events by both unauthorized and authorized users | Audit logs show denied access attempt by unauthorized user with timestamp, user ID, and action attempted, and successful access by authorized Scheduler user with timestamp, user ID, and report generated |
| 13 | Verify the audit log entries contain complete information including user identity, timestamp, action, and outcome | All access events are recorded correctly with complete details and proper categorization of success/failure |

**Postconditions:**
- Unauthorized user remains blocked from accessing reports
- Authorized Scheduler user retains full access to reporting functionality
- All access attempts are properly logged in audit trail
- System security controls are verified as functional
- No unauthorized data access occurred

---

