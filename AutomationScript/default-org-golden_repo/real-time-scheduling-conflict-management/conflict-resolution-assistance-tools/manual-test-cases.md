# Manual Test Cases

## Story: As Scheduler, I want to view a history log of scheduling conflicts to analyze and improve scheduling practices
**Story ID:** story-5

### Test Case: Verify conflict history retrieval with filters
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Scheduler role
- Conflict history database contains at least 20 conflict records
- Conflicts exist for multiple date ranges and resources
- User has authorization to access conflict history

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to conflict history page by clicking on 'Conflict History' menu item | Conflict history page loads successfully displaying empty filter form with fields for date range, resource, and conflict type. Default view shows paginated list of all conflicts |
| 2 | Select start date as '01/01/2024' and end date as '01/31/2024' in date range filter | Date range filter accepts the input and displays selected dates |
| 3 | Select a specific resource 'Conference Room A' from resource dropdown filter | Resource filter displays selected resource |
| 4 | Click 'Apply Filters' button | System processes filters and displays filtered conflict records. Loading indicator appears during processing |
| 5 | Review the displayed conflict records in the results table | Only conflicts matching the filter criteria are shown: conflicts between 01/01/2024 and 01/31/2024 for Conference Room A. Each record displays conflict ID, date, resource, type, and status |
| 6 | Verify each displayed record's date falls within selected range and resource matches filter | All displayed records have dates between 01/01/2024 and 01/31/2024 and resource is 'Conference Room A'. No records outside filter criteria are shown |

**Postconditions:**
- Filtered conflict records remain displayed on screen
- Filter selections remain active and visible
- User can apply additional filters or clear existing ones
- System maintains filter state for current session

---

### Test Case: Validate export functionality for conflict history
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in with Scheduler role
- Conflict history page is accessible
- At least 10 conflict records exist in the database
- User has export permissions enabled
- Browser allows file downloads

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to conflict history page | Conflict history page loads with list of all conflicts and filter options visible |
| 2 | Apply date range filter from '01/01/2024' to '01/15/2024' | Date filter is applied successfully |
| 3 | Select conflict type 'Resource Double Booking' from type filter dropdown | Type filter is applied successfully |
| 4 | Click 'Apply Filters' button | Filtered results are displayed showing only conflicts matching date range and type criteria. Record count is visible |
| 5 | Click 'Export to CSV' button | CSV file download initiates immediately. File name follows format 'conflict_history_YYYYMMDD.csv'. Download progress is visible |
| 6 | Open downloaded CSV file in spreadsheet application | CSV file opens successfully and contains all filtered conflict records with columns: Conflict ID, Date, Time, Resource, Type, Status, Description. Data matches what was displayed on screen |
| 7 | Return to conflict history page and click 'Export to PDF' button | PDF file download initiates. File name follows format 'conflict_history_YYYYMMDD.pdf'. Download progress is visible |
| 8 | Open downloaded PDF file in PDF reader | PDF file opens successfully with professional formatting. Contains header with export date, filtered conflict records in table format with all relevant columns, and footer with page numbers. Data matches filtered results |

**Postconditions:**
- Two files are downloaded: CSV and PDF formats
- Both files contain identical filtered data
- Original filtered view remains unchanged on screen
- Export action is logged in system audit trail
- Files are saved to user's default download location

---

### Test Case: Ensure access control for conflict history
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Test user account exists without Scheduler role or conflict history permissions
- Conflict history feature is enabled in the system
- Access control rules are configured properly
- User is logged into the system with unauthorized account

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in to the system using unauthorized user credentials (user without Scheduler role) | User successfully logs into the system with limited permissions |
| 2 | Attempt to navigate to conflict history page by entering URL '/conflicts/history' directly in browser | System blocks access and redirects to error page or dashboard |
| 3 | Verify error message displayed on screen | Clear error message is displayed: 'Access Denied: You do not have permission to view conflict history. Please contact your administrator.' HTTP 403 Forbidden status is returned |
| 4 | Check main navigation menu for conflict history option | Conflict history menu item is not visible or is disabled/grayed out for unauthorized user |
| 5 | Attempt to access conflict history API endpoint directly using GET /conflicts/history | API returns 403 Forbidden error with JSON response containing error message about insufficient permissions |

**Postconditions:**
- Unauthorized user remains unable to access conflict history
- Access attempt is logged in security audit log
- User session remains active but restricted
- No conflict data is exposed to unauthorized user
- System security integrity is maintained

---

## Story: As Scheduler, I want the system to log all detected conflicts for audit and compliance purposes
**Story ID:** story-8

### Test Case: Verify all conflicts are logged with metadata
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Conflict detection engine is running and operational
- Logging service is active and connected to database
- Test scheduling data exists with potential conflicts
- User has access to query log database
- System time is synchronized correctly

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Create a scheduling conflict by attempting to book 'Conference Room A' for two different meetings at the same time slot (2:00 PM - 3:00 PM on 02/15/2024) | System detects the scheduling conflict and displays conflict alert to user. Conflict detection engine triggers immediately |
| 2 | Note the conflict ID and timestamp displayed in the conflict alert | Conflict alert shows unique conflict ID (e.g., CONF-2024-001234) and timestamp of detection |
| 3 | Access the logging database using authorized query tool or admin interface | Successfully connected to logging database with read permissions |
| 4 | Query logs for the conflict entry using conflict ID: SELECT * FROM conflict_logs WHERE conflict_id = 'CONF-2024-001234' | Log entry is retrieved successfully from database |
| 5 | Verify log entry contains all required metadata fields | Log entry contains: conflict_id, timestamp, conflict_type (Resource Double Booking), resource_id (Conference Room A), affected_bookings (both booking IDs), severity_level, detection_method, system_version, user_id_initiator, and conflict_description |
| 6 | Validate timestamp accuracy by comparing log timestamp with conflict detection time | Log timestamp matches conflict detection time within 1 second accuracy |
| 7 | Verify all metadata values are accurate and complete | All metadata fields contain correct, non-null values matching the actual conflict scenario. Resource ID, booking IDs, and user information are accurate |

**Postconditions:**
- Conflict is permanently logged in database
- Log entry is immutable and timestamped
- Conflict remains in detected state until resolved
- Log is available for future audit queries
- System continues monitoring for new conflicts

---

### Test Case: Validate user action logging on conflicts
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Active scheduling conflict exists in the system
- Conflict alert is displayed to user
- User is logged in with Scheduler role
- Logging service is operational
- User action tracking is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Locate an active conflict alert displayed on the dashboard showing conflict ID 'CONF-2024-001235' | Conflict alert is visible with options to 'Acknowledge' or 'Dismiss' the conflict |
| 2 | Click 'Acknowledge' button on the conflict alert | System processes acknowledgment. Conflict status changes to 'Acknowledged'. Confirmation message appears: 'Conflict acknowledged successfully' |
| 3 | Access logging database and query for user action: SELECT * FROM conflict_logs WHERE conflict_id = 'CONF-2024-001235' AND action_type = 'ACKNOWLEDGE' | Log entry for acknowledgment action is retrieved |
| 4 | Verify log entry contains user action details | Log entry includes: conflict_id, action_type (ACKNOWLEDGE), user_id, username, action_timestamp, previous_status, new_status (Acknowledged), ip_address, and session_id |
| 5 | Create another conflict and click 'Dismiss' button on the conflict alert | Conflict is dismissed. Status changes to 'Dismissed'. Confirmation message appears |
| 6 | Query logs for dismiss action on the new conflict | Log entry for dismiss action is found with action_type 'DISMISS' and all required metadata including user information and timestamp |
| 7 | Verify chronological order of logged actions | All user actions are logged in correct chronological sequence with accurate timestamps showing progression of conflict handling |

**Postconditions:**
- All user actions are permanently recorded in logs
- Audit trail is complete and traceable
- Conflict status reflects latest user action
- Logs maintain data integrity
- User action history is available for compliance review

---

### Test Case: Ensure logs are securely stored and retrievable
- **ID:** tc-006
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Conflict logs exist in the database
- Encryption is enabled for log storage
- Authorized user credentials are available
- Unauthorized test user account exists
- Audit access interface is configured

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in to the system using authorized auditor credentials with log access permissions | Successfully authenticated and logged into system with auditor role |
| 2 | Navigate to audit log access interface or admin panel | Audit log interface loads successfully showing log query options |
| 3 | Execute query to retrieve conflict logs from the past 30 days: SELECT * FROM conflict_logs WHERE log_date >= CURRENT_DATE - 30 | Query executes successfully and returns list of conflict log entries |
| 4 | Verify data integrity by checking log entry completeness and format | All log entries are intact with complete data fields. No corruption or missing data detected. Timestamps are sequential and logical |
| 5 | Verify encryption status by checking database storage configuration | Logs are stored with encryption enabled. Encryption algorithm (e.g., AES-256) is confirmed. Encrypted fields include sensitive data like user information and conflict details |
| 6 | Export a sample of logs to verify data is decrypted properly for authorized access | Exported logs are readable and properly decrypted. All data fields are accessible and in correct format |
| 7 | Log out and log in using unauthorized user credentials without audit access permissions | Successfully logged in as unauthorized user with limited permissions |
| 8 | Attempt to access audit log interface or query conflict logs directly | Access is denied. Error message displayed: 'Access Denied: Insufficient permissions to view audit logs.' HTTP 403 Forbidden status returned |
| 9 | Attempt to access log database directly using unauthorized credentials | Database connection is refused or authentication fails. No log data is accessible. Security event is logged |
| 10 | Verify unauthorized access attempt is logged in security audit trail | Security log contains entry for unauthorized access attempt with user ID, timestamp, attempted resource, and denial reason |

**Postconditions:**
- Authorized users can access logs successfully
- Unauthorized access attempts are blocked and logged
- Log data integrity is maintained
- Encryption remains active on stored logs
- Audit trail includes both successful and failed access attempts
- System security posture is verified and intact

---

## Story: As Scheduler, I want the system to provide suggestions for alternative scheduling options when conflicts occur to facilitate quick resolution
**Story ID:** story-10

### Test Case: Validate generation of alternative scheduling suggestions
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Scheduler role
- At least one appointment exists in the system
- Multiple resources are available in the system
- Scheduling UI is accessible
- Resource availability data is up to date

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the scheduling interface | Scheduling interface loads successfully with calendar view |
| 2 | Attempt to schedule an appointment that conflicts with an existing appointment (same resource, overlapping time) | System detects the scheduling conflict and displays a conflict notification |
| 3 | Trigger the alternative suggestions feature by clicking on 'View Alternatives' or similar option | Alternative scheduling suggestions are automatically generated and displayed |
| 4 | Review the suggestions displayed in the UI | Suggestions are clearly displayed showing available time slots with corresponding available resources, including date, time, and resource name |
| 5 | Select one of the suggested alternative time slots from the list | Selected suggestion is highlighted and a confirmation or apply button becomes active |
| 6 | Click the apply or confirm button to apply the selected suggestion | Appointment is successfully updated with the new time slot and resource, conflict is resolved, and confirmation message is displayed |
| 7 | Verify the updated appointment in the calendar view | Appointment appears in the calendar at the new time slot with the assigned resource, no conflict indicators are present |

**Postconditions:**
- Appointment is successfully rescheduled without conflicts
- Original conflicting time slot remains occupied by the existing appointment
- New time slot is now occupied by the rescheduled appointment
- System logs the rescheduling action
- Resource availability is updated in the system

---

### Test Case: Verify suggestion generation latency under 2 seconds
- **ID:** tc-002
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in with Scheduler role
- System has normal load conditions
- Multiple resources and appointments exist in the database
- Timing measurement tool or browser developer tools are available
- Network connection is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open browser developer tools and navigate to the Network tab to monitor API response times | Developer tools are open and ready to capture network activity |
| 2 | Navigate to the scheduling interface | Scheduling interface loads successfully |
| 3 | Attempt to create an appointment that will trigger a scheduling conflict | Conflict is detected by the system |
| 4 | Note the timestamp when requesting alternative suggestions and trigger the suggestion generation | Request is sent to GET /scheduling/alternatives API endpoint, timestamp is recorded |
| 5 | Monitor the Network tab for the API response time | API response is received and displayed in the Network tab with timing information |
| 6 | Verify the total time from request initiation to suggestions appearing in the UI | Alternative suggestions appear in the UI within 2 seconds of the request, API response time is under 2 seconds as shown in developer tools |
| 7 | Repeat the test 3 more times with different conflict scenarios to ensure consistent performance | All iterations complete suggestion generation within 2 seconds |

**Postconditions:**
- Performance metrics are documented
- System meets the 2-second latency requirement
- No performance degradation is observed
- Test results are logged for reporting

---

### Test Case: Ensure suggestions reflect current resource availability
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- User is logged in with Scheduler role
- Multiple resources exist in the system with known schedules
- Some resources have appointments scheduled, others are available
- Resource availability data is current and accurate
- Access to view resource schedules independently is available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open the resource management view and document the current availability of all resources including their scheduled appointments | Resource schedules are visible showing occupied and available time slots for each resource |
| 2 | Identify specific time slots where certain resources are already booked | Booked time slots and resources are clearly identified and documented |
| 3 | Navigate to the scheduling interface and attempt to create an appointment that triggers a conflict | Conflict is detected and conflict notification appears |
| 4 | Request alternative scheduling suggestions | System generates and displays alternative suggestions |
| 5 | Review each suggested time slot and resource combination | All suggestions display specific time slots with assigned resources |
| 6 | Cross-reference each suggested resource and time slot against the documented resource schedules from step 1 | All suggested resources are confirmed to be available during the suggested time slots, no suggestions include resources that are already booked |
| 7 | Verify that resources with known conflicts during suggested times are NOT included in the suggestions | Suggestions exclude any resources that have existing appointments during the suggested time slots |
| 8 | Check that the suggestions only include time slots within valid scheduling hours and resource working hours | All suggested time slots fall within appropriate business hours and resource availability windows |

**Postconditions:**
- All suggestions are verified to reflect accurate resource availability
- No double-booking scenarios are present in suggestions
- Resource schedule integrity is maintained
- Test validation results are documented

---

