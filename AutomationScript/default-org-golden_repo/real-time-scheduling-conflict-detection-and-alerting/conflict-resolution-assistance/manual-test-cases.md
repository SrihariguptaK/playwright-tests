# Manual Test Cases

## Story: As Scheduler, I want to view detailed conflict history to analyze and prevent recurring scheduling issues
**Story ID:** story-15

### Test Case: Verify conflict logging and retrieval
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User has scheduler role with conflict history access permissions
- User is logged into the scheduling system
- Conflict logs database is accessible and operational
- At least one scheduling conflict exists in the system
- Test data includes conflicts with various types and date ranges

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Create a scheduling conflict by attempting to book two appointments for the same resource at overlapping times | System detects the conflict and prevents the double booking |
| 2 | Verify the conflict is logged by checking the conflict logs database | Conflict is logged with complete details including timestamp, resource ID, conflicting appointment IDs, conflict type, and involved parties |
| 3 | Navigate to the conflict history section from the main menu | Conflict history UI loads successfully and displays the conflict history dashboard |
| 4 | Apply date range filter to show conflicts from the last 7 days | System displays only conflicts that occurred within the specified date range |
| 5 | Apply resource filter to show conflicts for a specific resource | System displays only conflicts involving the selected resource |
| 6 | Apply conflict type filter to show specific conflict types | System displays only conflicts matching the selected conflict type |
| 7 | Verify the filtered conflict records display all required information including involved appointments and resolution status | Each conflict record shows complete details: timestamp, resource, conflicting appointments, conflict type, resolution status, and involved parties |
| 8 | Select export option and choose CSV format | Export dialog appears with format options including CSV, PDF, and Excel |
| 9 | Confirm export and download the conflict history report | Report is generated successfully and downloaded in CSV format containing all filtered conflict records with complete details |
| 10 | Open the downloaded CSV file and verify data integrity | CSV file contains accurate conflict data matching the filtered results displayed in the UI |

**Postconditions:**
- All conflicts remain logged in the database
- Exported report is saved to the user's download folder
- Audit log records the export action with user ID and timestamp
- System state remains unchanged

---

### Test Case: Validate access control for conflict history
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Two user accounts exist: one without conflict history permissions and one with valid permissions
- Both users are registered in the system
- Conflict history data exists in the database
- Access control rules are properly configured
- Authentication system is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into the system using credentials of a user without conflict history access permissions | User successfully logs in and reaches the main dashboard |
| 2 | Attempt to navigate to the conflict history section via the menu or direct URL | Access is denied and system displays an appropriate error message such as 'You do not have permission to access conflict history' or 'Access Denied - Insufficient Permissions' |
| 3 | Verify that the conflict history menu option is either hidden or disabled for this user | Conflict history option is not visible in the navigation menu or is displayed as disabled/grayed out |
| 4 | Attempt to access conflict history via API endpoint GET /conflicts/history using the unauthorized user's token | API returns 403 Forbidden status code with error message indicating insufficient permissions |
| 5 | Log out from the unauthorized user account | User is successfully logged out and redirected to the login page |
| 6 | Log into the system using credentials of a user with valid conflict history access permissions | User successfully logs in and reaches the main dashboard |
| 7 | Navigate to the conflict history section from the menu | Access is granted and the conflict history UI loads successfully displaying the conflict history dashboard |
| 8 | Verify that conflict data is displayed with all details visible | System displays conflict records with complete information including timestamps, resources, appointments, and resolution status |
| 9 | Verify that the access attempt is logged in the audit log | Audit log contains entries for both the denied access attempt and the successful access with user IDs, timestamps, and action details |

**Postconditions:**
- Unauthorized user remains blocked from conflict history access
- Authorized user retains access to conflict history
- All access attempts are logged in the audit trail
- No data is modified or compromised
- System security remains intact

---

## Story: As Scheduler, I want to override scheduling conflicts with appropriate permissions to handle exceptional cases
**Story ID:** story-17

### Test Case: Allow override with valid permissions
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User has scheduler role with override permissions enabled
- User is logged into the scheduling system
- A resource is already booked for a specific time slot
- Scheduling database is accessible and operational
- Audit logging system is active and functional
- Override permission validation is configured correctly

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the appointment scheduling interface | Appointment scheduling page loads successfully with all booking options available |
| 2 | Select a resource that already has an appointment scheduled | Resource is selected and calendar view shows existing appointment |
| 3 | Attempt to create a new appointment for the same resource at an overlapping time slot | System detects the scheduling conflict |
| 4 | Click Save or Submit to attempt saving the conflicting appointment | System displays a conflict warning dialog showing details of the conflict including existing appointment information and the option to override |
| 5 | Review the conflict details displayed in the warning dialog | Conflict warning shows complete information: conflicting time slots, resource name, existing appointment details, and an 'Override' button is visible |
| 6 | Click the 'Override' button to proceed with saving the conflicting appointment | System validates user's override permissions and processes the override request |
| 7 | Wait for system to complete the override processing | System saves the conflicting appointment successfully within 2 seconds and displays a confirmation message such as 'Appointment saved successfully with conflict override' |
| 8 | Navigate to the audit log or override log section | Override log interface loads successfully |
| 9 | Search for the most recent override entry using timestamp or appointment ID | Override log entry is found and displayed |
| 10 | Verify the override log entry contains all required details | Log entry includes user ID of the scheduler who performed the override, exact timestamp of the override action, conflict details including both appointment IDs, resource information, and override reason if provided |
| 11 | Verify both appointments are now visible in the schedule for the same resource | Calendar view shows both the original and the newly created appointment for the same resource at overlapping times, marked with conflict indicator |

**Postconditions:**
- Conflicting appointment is saved in the database
- Override action is logged in audit trail with complete details
- Both appointments remain active in the system
- Resource shows double-booking in the schedule
- System performance metrics show override completed within 2 seconds SLA

---

### Test Case: Prevent override without permissions
- **ID:** tc-004
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User has scheduler role but does NOT have override permissions
- User is logged into the scheduling system
- A resource is already booked for a specific time slot
- Permission validation system is properly configured
- Scheduling database is accessible and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into the system using credentials of a user without override permissions | User successfully logs in and reaches the scheduling dashboard |
| 2 | Navigate to the appointment scheduling interface | Appointment scheduling page loads successfully |
| 3 | Select a resource that already has an appointment scheduled | Resource is selected and calendar view displays the existing appointment |
| 4 | Attempt to create a new appointment for the same resource at an overlapping time slot | System detects the scheduling conflict |
| 5 | Fill in all required appointment details and click Save or Submit | System displays a conflict warning dialog showing details of the conflict |
| 6 | Verify the conflict warning dialog does not show an override option | Override button is either not visible or is disabled/grayed out due to insufficient permissions |
| 7 | Attempt to save the appointment by clicking any available save or confirm button | System blocks the save operation and displays an error message such as 'Cannot save conflicting appointment - Override permission required' or 'Access Denied - Insufficient permissions to override conflicts' |
| 8 | Verify the appointment was not saved by checking the schedule | Only the original appointment is visible in the schedule; the conflicting appointment was not created |
| 9 | Check the database to confirm no new appointment record was created | Database query confirms no new appointment exists for the attempted time slot |
| 10 | Verify the failed override attempt is logged in the audit trail | Audit log contains an entry showing the denied override attempt with user ID, timestamp, and reason for denial (insufficient permissions) |

**Postconditions:**
- Conflicting appointment is NOT saved in the database
- Original appointment remains unchanged
- Failed override attempt is logged in audit trail
- User receives clear error message about insufficient permissions
- System security and access controls remain enforced
- No unauthorized data modifications occurred

---

## Story: As Scheduler, I want to view resource availability in real-time to make informed scheduling decisions
**Story ID:** story-18

### Test Case: Display real-time resource availability
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in with Scheduler role and valid permissions
- Resource availability dashboard is accessible
- At least one resource exists in the system with known availability status
- System is connected to scheduling databases and APIs
- Real-time update mechanism is functioning

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the resource availability dashboard from the main menu | Resource availability dashboard loads successfully and displays all available resources with their current status (Available, Booked, Unavailable) |
| 2 | Verify that the displayed availability data matches the current state of resources in the system | All resource availability statuses are accurate and reflect the current state, including upcoming bookings and time slots |
| 3 | Select a specific resource from the availability dashboard | Detailed availability view for the selected resource is displayed, showing time slots, bookings, and availability status |
| 4 | Create a new appointment for the selected resource in a previously available time slot | Appointment is created successfully and saved to the system |
| 5 | Observe the resource availability dashboard and note the timestamp | The availability status for the resource updates to reflect the new booking within 5 seconds, showing the time slot as now booked |
| 6 | Modify an existing appointment by changing its time or duration to affect resource availability | Appointment modification is saved successfully |
| 7 | Monitor the resource availability dashboard for real-time updates | The availability view updates within 5 seconds to reflect the modified appointment, showing updated available and booked time slots |
| 8 | Attempt to schedule another appointment in a time slot that would create a conflict with existing bookings | System displays conflict indicators clearly on the availability view, highlighting the overlapping time slots with visual markers (e.g., red highlighting, warning icons) |
| 9 | Verify that conflict indicators are visible and accurately represent the scheduling conflict | Conflicts are clearly marked with appropriate visual indicators, tooltips or messages explaining the nature of the conflict, and the conflicting appointments are identifiable |

**Postconditions:**
- Resource availability data reflects all changes made during the test
- All created and modified appointments are saved in the system
- Conflict indicators are displayed where applicable
- Dashboard remains in a stable state for further use
- Real-time update mechanism continues to function properly

---

### Test Case: Ensure secure access to resource availability data
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- System has role-based access control configured
- Test user accounts exist with different permission levels (with and without resource availability access)
- Resource availability data exists in the system
- Authentication and authorization mechanisms are active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log out from any existing session to ensure a clean test state | User is successfully logged out and redirected to the login page |
| 2 | Log in with a user account that does not have permissions to access resource availability data (e.g., a user with 'Guest' or 'Limited User' role) | User is successfully authenticated and logged into the system |
| 3 | Attempt to navigate to the resource availability dashboard through the application menu | Resource availability dashboard option is either not visible in the menu or is disabled/grayed out |
| 4 | Attempt to directly access the resource availability dashboard using the direct URL or endpoint (e.g., /resources/availability) | Access is denied with an appropriate error message (e.g., '403 Forbidden' or 'You do not have permission to access this resource'), and user is redirected to an error page or their home dashboard |
| 5 | Verify that no resource availability data is displayed or accessible through any alternative navigation paths | No resource availability information is visible or accessible to the unauthorized user |
| 6 | Log out from the unauthorized user account | User is successfully logged out |
| 7 | Log in with a user account that has valid permissions to access resource availability data (e.g., 'Scheduler' role) | User is successfully authenticated and logged into the system with Scheduler privileges |
| 8 | Navigate to the resource availability dashboard from the main menu | Resource availability dashboard option is visible and accessible in the menu |
| 9 | Access the resource availability dashboard | Dashboard loads successfully and displays complete resource availability data including all resources, their statuses, bookings, and availability time slots |
| 10 | Verify that all expected features and data are accessible (calendar view, timeline view, resource details, conflict indicators) | All resource availability features and data are fully accessible and displayed correctly with no restrictions |

**Postconditions:**
- Unauthorized access attempts are logged in the system audit trail
- Authorized user has full access to resource availability data
- Security controls remain intact and functional
- No unauthorized data exposure occurred during the test
- User sessions are properly managed and secured

---

