# Manual Test Cases

## Story: As Scheduler, I want to detect overlapping appointments to avoid double bookings
**Story ID:** story-11

### Test Case: Validate detection of overlapping appointments
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Scheduler role
- Scheduling system is accessible and operational
- At least one resource is available in the system
- User has permissions to create and modify appointments
- Database is in a clean state with no existing conflicts

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the appointment scheduling interface | Appointment scheduling page loads successfully with all fields visible |
| 2 | Select a resource from the available resources dropdown | Resource is selected and displayed in the resource field |
| 3 | Enter appointment details: Date (today's date), Start time (10:00 AM), End time (11:00 AM), and other required fields | All appointment details are entered and displayed correctly in the form |
| 4 | Click the 'Save' or 'Create Appointment' button | Appointment is saved successfully, confirmation message is displayed, and appointment appears in the schedule |
| 5 | Navigate back to the appointment scheduling interface to create a new appointment | New appointment form is displayed and ready for input |
| 6 | Select the same resource used in the first appointment | Same resource is selected and displayed in the resource field |
| 7 | Enter overlapping appointment details: Same date, Start time (10:30 AM), End time (11:30 AM), and other required fields | Overlapping appointment details are entered in the form |
| 8 | Click the 'Save' or 'Create Appointment' button | System detects the conflict and displays an alert/warning message indicating an overlapping appointment exists |
| 9 | Review the conflict alert details displayed on screen | Alert displays accurate conflicting appointment details including resource name, original appointment time (10:00 AM - 11:00 AM), conflicting time period (10:30 AM - 11:00 AM), and appointment ID or reference |
| 10 | Verify that the overlapping appointment was not saved to the schedule | Only the first appointment is visible in the schedule; the overlapping appointment was not created |

**Postconditions:**
- Only one appointment exists for the resource in the specified time slot
- Conflict alert has been displayed and acknowledged
- System remains in a consistent state with no double bookings
- Original appointment remains unchanged

---

### Test Case: Verify conflict detection latency under 2 seconds
- **ID:** tc-002
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in with Scheduler role
- Scheduling system is accessible and operational
- At least one resource with an existing appointment is available
- Performance monitoring tool or browser developer tools are available to measure response time
- System is under normal load conditions

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open browser developer tools and navigate to the Network tab to monitor request timing | Developer tools are open and Network tab is active and recording |
| 2 | Navigate to the appointment scheduling interface | Appointment scheduling page loads successfully |
| 3 | Create a baseline appointment: Select a resource, enter Date (today), Start time (2:00 PM), End time (3:00 PM), and save | Baseline appointment is created successfully and visible in the schedule |
| 4 | Clear the Network tab in developer tools to start fresh timing measurement | Network tab is cleared and ready to record new requests |
| 5 | Start a timer and create an overlapping appointment: Select the same resource, enter Date (today), Start time (2:30 PM), End time (3:30 PM) | Overlapping appointment details are entered in the form |
| 6 | Click 'Save' button and immediately note the timestamp | System processes the request and conflict detection begins |
| 7 | Observe when the conflict alert appears on screen and note the timestamp | Conflict alert is displayed on screen |
| 8 | Calculate the time difference between clicking 'Save' and the conflict alert appearing | Time difference is calculated successfully |
| 9 | Verify the calculated time in the Network tab by checking the response time of the conflict detection API call | Network tab shows the API response time for conflict detection is under 2 seconds (≤ 2000ms) |
| 10 | Repeat steps 4-9 for modifying an existing appointment to create a conflict | Modification conflict detection also completes within 2 seconds |

**Postconditions:**
- Conflict detection latency is documented and verified to be under 2 seconds
- System performance meets the specified requirement
- No appointments were saved that caused conflicts
- System remains responsive and operational

---

### Test Case: Ensure logging of detected conflicts
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- User is logged in with Scheduler role and has access to conflict logs
- Scheduling system is accessible and operational
- Logging functionality is enabled in the system
- At least one resource is available for scheduling
- User has permissions to view system logs or audit trails

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the appointment scheduling interface | Appointment scheduling page loads successfully |
| 2 | Create a first appointment: Select Resource 'Conference Room A', Date (today), Start time (9:00 AM), End time (10:00 AM), and save | First appointment is created successfully and saved to the schedule |
| 3 | Note the current system time before creating the conflicting appointment | Current timestamp is recorded for later verification |
| 4 | Attempt to create an overlapping appointment: Select same Resource 'Conference Room A', Date (today), Start time (9:30 AM), End time (10:30 AM), and click Save | System detects the conflict and displays an alert without saving the appointment |
| 5 | Acknowledge or close the conflict alert | Alert is dismissed and user returns to the scheduling interface |
| 6 | Navigate to the conflict logs section (may be under Admin, Reports, or Audit Logs menu) | Conflict logs page or section loads successfully |
| 7 | Search or filter logs for conflicts that occurred around the noted timestamp | Log entries are filtered and displayed for the relevant time period |
| 8 | Locate the log entry for the conflict just triggered | A log entry exists for the detected conflict with a timestamp matching the conflict occurrence time |
| 9 | Review the log entry details for completeness | Log contains: Timestamp of conflict detection, Resource name (Conference Room A), Original appointment time (9:00 AM - 10:00 AM), Conflicting appointment time (9:30 AM - 10:30 AM), User who attempted the booking, Appointment IDs or references, Conflict status |
| 10 | Verify the timestamp format and accuracy in the log entry | Timestamp is in correct format (ISO 8601 or system standard) and matches the time when conflict was detected |
| 11 | Verify all resource details are accurately logged | Resource ID, resource name, and resource type are all correctly recorded in the log entry |

**Postconditions:**
- Conflict is logged in the system with complete metadata
- Log entry is persistent and retrievable
- No conflicting appointment was saved to the schedule
- Audit trail is maintained for compliance and review purposes

---

## Story: As Resource Manager, I want to detect double bookings of resources to optimize utilization
**Story ID:** story-12

### Test Case: Validate detection of double bookings for resources
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in with Resource Manager role
- Resource management system is accessible and operational
- Multiple resource types (rooms, equipment) are configured in the system
- User has permissions to create and modify resource bookings
- Database is in a clean state with no existing booking conflicts

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the resource booking interface | Resource booking page loads successfully with all booking fields and resource list visible |
| 2 | Select a resource type 'Equipment' from the resource type dropdown | Equipment resource type is selected and available equipment list is displayed |
| 3 | Select a specific resource 'Projector-001' from the equipment list | Projector-001 is selected and displayed in the resource field |
| 4 | Enter booking details: Date (tomorrow's date), Start time (1:00 PM), End time (3:00 PM), Purpose 'Team Presentation', and other required fields | All booking details are entered correctly and displayed in the form |
| 5 | Click the 'Save' or 'Book Resource' button | Booking is saved successfully, confirmation message appears, and booking is visible in the resource schedule |
| 6 | Navigate back to the resource booking interface to create a new booking | New resource booking form is displayed and ready for input |
| 7 | Select the same resource type 'Equipment' and the same resource 'Projector-001' | Projector-001 is selected again in the new booking form |
| 8 | Enter overlapping booking details: Same date (tomorrow), Start time (2:00 PM), End time (4:00 PM), Purpose 'Client Meeting', and other required fields | Overlapping booking details are entered in the form |
| 9 | Click the 'Save' or 'Book Resource' button | System detects the double booking conflict and displays an alert/warning message to the Resource Manager |
| 10 | Review the conflict alert details displayed on screen | Alert shows accurate conflicting booking information including: Resource name (Projector-001), Resource type (Equipment), Original booking time (1:00 PM - 3:00 PM), Conflicting time period (2:00 PM - 3:00 PM), Original booking purpose, Booking reference numbers |
| 11 | Verify that the overlapping booking was not saved to the schedule | Only the first booking for Projector-001 is visible in the schedule; the double booking was prevented |
| 12 | Check the resource availability calendar for Projector-001 | Calendar shows Projector-001 as booked only from 1:00 PM - 3:00 PM tomorrow, with no double booking |

**Postconditions:**
- Only one booking exists for Projector-001 in the specified time slot
- Double booking alert has been displayed and acknowledged
- System maintains data integrity with no conflicting bookings
- Resource utilization data remains accurate
- Original booking remains unchanged and valid

---

### Test Case: Verify real-time detection latency under 2 seconds
- **ID:** tc-005
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- User is logged in with Resource Manager role
- Resource management system is accessible and operational
- At least one resource with an existing booking is available in the system
- Performance monitoring tool or browser developer tools are available
- System is under normal operational load
- Network connection is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open browser developer tools and navigate to the Network tab | Developer tools are open with Network tab active and recording network activity |
| 2 | Navigate to the resource booking interface | Resource booking page loads successfully |
| 3 | Create a baseline booking: Select resource 'Meeting Room B', Date (next Monday), Start time (10:00 AM), End time (11:30 AM), and save | Baseline booking is created successfully and appears in the resource schedule |
| 4 | Clear the Network tab in developer tools to prepare for timing measurement | Network tab is cleared and ready to record new requests |
| 5 | Prepare a stopwatch or timer application to measure response time | Timer is ready to start measurement |
| 6 | Create a conflicting booking: Select same resource 'Meeting Room B', Date (next Monday), Start time (11:00 AM), End time (12:00 PM), and fill all required fields | Conflicting booking details are entered in the form |
| 7 | Start the timer and immediately click the 'Save' or 'Book Resource' button, noting the exact timestamp | System processes the booking request and timer is running |
| 8 | Observe when the double booking conflict alert appears on screen and stop the timer | Conflict alert is displayed and timer is stopped |
| 9 | Record the elapsed time from clicking 'Save' to alert appearance | Elapsed time is recorded (should be ≤ 2 seconds) |
| 10 | Verify the timing in the Network tab by locating the conflict detection API call (e.g., POST /resources/bookings or GET /resources/conflicts) | API call is visible in Network tab with response time displayed |
| 11 | Check the response time of the conflict detection API call | API response time is under 2000ms (2 seconds) |
| 12 | Repeat the test by modifying an existing booking to create a conflict: Edit the baseline booking to extend end time to 12:00 PM, measure detection time | Modification conflict detection also completes within 2 seconds |
| 13 | Document all timing measurements for both creation and modification scenarios | All measurements are documented and show latency under 2 seconds |

**Postconditions:**
- Conflict detection latency is verified to be under 2 seconds for both scenarios
- Performance requirement is met and documented
- No conflicting bookings were saved to the system
- System remains responsive and operational
- Performance metrics are recorded for future reference

---

### Test Case: Ensure logging of resource booking conflicts
- **ID:** tc-006
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- User is logged in with Resource Manager role
- User has permissions to access conflict logs and audit trails
- Resource management system is accessible and operational
- Logging functionality is enabled and configured correctly
- At least one resource is available for booking
- Log viewing interface is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the resource booking interface | Resource booking page loads successfully |
| 2 | Create a first booking: Select Resource Type 'Room', Resource 'Training Room 3', Date (next Friday), Start time (2:00 PM), End time (4:00 PM), Purpose 'Training Session', and save | First booking is created successfully and saved to the system |
| 3 | Note the current system timestamp before triggering the conflict | Current timestamp is recorded (e.g., 2024-01-15 14:23:45) for later log verification |
| 4 | Attempt to create a double booking: Select Resource Type 'Room', Resource 'Training Room 3', Date (next Friday), Start time (3:00 PM), End time (5:00 PM), Purpose 'Workshop', and click Save | System detects the double booking conflict and displays an alert without saving the booking |
| 5 | Read and acknowledge the conflict alert message | Alert is acknowledged and dismissed, user returns to booking interface |
| 6 | Navigate to the conflict logs section (typically under Reports, Audit Logs, or System Logs menu) | Conflict logs page loads successfully with search and filter options visible |
| 7 | Apply filters: Set date/time range around the noted timestamp, Resource Type 'Room', and Conflict Type 'Double Booking' | Filters are applied and log entries are filtered accordingly |
| 8 | Search for the log entry corresponding to the triggered double booking conflict | Log entry for the conflict is found and displayed in the results |
| 9 | Click on or expand the log entry to view full details | Complete log entry details are displayed |
| 10 | Verify the log entry contains the conflict timestamp | Timestamp is present and matches the time when conflict was detected (within seconds of noted time) |
| 11 | Verify the log entry contains resource information | Log shows: Resource ID, Resource Name (Training Room 3), Resource Type (Room) |
| 12 | Verify the log entry contains original booking details | Log shows: Original booking time (2:00 PM - 4:00 PM), Original booking purpose (Training Session), Original booking ID/reference |
| 13 | Verify the log entry contains conflicting booking attempt details | Log shows: Attempted booking time (3:00 PM - 5:00 PM), Attempted booking purpose (Workshop), Overlapping time period (3:00 PM - 4:00 PM) |
| 14 | Verify the log entry contains user information | Log shows: Username or User ID of the person who attempted the double booking, User role (Resource Manager) |
| 15 | Verify the log entry contains conflict resolution status | Log shows: Conflict Status (Detected/Prevented), Action Taken (Booking Rejected), Override Status (Not Overridden) |
| 16 | Export or print the log entry for documentation | Log entry is successfully exported in the required format (PDF, CSV, or print) |

**Postconditions:**
- Double booking conflict is fully logged with complete metadata
- Log entry is persistent and retrievable for audit purposes
- No conflicting booking was saved to the system
- Resource schedule remains accurate with only the original booking
- Audit trail is maintained for compliance and reporting
- Log data can be used for analysis and reporting

---

## Story: As Scheduler, I want the system to support conflict detection for recurring events to prevent repeated scheduling errors
**Story ID:** story-20

### Test Case: Validate detection of conflicts in recurring events
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User has Scheduler role with permissions to create events
- Scheduling database is accessible and operational
- Conflict detection engine is enabled
- User is authenticated and logged into the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the event creation interface | Event creation form is displayed with all required fields |
| 2 | Enter event details: Title='Weekly Team Meeting', Start Time='10:00 AM', End Time='11:00 AM', Recurrence Pattern='Weekly', Days='Monday', Start Date='Current Date', End Date='3 months from current date' | All event details are populated correctly in the form |
| 3 | Click 'Save' or 'Create Event' button | System validates the recurring event, processes the recurrence pattern, and displays success message 'Recurring event created successfully'. Event is saved to the scheduling database |
| 4 | Navigate to create a new event that conflicts with the recurring event | New event creation form is displayed |
| 5 | Enter conflicting event details: Title='Training Session', Start Time='10:30 AM', End Time='11:30 AM', Date='Next Monday' (overlaps with recurring event instance) | Event details are entered into the form |
| 6 | Click 'Save' or 'Create Event' button | System detects the conflict with the recurring event instance and displays a conflict alert message containing: conflicting event name ('Weekly Team Meeting'), date and time of conflict, and details about the recurring pattern |
| 7 | Review the conflict alert details | Alert clearly identifies the specific instance(s) of the recurring event that conflict, shows the overlapping time period, and provides options to modify or cancel the new event |

**Postconditions:**
- Recurring event remains saved in the system
- Conflicting event is not saved until conflict is resolved
- Conflict alert is displayed to the user
- System maintains data integrity with no duplicate or overlapping events

---

### Test Case: Verify detection latency for recurring event conflicts
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User has Scheduler role with permissions to create and modify events
- Scheduling database contains existing events
- Conflict detection engine is operational
- Performance monitoring tools are available to measure response time
- User is authenticated and logged into the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the event creation interface | Event creation form is displayed |
| 2 | Enter recurring event details: Title='Daily Standup', Start Time='9:00 AM', End Time='9:30 AM', Recurrence Pattern='Daily', Start Date='Current Date', End Date='1 month from current date' | Recurring event details are populated in the form |
| 3 | Start timer/performance monitoring tool and click 'Save' or 'Create Event' button | Timer starts and system begins processing the recurring event |
| 4 | Observe system processing and wait for response | System analyzes the recurrence pattern, checks all instances against existing events for conflicts, and completes processing |
| 5 | Stop timer when conflict detection completes and system displays result (success message or conflict alert) | Timer stops and elapsed time is recorded. System displays appropriate message indicating completion of conflict detection |
| 6 | Review the measured conflict detection time | Total time from clicking 'Save' to receiving conflict detection result is 3 seconds or less, meeting the performance requirement |
| 7 | Repeat test with a recurring event that has conflicts: Create event 'Morning Review' with Start Time='9:15 AM', End Time='9:45 AM', Date='Tomorrow' (conflicts with Daily Standup) | System processes the event and detects conflict |
| 8 | Measure the time from submission to conflict alert display | Conflict detection and alert generation completes within 3 seconds |

**Postconditions:**
- Recurring event is saved if no conflicts exist
- Conflict detection latency is documented and meets performance criteria (under 3 seconds)
- System performance metrics are recorded for reporting
- User receives timely feedback on event creation status

---

## Story: As Scheduler, I want the system to log all detected scheduling conflicts for audit and reporting purposes
**Story ID:** story-21

### Test Case: Verify logging of detected conflicts
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User has Scheduler role with permissions to create events
- Conflict detection engine is operational
- Logging system is enabled and configured
- User has access to retrieve conflict logs via API or reporting interface
- Scheduling database contains at least one existing event
- User is authenticated and logged into the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the event creation interface | Event creation form is displayed |
| 2 | Create a base event: Title='Project Review', Start Time='2:00 PM', End Time='3:00 PM', Date='Tomorrow' | Event is created successfully and saved to the system |
| 3 | Create a conflicting event: Title='Client Meeting', Start Time='2:30 PM', End Time='3:30 PM', Date='Tomorrow' (overlaps with Project Review) | System detects the scheduling conflict and displays conflict alert to the user |
| 4 | Note the timestamp when the conflict was detected | Current timestamp is recorded for verification against log entry |
| 5 | Navigate to the conflict logs interface or access the GET /conflict-logs API endpoint | Conflict logs retrieval interface or API is accessible |
| 6 | Retrieve conflict logs for the current date/time period | System returns conflict log entries successfully |
| 7 | Search for the log entry corresponding to the triggered conflict between 'Project Review' and 'Client Meeting' | Log entry exists for the detected conflict |
| 8 | Verify log entry contains complete metadata: timestamp, involved resources (Project Review and Client Meeting), conflict type, user who triggered the conflict, event details (dates, times), and conflict resolution status | Log entry contains all required metadata fields with accurate information matching the conflict that was triggered. Timestamp is within 1 second of when conflict was detected |

**Postconditions:**
- Conflict is logged in the system with complete metadata
- Log entry is stored securely in the logging database
- Log entry is retrievable for audit and reporting purposes
- System maintains complete audit trail of conflict detection events

---

### Test Case: Validate secure access to conflict logs
- **ID:** tc-004
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Logging system contains existing conflict log entries
- Role-based access control is configured and enabled
- Two user accounts are available: one unauthorized user without log access permissions and one authorized user with log access permissions
- Conflict logs API endpoint (GET /conflict-logs) is operational
- Security and authentication mechanisms are active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into the system using credentials of an unauthorized user (user without permissions to view conflict logs) | User is successfully authenticated and logged into the system |
| 2 | Attempt to navigate to the conflict logs interface or reporting tool | System denies access and displays an error message such as 'Access Denied' or 'You do not have permission to view conflict logs' |
| 3 | Attempt to directly access the GET /conflict-logs API endpoint using the unauthorized user's authentication token | API returns HTTP 403 Forbidden status code with error message indicating insufficient permissions. No log data is returned |
| 4 | Verify that no conflict log data is displayed or accessible to the unauthorized user | Unauthorized user cannot view, retrieve, or access any conflict log entries. Security controls prevent unauthorized access |
| 5 | Log out from the unauthorized user account | User is successfully logged out from the system |
| 6 | Log into the system using credentials of an authorized user (user with permissions to view conflict logs) | Authorized user is successfully authenticated and logged into the system |
| 7 | Navigate to the conflict logs interface or reporting tool | System grants access and displays the conflict logs interface |
| 8 | Access the GET /conflict-logs API endpoint using the authorized user's authentication token | API returns HTTP 200 OK status code with conflict log data. Logs are retrieved successfully within 2 seconds |
| 9 | Verify that conflict log entries are displayed with complete information including filtering options by date, resource, and conflict type | Authorized user can view all conflict logs with complete metadata. Filtering options are available and functional. Log retrieval response time is under 2 seconds |

**Postconditions:**
- Unauthorized users remain unable to access conflict logs
- Authorized users can successfully access and retrieve conflict logs
- Security controls are validated and functioning correctly
- Access attempts are logged for security audit purposes
- Role-based access control is enforced properly

---

## Story: As Scheduler, I want the system to handle concurrent scheduling operations without missing conflicts
**Story ID:** story-22

### Test Case: Validate conflict detection under concurrent scheduling
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 30 mins

**Preconditions:**
- Scheduling system is operational and accessible
- Database has concurrency controls enabled
- 100 test user accounts are created and authenticated
- Test environment can support 100 concurrent connections
- Baseline appointments exist in the system for conflict scenarios
- Performance monitoring tools are configured
- API endpoints POST /appointments and PUT /appointments/{id} are available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Prepare 100 concurrent scheduling requests with a mix of new appointments and modifications, ensuring at least 20% have intentional time/resource conflicts | Test data set is prepared with appointments scheduled for overlapping time slots and resources |
| 2 | Initiate 100 concurrent users to simultaneously create and modify appointments using POST /appointments and PUT /appointments/{id} endpoints | All 100 requests are submitted to the system within a 2-second window |
| 3 | Monitor system processing of all 100 concurrent operations | System accepts and processes all 100 operations without crashes, timeouts, or rejected requests |
| 4 | Verify that the system detects all intentional conflicts in the concurrent operations | All conflicting appointments (minimum 20 conflicts) are identified by the conflict detection mechanism |
| 5 | Check that conflict alerts are generated for each detected conflict | Conflict alerts are generated for all detected conflicts with accurate details about the conflicting appointments |
| 6 | Verify the timing of conflict detection and alert generation | All conflict alerts are generated within 2 seconds of operation submission |
| 7 | Review system logs and database records to confirm all operations were logged | All 100 operations are recorded in system logs with appropriate status (success or conflict) |
| 8 | Validate that no false positives exist - non-conflicting appointments are successfully created/modified | All non-conflicting appointments (approximately 80) are successfully saved without conflict alerts |
| 9 | Calculate conflict detection accuracy rate | Conflict detection accuracy is 100% with zero missed conflicts and zero false positives |

**Postconditions:**
- All non-conflicting appointments are successfully saved in the database
- All conflicting appointments are rejected or flagged with alerts
- System remains stable and responsive
- No data corruption or inconsistencies exist
- Audit logs contain complete records of all operations
- System performance metrics are within acceptable thresholds

---

### Test Case: Ensure data consistency during concurrent operations
- **ID:** tc-002
- **Type:** edge-case
- **Priority:** High
- **Estimated Time:** 25 mins

**Preconditions:**
- Scheduling system is operational with database concurrency controls active
- Multiple test user accounts are authenticated
- Baseline appointments exist that can be targeted for concurrent updates
- Database transaction isolation level is properly configured
- Database supports ACID properties
- Monitoring tools are in place to detect lost updates or inconsistencies

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Identify 10 existing appointments in the system that will be targets for concurrent updates | 10 appointments are selected with their current state documented (time, resource, attendees, status) |
| 2 | Create test scenarios where multiple users will attempt to modify the same appointments simultaneously with overlapping time slots | Test data prepared with 5-10 concurrent update requests per target appointment, each attempting to change time slots that would create conflicts |
| 3 | Execute concurrent PUT /appointments/{id} requests from multiple users targeting the same appointments | All concurrent update requests are submitted simultaneously to the system |
| 4 | Monitor database transaction processing and locking mechanisms | Database applies appropriate locks and ensures serialization of conflicting updates |
| 5 | Verify that only one update per appointment is successfully committed when updates conflict | Each appointment reflects exactly one successful update, with other conflicting updates properly rejected or queued |
| 6 | Check for lost updates by comparing the final state of each appointment against all submitted update requests | No updates are lost - each update request either succeeded, was rejected with conflict alert, or failed with appropriate error message |
| 7 | Query the database to verify data integrity of all modified appointments | All appointment records have valid, consistent data with no corrupted fields, orphaned records, or invalid references |
| 8 | Verify that appointment timestamps, version numbers, or other concurrency control fields are correctly updated | All concurrency control mechanisms show proper incrementation and no version conflicts exist |
| 9 | Check for any phantom reads, dirty reads, or non-repeatable reads in the transaction logs | No data anomalies detected - all transactions maintained proper isolation |
| 10 | Validate that all users received appropriate responses indicating success or conflict for their update attempts | Each user received accurate response status (200 for success, 409 for conflict, etc.) matching the actual outcome of their request |
| 11 | Perform a comprehensive data consistency check across all related tables and relationships | All foreign key relationships are intact, no orphaned records exist, and referential integrity is maintained |

**Postconditions:**
- All appointments in the database have consistent, valid data
- No lost updates occurred during concurrent operations
- Database integrity constraints are satisfied
- All users received accurate feedback about their operations
- Transaction logs show proper isolation and atomicity
- System remains in a stable state ready for subsequent operations

---

