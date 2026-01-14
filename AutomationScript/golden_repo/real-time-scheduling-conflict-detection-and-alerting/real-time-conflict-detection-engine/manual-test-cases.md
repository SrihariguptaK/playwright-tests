# Manual Test Cases

## Story: As Scheduler, I want to receive immediate alerts for overlapping bookings to prevent double-booking
**Story ID:** story-11

### Test Case: Validate detection of overlapping bookings
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Scheduler is logged in with valid credentials and appropriate role-based permissions
- Scheduling system is operational and accessible
- At least one existing booking is present in the system (e.g., Resource A booked from 10:00 AM to 11:00 AM)
- Conflict detection service is running and responsive
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the booking creation page in the scheduling system | Booking creation page loads successfully with all required fields visible |
| 2 | Enter booking details that overlap with the existing booking (same Resource A, time slot 10:30 AM to 11:30 AM) | All booking details are entered successfully in the form fields |
| 3 | Submit the booking request by clicking the 'Create Booking' button | System processes the request and detects the conflict within 1 second |
| 4 | Observe the system response and alert mechanism | System sends an immediate alert to the scheduler displaying conflict notification |
| 5 | Review the alert content for conflict details | Scheduler receives detailed conflict alert showing: conflicting resource name (Resource A), existing booking time (10:00 AM - 11:00 AM), new booking time (10:30 AM - 11:30 AM), overlap duration, and conflicting booking owner |
| 6 | Attempt to confirm the booking by clicking 'Confirm' or 'Save' button while conflict is unresolved | System prevents booking confirmation and displays message: 'Cannot confirm booking. Please resolve the conflict first.' Booking remains in draft or pending state |
| 7 | Verify that the booking is not saved to the schedule | The conflicting booking does not appear in the calendar view and is not persisted in the database |

**Postconditions:**
- Conflicting booking is not confirmed or saved in the system
- Original existing booking remains unchanged
- Conflict alert is displayed and logged
- Scheduler is aware of the conflict and can take corrective action
- System remains in a consistent state ready for next booking attempt

---

### Test Case: Verify conflict logging
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Scheduler is logged in with valid credentials
- Scheduling system is operational
- At least one existing booking is present in the system
- Conflict logging service is enabled and functional
- User has permissions to access conflict logs
- System clock is synchronized and accurate

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the booking creation page | Booking creation page is displayed successfully |
| 2 | Create a booking that conflicts with an existing booking (e.g., same resource and overlapping time) | Booking details are entered and submitted successfully |
| 3 | Observe the system response when conflict is detected | System detects conflict and triggers alert within 1 second |
| 4 | Note the exact timestamp when the conflict was detected | Conflict detection timestamp is visible in the alert or system response |
| 5 | Navigate to the conflict logs section or admin panel | Conflict logs page loads successfully with search and filter options |
| 6 | Search for the recently created conflict event using timestamp or user details | Conflict event is found in the logs |
| 7 | Review the logged conflict details | Logs contain accurate conflict details including: timestamp of conflict detection, user ID and username of scheduler who attempted the booking, conflicting resource details, existing booking ID and details, attempted booking details, conflict type (overlap), and duration of overlap |
| 8 | Verify the completeness and accuracy of logged information | All required metadata is present and matches the actual conflict scenario. No data is missing or corrupted |

**Postconditions:**
- Conflict event is permanently logged in the system database
- Log entry contains complete and accurate information for audit purposes
- Log is accessible for future review and reporting
- System maintains log integrity and consistency

---

### Test Case: Test alert UI display
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 7 mins

**Preconditions:**
- Scheduler is logged in with valid credentials
- Scheduling system UI is fully loaded and responsive
- At least one existing booking is present in the system
- Browser supports all required UI components and JavaScript
- Alert UI component is properly configured and enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the booking creation page | Booking creation page is displayed with all form fields visible |
| 2 | Enter booking details that will trigger a conflict (overlapping resource and time) | Booking details are entered successfully |
| 3 | Submit the booking to trigger conflict detection | System processes the booking and detects the conflict within 1 second |
| 4 | Observe the alert UI component that appears on screen | Alert UI component is displayed prominently on the screen with clear visibility. Alert includes: conflict icon or visual indicator, conflict title/heading, detailed conflict information (resource name, time slots, conflicting booking details), timestamp of conflict detection, and action buttons (Acknowledge, View Details, Cancel) |
| 5 | Verify the alert UI styling and positioning | Alert is displayed in a modal or prominent notification area, uses appropriate color coding (e.g., red or orange for warning), text is readable and properly formatted, and alert does not obstruct critical UI elements |
| 6 | Click on 'View Details' button in the alert | Detailed conflict information is displayed showing full details of both the existing booking and the attempted booking, including participants, resources, and exact time overlap |
| 7 | Click on 'Acknowledge' button to acknowledge the alert | Scheduler successfully acknowledges the alert. Alert UI updates to show acknowledged status or closes gracefully. System records the acknowledgment action with timestamp |
| 8 | Verify that the alert can be dismissed or closed | Alert UI provides a close button (X) that allows scheduler to dismiss the alert. Alert closes smoothly without errors |

**Postconditions:**
- Alert UI component has been displayed and tested successfully
- Scheduler has viewed and acknowledged the conflict alert
- Alert interaction is logged in the system
- UI returns to normal state after alert dismissal
- Conflicting booking remains unconfirmed

---

## Story: As Scheduler, I want the system to support conflict detection across multiple scheduling calendars to ensure comprehensive conflict management
**Story ID:** story-16

### Test Case: Detect conflicts across multiple calendars
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Scheduler is logged in with valid credentials and cross-calendar access permissions
- Multiple calendars are configured in the system (minimum 2 calendars: e.g., Team A Calendar and Team B Calendar)
- Each calendar has at least one existing booking
- Cross-calendar conflict detection service is enabled and operational
- All calendars are synchronized and accessible
- Test data includes a shared resource that can be booked across multiple calendars

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to Team A Calendar and create a booking for a shared resource (e.g., Conference Room 1) from 2:00 PM to 3:00 PM | Booking is created successfully in Team A Calendar and saved to the system |
| 2 | Navigate to Team B Calendar | Team B Calendar loads successfully showing existing bookings |
| 3 | Attempt to create a booking in Team B Calendar for the same shared resource (Conference Room 1) with overlapping time slot from 2:30 PM to 3:30 PM | Booking details are entered in the form |
| 4 | Submit the booking request | System detects cross-calendar conflict involving Conference Room 1 booked in both Team A and Team B calendars within 2 seconds |
| 5 | Review the conflict alert that appears | Alert accurately reflects all conflicting bookings showing: source calendar (Team A Calendar), conflicting booking details (Conference Room 1, 2:00 PM - 3:00 PM), target calendar (Team B Calendar), attempted booking details (Conference Room 1, 2:30 PM - 3:30 PM), overlap period (2:30 PM - 3:00 PM), and resource name (Conference Room 1) |
| 6 | Note the conflict details and navigate back to Team B Calendar booking form | Booking form remains open with conflict alert visible |
| 7 | Modify the booking time in Team B Calendar to a non-conflicting time slot (e.g., 3:30 PM to 4:30 PM) | Booking details are updated successfully |
| 8 | Submit the modified booking request | System processes the request and detects no conflicts across all calendars |
| 9 | Confirm the booking | Booking is confirmed and saved successfully in Team B Calendar. Conflict alert is cleared and no longer displayed |
| 10 | Verify both calendars show correct bookings without conflicts | Team A Calendar shows Conference Room 1 booked from 2:00 PM to 3:00 PM. Team B Calendar shows Conference Room 1 booked from 3:30 PM to 4:30 PM. No conflict indicators are present |

**Postconditions:**
- Cross-calendar conflict was successfully detected and alerted
- Conflict was resolved by modifying the booking time
- Both calendars contain valid, non-conflicting bookings
- Shared resource (Conference Room 1) is properly allocated across calendars
- Conflict alert is cleared from the system
- All calendar data is synchronized and consistent

---

### Test Case: Verify conflict detection latency with multiple calendars
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- Scheduler is logged in with valid credentials
- Multiple calendars are configured and operational (minimum 3 calendars for comprehensive testing)
- Each calendar contains multiple existing bookings to simulate realistic load
- Cross-calendar conflict detection service is running
- System performance monitoring tools are available or timer is ready
- At least one shared resource exists across multiple calendars
- Network latency is within normal operational parameters

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Prepare a stopwatch or note the system timestamp before initiating the booking | Timer is ready to measure conflict detection latency |
| 2 | Navigate to any calendar (e.g., Calendar C) in the system | Calendar C loads successfully |
| 3 | Identify a resource that is already booked in a different calendar (e.g., Projector X booked in Calendar A from 1:00 PM to 2:00 PM) | Existing booking information is confirmed in Calendar A |
| 4 | Start the timer and immediately input a booking in Calendar C for the same resource (Projector X) with overlapping time (1:30 PM to 2:30 PM) | Booking details are entered and form is ready for submission |
| 5 | Submit the booking request and continue timing | Booking request is submitted to the system for processing |
| 6 | Observe when the conflict alert appears and stop the timer | Conflict is detected and alert is displayed. Elapsed time from submission to alert display is recorded |
| 7 | Verify the measured latency | Conflict detection latency is under 2 seconds. Alert appears within the acceptable performance threshold |
| 8 | Review the conflict alert content | Alert displays accurate cross-calendar conflict information including: source calendar (Calendar A), conflicting resource (Projector X), existing booking time (1:00 PM - 2:00 PM), attempted booking calendar (Calendar C), attempted booking time (1:30 PM - 2:30 PM), and overlap duration (30 minutes) |
| 9 | Repeat the test with bookings across different calendar combinations (e.g., Calendar B to Calendar C, Calendar A to Calendar B) | Each test iteration detects conflicts within 2 seconds consistently across all calendar combinations |
| 10 | Document the latency measurements for all test iterations | All recorded latencies are under 2 seconds, demonstrating consistent performance with multiple calendars |

**Postconditions:**
- Conflict detection latency has been measured and verified to be under 2 seconds
- System performance meets the specified requirements for cross-calendar conflict detection
- Multiple test iterations confirm consistent performance
- Test bookings can be cleaned up or cancelled
- System remains responsive and operational
- Performance metrics are documented for reporting

---

## Story: As Scheduler, I want the system to log all detected conflicts with detailed metadata to support audit and analysis
**Story ID:** story-17

### Test Case: Verify conflict logging with metadata
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is authenticated with scheduler role
- Conflict detection system is operational
- Conflict log database is accessible
- API endpoint GET /api/conflicts/logs is available
- At least two overlapping bookings exist to trigger a conflict

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Create or trigger a scheduling conflict by attempting to book a resource that is already reserved for the same time slot | System detects the conflict and triggers conflict detection mechanism |
| 2 | Verify that the conflict is logged in the conflict log database | Conflict entry is created with complete metadata including timestamp (date and time of conflict detection), user ID of the user who triggered the conflict, resource ID involved in the conflict, and booking details |
| 3 | Send GET request to /api/conflicts/logs endpoint to query the conflict logs | API returns the conflict logs with all metadata fields populated correctly |
| 4 | Measure the response time of the API query | Logs are returned within 3 seconds with complete metadata including timestamp, user information, resource details, and conflict status |
| 5 | Verify the completeness of logged metadata fields | All required fields are present: conflict ID, timestamp, user ID, resource ID, booking IDs involved, conflict type, and resolution status |

**Postconditions:**
- Conflict is logged in the database with complete metadata
- Conflict log is queryable via API
- System remains in operational state
- No data corruption or loss occurred

---

### Test Case: Test access control for conflict logs
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Conflict logs exist in the database
- API endpoint GET /api/conflicts/logs is available
- Test user accounts with different roles are configured (authorized and unauthorized)
- Authentication and authorization mechanisms are active
- Role-based access control (RBAC) is properly configured

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Authenticate as a user without authorized role (e.g., regular user or guest role) | User is successfully authenticated but does not have admin or scheduler privileges |
| 2 | Attempt to access conflict logs by sending GET request to /api/conflicts/logs endpoint | Access is denied with HTTP 403 Forbidden status code and appropriate error message indicating insufficient permissions |
| 3 | Verify that no conflict log data is returned in the response | Response body does not contain any conflict log information or sensitive data |
| 4 | Log out and authenticate as a user with authorized role (admin or scheduler) | User is successfully authenticated with proper authorization credentials |
| 5 | Send GET request to /api/conflicts/logs endpoint with authorized credentials | Access is granted with HTTP 200 OK status code |
| 6 | Verify the conflict logs are returned in the response | Logs are accessible and returned with complete metadata within 3 seconds |

**Postconditions:**
- Unauthorized access attempts are logged for security audit
- Access control mechanisms remain intact
- Authorized users can successfully access logs
- No security vulnerabilities exposed

---

## Story: As Scheduler, I want the system to prevent booking confirmation when conflicts exist to avoid scheduling errors
**Story ID:** story-18

### Test Case: Block booking confirmation when conflict exists
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- User is authenticated with scheduler role
- Scheduling system is operational
- API endpoint POST /api/schedule/confirm is available
- A booking exists that conflicts with the booking to be confirmed
- Conflict detection service is running and functional
- Test booking is in pending/unconfirmed state

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Create or select a booking that has a scheduling conflict with an existing confirmed booking (same resource, overlapping time) | Booking is created in pending state with known conflict |
| 2 | Attempt to confirm the conflicting booking by sending POST request to /api/schedule/confirm with the booking ID | System performs real-time conflict check before processing confirmation |
| 3 | Verify the system response to the confirmation attempt | System blocks the confirmation action and returns an error response with HTTP 409 Conflict status code |
| 4 | Review the error message returned by the system | Clear error message is displayed detailing the conflict including conflicting resource, time slot, and existing booking information |
| 5 | Verify the booking status remains unchanged | Booking remains in pending/unconfirmed state and is not confirmed |
| 6 | Resolve the conflict by modifying the booking (change time slot or resource to eliminate overlap) | Booking is updated successfully with no conflicts detected |
| 7 | Retry the confirmation by sending POST request to /api/schedule/confirm with the updated booking ID | System performs conflict check and finds no conflicts |
| 8 | Verify the confirmation is successful | Booking is confirmed successfully with HTTP 200 OK status, booking status changes to confirmed, and confirmation details are returned |

**Postconditions:**
- Conflicting booking was blocked from confirmation
- Resolved booking is successfully confirmed
- Schedule integrity is maintained
- No double-booking or scheduling errors occurred
- Audit trail of confirmation attempts is logged

---

### Test Case: Verify confirmation response time
- **ID:** tc-004
- **Type:** boundary
- **Priority:** Medium
- **Estimated Time:** 5 mins

**Preconditions:**
- User is authenticated with scheduler role
- Scheduling system is operational
- API endpoint POST /api/schedule/confirm is available
- Test booking exists in pending state with no conflicts
- Performance monitoring tools are available to measure response time
- System is under normal load conditions

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Prepare a valid booking confirmation request with booking ID that has no conflicts | Request payload is properly formatted and ready to submit |
| 2 | Record the timestamp before sending the confirmation request | Start time is captured accurately |
| 3 | Submit booking confirmation request by sending POST request to /api/schedule/confirm endpoint | Request is sent successfully to the server |
| 4 | Wait for and receive the response from the server | Server processes the request and returns a response |
| 5 | Record the timestamp when the response is received | End time is captured accurately |
| 6 | Calculate the total response time (end time minus start time) | Response time is calculated and displayed |
| 7 | Verify that the response time is under 2 seconds | Confirmation response is received within 2 seconds, meeting the performance requirement |
| 8 | Verify the booking confirmation was successful | Response contains HTTP 200 OK status and booking is confirmed |

**Postconditions:**
- Booking is successfully confirmed
- Response time meets performance criteria (under 2 seconds)
- System performance is within acceptable limits
- Performance metrics are logged for monitoring

---

## Story: As Scheduler, I want the system to support concurrent scheduling inputs without missing conflict detections to maintain data integrity
**Story ID:** story-19

### Test Case: Ensure conflict detection under concurrent booking submissions
- **ID:** tc-001
- **Type:** edge-case
- **Priority:** High
- **Estimated Time:** 20 mins

**Preconditions:**
- Scheduling system is operational and accessible
- Database has transaction support enabled
- Test environment supports at least 100 concurrent connections
- Multiple scheduler accounts are created and authenticated
- Test data includes resources with defined availability schedules
- Performance monitoring tools are configured to track concurrent operations
- API endpoint POST /api/schedule/book is available and functional

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Prepare 100 booking requests with intentionally overlapping time slots for the same resources | 100 booking payloads are created with overlapping times (e.g., 50 requests for Resource A from 10:00-11:00, 50 requests for Resource B from 14:00-15:00) |
| 2 | Initiate concurrent submission of all 100 booking requests simultaneously using load testing tool or multi-threaded script | All 100 requests are sent to the system within a 1-2 second window |
| 3 | Monitor system response for each booking submission request | System processes all 100 requests and returns responses for each submission |
| 4 | Analyze responses to verify conflict detection - check for conflict alerts/errors for overlapping bookings | System detects all conflicts accurately: only 1 booking per resource per time slot is accepted, remaining 49 requests for each resource receive conflict error messages |
| 5 | Query the database to retrieve all bookings created during the concurrent submission test | Database query returns only the successfully created bookings without conflicts |
| 6 | Verify no bookings were created with unresolved conflicts by checking each booking against the resource availability schedule | No conflicting bookings are persisted in the database - each resource has only one booking per time slot with no overlaps |
| 7 | Review system logs and transaction records for any race conditions or deadlock errors | Logs show proper transaction handling with no race conditions, deadlocks, or data integrity errors |
| 8 | Verify the count of successful bookings matches expected results (2 successful bookings for 2 resources) | Exactly 2 bookings are confirmed (1 per resource), and 98 requests were rejected with appropriate conflict messages |

**Postconditions:**
- Only non-conflicting bookings are persisted in the database
- All conflict errors are logged appropriately
- System remains stable and responsive after concurrent load
- No data corruption or inconsistencies exist in the scheduling database
- All rejected booking requests have clear conflict error messages recorded

---

### Test Case: Verify data consistency during concurrent operations
- **ID:** tc-002
- **Type:** edge-case
- **Priority:** High
- **Estimated Time:** 25 mins

**Preconditions:**
- Scheduling system is operational with transaction support enabled
- Database is in a known consistent state with existing bookings
- Multiple scheduler accounts are authenticated and have appropriate permissions
- Test environment supports concurrent operations (minimum 50 concurrent users)
- Baseline data snapshot is taken for comparison
- API endpoints POST /api/schedule/book and DELETE /api/schedule/cancel are functional
- Monitoring tools are configured to track data consistency metrics

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Create initial set of 25 confirmed bookings across various resources and time slots | 25 bookings are successfully created and persisted in the database with confirmed status |
| 2 | Take a snapshot of the current database state including all booking records, resource availability, and timestamps | Database snapshot captured showing 25 confirmed bookings with all associated metadata |
| 3 | Prepare concurrent operations: 25 new booking requests and 15 cancellation requests for existing bookings | 40 total operations are prepared (25 create, 15 cancel) targeting different and some overlapping resources |
| 4 | Execute all 40 operations concurrently using multi-threaded approach to simulate real-world concurrent scheduler activity | All 40 operations are submitted to the system simultaneously within a 2-3 second window |
| 5 | Monitor and collect responses from all concurrent operations | System returns response for each of the 40 operations with appropriate success or error status codes |
| 6 | Query the database to retrieve current state of all bookings after concurrent operations complete | Database query returns complete list of all bookings with their current status |
| 7 | Verify data consistency by checking: (a) All successful cancellations are reflected in database, (b) All successful new bookings are persisted, (c) No phantom bookings exist, (d) Resource availability is correctly updated | Data remains consistent with no anomalies: cancelled bookings are removed or marked cancelled, new valid bookings are confirmed, no duplicate or orphaned records exist, resource availability accurately reflects current bookings |
| 8 | Perform referential integrity check to ensure all foreign key relationships are maintained | All booking records have valid references to resources, schedulers, and related entities with no broken relationships |
| 9 | Compare final database state with expected state based on successful operations | Final booking count and resource availability matches expected calculations: (25 initial + successful new bookings - successful cancellations) |
| 10 | Review transaction logs for any rollback operations, deadlocks, or consistency violations | Transaction logs show proper atomic operations with appropriate rollbacks for failed transactions and no data consistency violations |
| 11 | Verify audit trail completeness for all operations performed | Audit logs contain complete records of all 40 operations with timestamps, user information, and operation outcomes |

**Postconditions:**
- Database maintains complete data consistency with no anomalies
- All successful bookings are persisted correctly
- All successful cancellations are reflected in the system
- No orphaned or duplicate records exist
- Resource availability accurately reflects current booking state
- System remains stable and responsive
- All operations are properly logged in audit trail

---

