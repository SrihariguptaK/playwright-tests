# Manual Test Cases

## Story: As Scheduler, I want to detect overlapping appointments to avoid double bookings
**Story ID:** story-1

### Test Case: Detect overlapping appointments on creation
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with Scheduler role
- At least one existing appointment is scheduled (e.g., 2:00 PM - 3:00 PM)
- Scheduler has access to the appointment creation interface
- Appointment database is accessible and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the appointment creation page | Appointment creation form is displayed with all required fields (date, time, duration, client, etc.) |
| 2 | Enter appointment details that overlap with existing appointment (e.g., start time 2:30 PM, end time 3:30 PM when existing appointment is 2:00 PM - 3:00 PM) | Form accepts the input and displays the entered values |
| 3 | Click 'Save' or 'Create Appointment' button | System flags the new appointment as conflicting and displays a conflict warning message indicating the overlapping time slot and existing appointment details |
| 4 | Attempt to save the appointment without making changes | System prevents saving and displays conflict warning with message such as 'Cannot save: Appointment overlaps with existing appointment from 2:00 PM - 3:00 PM' |
| 5 | Adjust the appointment time to a non-overlapping slot (e.g., change to 3:30 PM - 4:30 PM) | Conflict warning disappears and form shows no validation errors |
| 6 | Click 'Save' or 'Create Appointment' button | Appointment is saved successfully, confirmation message is displayed, and the new appointment appears in the schedule without any conflict indicators |

**Postconditions:**
- New appointment is saved in the database with non-overlapping time slot
- No conflicting appointments exist in the system
- Scheduler remains on the scheduling interface or is redirected to appointment list
- System audit log records the appointment creation

---

### Test Case: Detect overlapping appointments on update
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in with Scheduler role
- At least two existing appointments are scheduled (e.g., Appointment A: 2:00 PM - 3:00 PM, Appointment B: 4:00 PM - 5:00 PM)
- Scheduler has access to the appointment editing interface
- Appointment database is accessible and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the appointment list and select Appointment B (4:00 PM - 5:00 PM) to edit | Appointment edit form is displayed with current appointment details pre-populated |
| 2 | Modify the appointment time to overlap with Appointment A (e.g., change start time to 2:30 PM, end time to 3:30 PM) | Form accepts the modified input and displays the updated values |
| 3 | Click 'Save' or 'Update Appointment' button | System flags the updated appointment as conflicting and displays a conflict warning message indicating the overlapping time slot with Appointment A |
| 4 | Attempt to save the updated appointment without resolving the conflict | System prevents saving and displays conflict warning with message such as 'Cannot update: Appointment overlaps with existing appointment from 2:00 PM - 3:00 PM' |
| 5 | Click 'Cancel' button to abandon the update | Edit form is closed and user is returned to the appointment list or calendar view |
| 6 | Verify Appointment B details in the schedule | Original appointment remains unchanged with time slot 4:00 PM - 5:00 PM, no modifications were saved |

**Postconditions:**
- Appointment B retains its original time slot (4:00 PM - 5:00 PM)
- No changes are saved to the database
- No conflicting appointments exist in the system
- Scheduler remains on the scheduling interface

---

### Test Case: Performance test for overlap detection latency
- **ID:** tc-003
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in with Scheduler role
- Multiple existing appointments are scheduled in the system
- Performance monitoring tools are available to measure response time
- System is under normal load conditions
- Appointment database is accessible and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Record the current timestamp and create a new appointment that overlaps with an existing appointment | Appointment creation form accepts the input |
| 2 | Click 'Save' button and measure the time until conflict detection message appears | System detects the conflict and displays warning message within 2 seconds of submission |
| 3 | Record the elapsed time from submission to conflict detection | Elapsed time is less than or equal to 2 seconds |
| 4 | Cancel the conflicting appointment creation | Form is closed without saving |
| 5 | Initiate multiple concurrent appointment creations (5-10 appointments) with varying overlap scenarios using multiple browser sessions or automated scripts | All appointment creation requests are submitted simultaneously |
| 6 | Monitor and measure the conflict detection response time for each concurrent request | System processes all conflict detections within 2 seconds for each request, maintaining SLA even under concurrent load |
| 7 | Review performance logs and metrics | All conflict detection operations completed within the 2-second SLA threshold with 100% accuracy |

**Postconditions:**
- No test appointments are saved in the database
- System performance metrics are recorded and documented
- System returns to normal operational state
- Performance test results confirm SLA compliance

---

## Story: As Resource Manager, I want to detect double-booking of resources to optimize utilization
**Story ID:** story-2

### Test Case: Detect resource double-booking on creation
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with Resource Manager role
- At least one resource is available in the system (e.g., Conference Room A)
- An existing booking exists for the resource (e.g., Conference Room A booked from 2:00 PM - 3:00 PM)
- Resource Manager has access to the resource booking interface
- Resource allocation database is accessible and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the resource booking creation page | Resource booking form is displayed with all required fields (resource type, resource name, date, time, duration, etc.) |
| 2 | Select Conference Room A as the resource | Resource is selected and displayed in the form |
| 3 | Enter booking details that overlap with the existing booking (e.g., start time 2:30 PM, end time 3:30 PM) | Form accepts the input and displays the entered values |
| 4 | Click 'Save' or 'Create Booking' button | System flags the new booking as conflicting and displays a conflict warning message indicating the resource is already booked during the specified time |
| 5 | Attempt to save the booking without making changes | System prevents saving and displays conflict warning with message such as 'Cannot save: Conference Room A is already booked from 2:00 PM - 3:00 PM' |
| 6 | Adjust the booking time to a non-overlapping slot (e.g., change to 3:30 PM - 4:30 PM) | Conflict warning disappears and form shows no validation errors |
| 7 | Click 'Save' or 'Create Booking' button | Booking is saved successfully, confirmation message is displayed, and the new booking appears in the resource schedule without any conflict indicators |

**Postconditions:**
- New resource booking is saved in the database with non-overlapping time slot
- No double-booked resources exist in the system
- Resource Manager remains on the resource scheduling interface or is redirected to booking list
- System audit log records the booking creation

---

### Test Case: Detect resource double-booking on update
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in with Resource Manager role
- At least two existing bookings exist for the same resource (e.g., Booking A: Conference Room A from 2:00 PM - 3:00 PM, Booking B: Conference Room A from 4:00 PM - 5:00 PM)
- Resource Manager has access to the resource booking editing interface
- Resource allocation database is accessible and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the resource booking list and select Booking B (Conference Room A, 4:00 PM - 5:00 PM) to edit | Booking edit form is displayed with current booking details pre-populated |
| 2 | Modify the booking time to overlap with Booking A (e.g., change start time to 2:30 PM, end time to 3:30 PM) | Form accepts the modified input and displays the updated values |
| 3 | Click 'Save' or 'Update Booking' button | System flags the updated booking as conflicting and displays a conflict warning message indicating the resource double-booking with Booking A |
| 4 | Attempt to save the updated booking without resolving the conflict | System prevents saving and displays conflict warning with message such as 'Cannot update: Conference Room A is already booked from 2:00 PM - 3:00 PM' |
| 5 | Click 'Cancel' button to abandon the update | Edit form is closed and user is returned to the booking list or resource calendar view |
| 6 | Verify Booking B details in the resource schedule | Original booking remains unchanged with time slot 4:00 PM - 5:00 PM for Conference Room A, no modifications were saved |

**Postconditions:**
- Booking B retains its original time slot (4:00 PM - 5:00 PM)
- No changes are saved to the database
- No double-booked resources exist in the system
- Resource Manager remains on the resource scheduling interface

---

### Test Case: Performance test for resource double-booking detection
- **ID:** tc-006
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in with Resource Manager role
- Multiple existing resource bookings are scheduled in the system
- Performance monitoring tools are available to measure response time
- System is under normal load conditions
- Resource allocation database is accessible and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Record the current timestamp and create a new resource booking that overlaps with an existing booking | Resource booking form accepts the input |
| 2 | Click 'Save' button and measure the time until conflict detection message appears | System detects the double-booking conflict and displays warning message within 2 seconds of submission |
| 3 | Record the elapsed time from submission to conflict detection | Elapsed time is less than or equal to 2 seconds |
| 4 | Cancel the conflicting booking creation | Form is closed without saving |
| 5 | Initiate multiple concurrent resource booking creations (5-10 bookings) with varying overlap scenarios using multiple browser sessions or automated scripts | All booking creation requests are submitted simultaneously |
| 6 | Monitor and measure the conflict detection response time for each concurrent request | System processes all conflict detections within 2 seconds for each request, maintaining SLA even under concurrent load |
| 7 | Review performance logs and metrics | All double-booking detection operations completed within the 2-second SLA threshold with 100% accuracy |

**Postconditions:**
- No test bookings are saved in the database
- System performance metrics are recorded and documented
- System returns to normal operational state
- Performance test results confirm SLA compliance

---

## Story: As Scheduler, I want the system to validate participant availability to prevent scheduling conflicts
**Story ID:** story-9

### Test Case: Validate participant availability on scheduling
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Scheduler user is logged into the system with valid credentials
- Scheduler has permissions to create events and view participant availability
- At least 3 participants exist in the system with active calendar data
- Participant calendar APIs are accessible and responding
- At least one participant has a conflicting event in their calendar
- Scheduling UI is loaded and functional

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the event creation page in the scheduling interface | Event creation form is displayed with fields for event details and participant selection |
| 2 | Enter event title 'Project Review Meeting' and select date as tomorrow at 2:00 PM with duration of 1 hour | Event details are populated in the form fields |
| 3 | Click on the participant selection field and select 3 participants from the dropdown list | Selected participants are added to the event with their names displayed in the participant list |
| 4 | Observe the system behavior as it retrieves participant availability data | System initiates availability check and displays loading indicator. Availability data is retrieved within 2 seconds for all selected participants |
| 5 | Review the availability status displayed for each participant | System displays availability status for each participant. At least one participant shows as 'Unavailable' or 'Conflict' with conflict details visible (e.g., 'Busy: Client Meeting 2:00 PM - 3:00 PM') |
| 6 | Verify that conflict alerts are prominently displayed in the scheduling UI | Conflict alert banner or notification is displayed showing 'Scheduling Conflict Detected' with details of which participants are unavailable and the conflicting time slots |
| 7 | Click on the conflict details to view more information about the participant's unavailability | Detailed conflict information is displayed including participant name, conflicting event title, and time range |
| 8 | Adjust the event time by changing the start time to 4:00 PM (a time when all participants are available) | Event time is updated to 4:00 PM in the form |
| 9 | Observe the system as it automatically revalidates participant availability for the new time slot | System initiates automatic revalidation and displays loading indicator. Availability check completes within 2 seconds |
| 10 | Review the updated availability status for all participants | All participants show as 'Available' with no conflict alerts displayed. Green checkmarks or 'Available' status indicators are shown next to each participant name |
| 11 | Click the 'Create Event' or 'Schedule' button to finalize the event | Event is successfully created with confirmation message displayed: 'Event scheduled successfully with all participants available' |

**Postconditions:**
- Event is created in the system with all participants confirmed as available
- No scheduling conflicts exist for the selected time slot
- Participants are added to the event in the database
- Event appears in the scheduler's calendar view
- Availability validation completed within performance threshold of 2 seconds
- System logs record the availability checks and conflict detection

---

## Story: As Scheduler, I want the system to handle concurrent scheduling operations without conflicts to ensure data integrity
**Story ID:** story-10

### Test Case: Handle concurrent scheduling operations without conflicts
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 25 mins

**Preconditions:**
- Test environment is configured with scheduling database and application servers
- At least 100 test user accounts with scheduler role are created and active
- Database transaction isolation level is properly configured
- Concurrency control mechanisms (locking, transactions) are enabled in the system
- Load testing tools or scripts are prepared to simulate concurrent users
- Database monitoring tools are available to verify data consistency
- Test data includes shared resources (rooms, participants) that multiple users may schedule
- System performance monitoring is active to track operation completion times

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Prepare concurrent test scenario by configuring load testing tool to simulate 100 users simultaneously creating new events for the same time slot and shared resource (e.g., Conference Room A at 10:00 AM tomorrow) | Load testing tool is configured with 100 concurrent user sessions ready to execute scheduling operations |
| 2 | Initiate the concurrent scheduling operations by triggering all 100 users to submit event creation requests simultaneously | System receives 100 concurrent POST requests to the scheduling endpoint. All requests are queued and processed by the system |
| 3 | Monitor system behavior during concurrent operations using application logs and performance monitoring tools | System applies concurrency control mechanisms (database locks, transaction management). No application errors or crashes occur. System remains responsive |
| 4 | Wait for all 100 concurrent operations to complete and observe the response times | All operations complete within SLA thresholds. System processes requests sequentially or with proper conflict detection. Response times are logged for each operation |
| 5 | Review the responses received by each of the 100 simulated users | Only one user receives success confirmation for booking Conference Room A at 10:00 AM. The remaining 99 users receive clear feedback messages such as 'Resource unavailable' or 'Scheduling conflict detected - room already booked' |
| 6 | Query the scheduling database to verify the number of events created for Conference Room A at 10:00 AM tomorrow | Database query returns exactly 1 event record for the specified time and resource. No duplicate bookings exist |
| 7 | Execute database consistency check queries to verify referential integrity, constraint violations, and orphaned records | All database integrity checks pass. No constraint violations, no orphaned records, no data corruption detected. Foreign key relationships are intact |
| 8 | Prepare second concurrent test scenario with 100 users updating different existing events simultaneously (non-conflicting updates) | Load testing tool is configured with 100 users each updating a unique event record |
| 9 | Execute the concurrent update operations by triggering all 100 users to submit PUT requests simultaneously | System receives and processes 100 concurrent PUT requests. Concurrency controls are applied |
| 10 | Monitor and wait for all update operations to complete | All 100 update operations complete successfully within SLA thresholds. No deadlocks or transaction rollbacks occur |
| 11 | Verify that all 100 events were updated correctly by querying the database and comparing with expected update values | All 100 event records show the correct updated values. No updates were lost or overwritten incorrectly. Data consistency is maintained |
| 12 | Prepare third concurrent test scenario with 50 users creating events and 50 users updating events simultaneously (mixed operations) | Load testing tool is configured with mixed operation types across 100 concurrent users |
| 13 | Execute the mixed concurrent operations simultaneously | System processes 100 concurrent mixed operations (50 creates, 50 updates) without errors |
| 14 | Verify operation results and database state after mixed concurrent operations | All create operations result in new records or appropriate conflict messages. All update operations complete successfully or return appropriate feedback. Database remains consistent with no data corruption |
| 15 | Review application logs and user feedback messages for all concurrent test scenarios | Users receive clear, accurate feedback on operation status. Success messages for completed operations show 'Event created successfully' or 'Event updated successfully'. Conflict messages clearly state 'Unable to complete operation - resource conflict' or similar. No ambiguous or missing feedback |
| 16 | Generate and review performance report showing concurrent user support and operation completion times | Report confirms system successfully supported 100 concurrent scheduling users. Average operation completion time is within SLA thresholds. No performance degradation beyond acceptable limits |

**Postconditions:**
- Database contains accurate scheduling data with no corruption or inconsistencies
- All concurrent operations are logged with appropriate status (success/conflict)
- System demonstrated support for 100 concurrent users without data conflicts
- No orphaned records or referential integrity violations exist in the database
- All users received appropriate feedback on their operation status
- Performance metrics confirm operations completed within SLA thresholds
- Concurrency control mechanisms functioned correctly throughout all test scenarios
- System remains stable and responsive after concurrent load testing

---

