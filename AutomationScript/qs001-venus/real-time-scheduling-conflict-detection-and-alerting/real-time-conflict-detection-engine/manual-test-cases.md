# Manual Test Cases

## Story: As Scheduler, I want to detect overlapping appointments in real-time to prevent double-booking
**Story ID:** story-1

### Test Case: Validate detection of overlapping appointments
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- User is logged in with Scheduler role
- Scheduling interface is accessible
- At least one existing appointment is present in the system (e.g., Resource A booked from 10:00 AM to 11:00 AM on current date)
- System conflict detection service is running
- Database contains active scheduling data

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the scheduling interface by clicking on 'Schedule' menu option | Scheduling form is displayed with fields for appointment details including resource, date, start time, end time, and client information |
| 2 | Enter appointment details that overlap with the existing appointment: Select Resource A, set date to current date, set start time to 10:30 AM, set end time to 11:30 AM, enter client name | System detects the conflict within 1 second and triggers validation process |
| 3 | Observe the scheduling interface for conflict alert notification | Conflict alert is displayed clearly on the UI showing message such as 'Conflict Detected: Resource A is already booked from 10:00 AM to 11:00 AM' with visual indicators (e.g., red border, warning icon) |

**Postconditions:**
- Conflict alert remains visible until user takes action
- Overlapping appointment is not saved to the database
- System remains in ready state for next scheduling action
- Conflict detection event is logged in the system

---

### Test Case: Verify prevention of saving overlapping schedules without override
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with Scheduler role without override authorization
- Scheduling interface is accessible
- Existing appointment exists (e.g., Resource B booked from 2:00 PM to 3:00 PM on current date)
- System save validation is enabled
- Conflict detection service is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to scheduling interface and enter overlapping appointment details: Select Resource B, set date to current date, set start time to 2:30 PM, set end time to 3:30 PM | System detects conflict and displays conflict alert on the interface |
| 2 | Click 'Save' button to attempt saving the schedule with overlapping appointment without applying any override | System blocks the save operation and displays error message such as 'Cannot save schedule: Overlapping appointment detected. Please resolve conflict or obtain authorization to override.' Save button remains inactive or save action is prevented |
| 3 | Modify the appointment to resolve the conflict by changing start time to 3:00 PM and end time to 4:00 PM | Conflict alert disappears and system validates that no conflicts exist |
| 4 | Click 'Save' button to save the modified schedule | Schedule saves successfully with confirmation message displayed such as 'Appointment saved successfully'. New appointment appears in the schedule view |

**Postconditions:**
- Only the non-conflicting appointment is saved in the database
- Schedule displays the newly created appointment without conflicts
- System returns to ready state for next scheduling operation
- Save attempt and resolution are logged in audit trail

---

### Test Case: Check logging of detected conflicts
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in with Scheduler role
- Admin interface access is available for log review
- Existing appointment exists (e.g., Resource C booked from 9:00 AM to 10:00 AM on current date)
- Logging service is enabled and operational
- System timestamp is accurate

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to scheduling interface and create an overlapping appointment: Select Resource C, set date to current date, set start time to 9:30 AM, set end time to 10:30 AM, enter client details | System detects conflict, displays conflict alert, and triggers logging mechanism. Conflict is logged with metadata including user ID, timestamp, resource ID, conflicting time slots, and appointment details |
| 2 | Navigate to admin interface by clicking 'Admin' menu, then select 'Conflict Logs' or 'Audit Logs' section | Admin interface displays conflict logs section with searchable and filterable log entries |
| 3 | Search or filter logs for the recently created conflict by date, time, or resource (Resource C) | Log entry for the conflict is displayed showing complete details: User who triggered conflict, exact timestamp (date and time), Resource C identifier, conflicting time slots (9:30 AM - 10:30 AM overlapping with 9:00 AM - 10:00 AM), appointment IDs involved, and conflict status |
| 4 | Verify the accuracy of logged information by comparing with the actual conflict details entered | All logged conflict details are accurate and complete, matching the actual conflict scenario including correct user, timestamp within 1 second of detection, resource details, and time slot information |

**Postconditions:**
- Conflict log entry persists in the database
- Log data is available for audit and reporting purposes
- System maintains complete audit trail of conflict detection
- Admin interface remains accessible for future log reviews

---

## Story: As Scheduler, I want to detect resource double-booking in real-time to avoid scheduling errors
**Story ID:** story-2

### Test Case: Validate detection of resource double-booking
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- User is logged in with Scheduler role
- Scheduling interface is accessible
- Resource 'Conference Room A' is already assigned to an appointment from 1:00 PM to 2:00 PM on current date
- Resource allocation service is running
- Real-time validation is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the scheduling interface by selecting 'Schedule' from the main menu | Scheduling form is displayed with all required fields including resource assignment dropdown, date picker, time selectors, and appointment details fields |
| 2 | Create a new appointment and assign 'Conference Room A' as the resource for the same time slot: Set date to current date, set start time to 1:00 PM, set end time to 2:00 PM, enter client and appointment details | System detects resource double-booking within 1 second of resource assignment and initiates alert mechanism |
| 3 | Observe the scheduling interface for detailed alert notification | Detailed alert is displayed specifying the resource conflict with message such as 'Double-Booking Detected: Conference Room A is already booked from 1:00 PM to 2:00 PM on [current date]'. Alert includes resource name, conflicting time slot, and visual indicators (warning icon, highlighted fields) |

**Postconditions:**
- Double-booking alert remains visible until user resolves the conflict
- Appointment with double-booked resource is not saved
- System is ready for user to modify resource assignment
- Double-booking detection event is logged with full details

---

### Test Case: Verify prevention of saving double-booked schedules without override
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with Scheduler role without authorized override privileges
- Scheduling interface is accessible
- Resource 'Meeting Room B' is already assigned from 11:00 AM to 12:00 PM on current date
- Save validation rules are active
- Double-booking detection is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to scheduling interface and create appointment with double-booked resource: Select 'Meeting Room B', set date to current date, set start time to 11:00 AM, set end time to 12:00 PM, enter appointment details | System detects double-booking and displays detailed alert specifying 'Meeting Room B' conflict with time slot details |
| 2 | Attempt to save the schedule by clicking 'Save' or 'Submit' button without applying any override authorization | System blocks the save operation and displays error message such as 'Cannot save schedule: Meeting Room B is double-booked for 11:00 AM to 12:00 PM. Please select a different resource or time, or obtain authorization to override.' Save action is prevented and appointment is not persisted |
| 3 | Resolve the conflict by changing the resource assignment to 'Meeting Room C' which is available for the same time slot | Double-booking alert disappears, system validates resource availability, and no conflicts are detected for Meeting Room C |
| 4 | Click 'Save' button to save the schedule with the resolved resource assignment | Schedule saves successfully with confirmation message 'Appointment saved successfully'. New appointment with Meeting Room C appears in the schedule view for the specified time slot |

**Postconditions:**
- Only the appointment with non-conflicting resource (Meeting Room C) is saved in database
- Resource allocation table reflects the new assignment correctly
- Schedule view displays updated appointment without double-booking
- Save attempt, conflict, and resolution are logged in audit trail

---

### Test Case: Check logging of double-booking events
- **ID:** tc-006
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in with Scheduler role
- Admin interface is accessible for log review
- Resource 'Projector Unit 1' is already assigned from 3:00 PM to 4:00 PM on current date
- Event logging service is enabled and functioning
- System clock is synchronized and accurate

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to scheduling interface and trigger double-booking detection by assigning 'Projector Unit 1' to a new appointment: Set date to current date, set start time to 3:00 PM, set end time to 4:00 PM, complete appointment details | System detects double-booking, displays alert, and logs the event with comprehensive metadata including user ID, timestamp, resource ID ('Projector Unit 1'), conflicting time slot (3:00 PM - 4:00 PM), appointment IDs, and detection status |
| 2 | Open admin interface by navigating to 'Admin' menu and selecting 'Event Logs' or 'Double-Booking Logs' section | Admin interface displays the event logs section with list of logged events, search functionality, and filter options by date, resource, user, or event type |
| 3 | Search for the recently triggered double-booking event by filtering for 'Projector Unit 1' or by current date and time range | Log entry for the double-booking event is displayed in the results showing: User who triggered the event, precise timestamp (date and time with seconds), Resource identifier ('Projector Unit 1'), conflicting time slot details (3:00 PM - 4:00 PM), both appointment IDs involved in the conflict, and event status |
| 4 | Review and verify the accuracy and completeness of the logged event details by cross-referencing with the actual double-booking scenario | All logged event details are accurate and complete: Correct user identification, timestamp within 1 second of actual detection time, accurate resource details, precise time slot information, both conflicting appointment references, and complete metadata. No data is missing or incorrect |

**Postconditions:**
- Double-booking event log entry is permanently stored in the database
- Log data is available for compliance, audit, and reporting purposes
- Event logging accuracy is maintained at 100%
- Admin interface remains accessible for ongoing monitoring and review

---

## Story: As Scheduler, I want the system to handle concurrent scheduling inputs without missing conflicts to ensure data integrity
**Story ID:** story-8

### Test Case: Validate conflict detection under concurrent scheduling
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 25 mins

**Preconditions:**
- Scheduling system is operational and accessible
- Database has concurrency controls enabled
- 100 test user accounts are created and authenticated
- Test environment supports concurrent connections
- Baseline scheduling data exists in the database
- Monitoring tools are configured to track conflicts and data integrity

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Prepare 100 concurrent scheduling requests with overlapping time slots and resources using automated test scripts or load testing tools | Test scripts are configured correctly with overlapping scheduling inputs ready for execution |
| 2 | Execute all 100 concurrent scheduling requests simultaneously | All 100 requests are submitted to the system without connection errors or timeouts |
| 3 | Monitor system processing of concurrent requests in real-time | System processes all requests with transaction isolation, no crashes or system errors occur |
| 4 | Verify that all scheduling conflicts are detected by the system | System detects 100% of conflicts where schedules overlap in time and resources, no conflicts are missed |
| 5 | Check system logs and error reports for any processing errors | No errors, exceptions, or warnings related to concurrent processing are logged |
| 6 | Query the scheduling database to verify data integrity | All scheduling records are complete, accurate, and consistent with no duplicate or corrupted entries |
| 7 | Verify no race conditions occurred by checking for orphaned records or inconsistent states | Data integrity is maintained with no evidence of race conditions or data corruption |
| 8 | Check that conflict alerts were generated for all detected conflicts | Conflict alerts are created in the system for every detected scheduling conflict |
| 9 | Verify conflict alerts are delivered to all affected users | All users involved in scheduling conflicts receive their respective conflict notifications |
| 10 | Measure the time taken for conflict detection and alert delivery | Conflict detection and alert delivery complete within 2 seconds under concurrent load |
| 11 | Review alert content for accuracy and completeness | Alerts contain correct conflict details including time, resource, and conflicting parties |

**Postconditions:**
- All scheduling conflicts are accurately detected and recorded
- Database maintains complete data integrity with no corruption
- All affected users have received conflict notifications
- System remains stable and operational
- Test data can be cleaned up or retained for analysis

---

## Story: As Scheduler, I want the system to validate scheduling inputs to prevent invalid data entry causing false conflicts
**Story ID:** story-9

### Test Case: Verify validation of scheduling inputs
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- Scheduling system is accessible and operational
- User is logged in with scheduler privileges
- Scheduling input form is loaded and ready
- Input validation rules are configured on frontend and backend
- Network connection is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the scheduling input form | Scheduling form is displayed with all required fields visible and enabled |
| 2 | Enter an invalid date format in the date field (e.g., '32/13/2024' or 'abc123') | Inline error message is displayed immediately below or next to the date field indicating invalid date format |
| 3 | Measure the time taken for the validation error to appear | Validation error message appears within 500 milliseconds of input |
| 4 | Verify the error message content and clarity | Error message clearly states the expected date format (e.g., 'Please enter date in MM/DD/YYYY format') |
| 5 | Attempt to submit the form with the invalid date | Form submission is prevented, error message persists, and focus remains on the invalid field |
| 6 | Correct the date field with a valid date format | Error message disappears and field is marked as valid |
| 7 | Enter a start time that is after the end time (e.g., start: 3:00 PM, end: 2:00 PM) | Inline validation error message is displayed indicating that start time must be before end time |
| 8 | Measure the time taken for the validation error to appear | Validation error message appears within 500 milliseconds of completing the end time input |
| 9 | Attempt to submit the form with start time after end time | Validation error prevents form submission and displays clear error message |
| 10 | Verify the error message provides clear guidance | Error message states 'Start time must be before end time' or similar clear instruction |
| 11 | Correct the time fields so start time is before end time | Validation error disappears and time fields are marked as valid |
| 12 | Enter all valid inputs in the scheduling form (valid date format, start time before end time, valid resource identifiers) | No validation errors are displayed, all fields show valid status |
| 13 | Submit the form with all valid inputs | Form submission is allowed and proceeds successfully to conflict detection phase |
| 14 | Verify the submitted data is processed correctly | Scheduling request is accepted and confirmation message or next step is displayed |

**Postconditions:**
- Invalid inputs are rejected and not stored in the database
- Valid scheduling data is successfully submitted
- User receives appropriate feedback for all validation scenarios
- System maintains data quality by preventing invalid entries
- Form is ready for next scheduling input

---

