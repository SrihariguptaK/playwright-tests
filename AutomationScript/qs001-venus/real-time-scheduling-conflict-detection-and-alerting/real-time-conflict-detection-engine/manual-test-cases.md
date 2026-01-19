# Manual Test Cases

## Story: As Scheduler, I want to receive real-time detection of overlapping time slots to prevent double bookings
**Story ID:** story-11

### Test Case: Validate detection of overlapping time slots during booking creation
- **ID:** tc-001
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- User is logged in with Scheduler role
- Scheduling database is accessible and populated with existing bookings
- At least one existing booking exists for a resource (e.g., Resource A booked from 10:00 AM to 11:00 AM)
- Booking creation interface is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the booking creation page | Booking form is displayed with fields for resource selection, date, start time, end time, and other booking details |
| 2 | Select a resource that has an existing booking (e.g., Resource A) | Resource is selected and displayed in the form |
| 3 | Select a date and time slot that overlaps with the existing booking (e.g., 10:30 AM to 11:30 AM when existing booking is 10:00 AM to 11:00 AM) | System immediately displays a real-time conflict alert message indicating an overlapping time slot with details including conflicting booking ID, resource name, and conflicting time range |
| 4 | Attempt to save the booking by clicking the Save or Submit button | System prevents saving the booking and displays an error message stating that the booking cannot be saved due to overlapping time slots |

**Postconditions:**
- No new booking is created in the database
- Existing booking remains unchanged
- Scheduler remains on the booking creation page with the conflict alert visible

---

### Test Case: Verify booking creation succeeds when no conflicts exist
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in with Scheduler role
- Scheduling database is accessible
- At least one resource is available without any bookings for the selected time slot
- Booking creation interface is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the booking creation page | Booking form is displayed with all required fields |
| 2 | Select a resource that is available (e.g., Resource B) | Resource is selected and displayed in the form |
| 3 | Select a date and time slot that does not conflict with any existing bookings (e.g., 2:00 PM to 3:00 PM) | No conflict alerts are shown, form remains in valid state |
| 4 | Fill in all other required booking details (description, attendees, etc.) | All fields are populated correctly |
| 5 | Submit the booking form by clicking the Save or Submit button | Booking is saved successfully, confirmation message is displayed with booking details, and user is redirected to booking list or confirmation page |

**Postconditions:**
- New booking is created and stored in the database
- Booking appears in the schedule for the selected resource and time slot
- Confirmation message is visible to the scheduler

---

### Test Case: Ensure conflict detection latency is under 1 second
- **ID:** tc-003
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with Scheduler role
- Scheduling database contains multiple existing bookings
- Performance monitoring tool or browser developer tools are available to measure response time
- At least one resource has an existing booking that can be used to trigger a conflict

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the booking creation page | Booking form is displayed |
| 2 | Start timing measurement (using browser developer tools or stopwatch) | Timer is started |
| 3 | Select a resource and time slot that triggers conflict detection (overlapping with an existing booking) | Conflict alert appears on the screen |
| 4 | Stop timing measurement when the conflict alert is fully displayed | Elapsed time from selection to alert display is recorded and is less than 1 second (under 1000 milliseconds) |
| 5 | Verify the conflict alert contains accurate details about the conflicting booking | Alert displays correct booking ID, resource name, and conflicting time range |

**Postconditions:**
- Performance requirement of under 1 second latency is confirmed
- Conflict detection system is functioning within acceptable performance parameters
- No booking is saved

---

## Story: As Scheduler, I want to receive alerts for resource double-booking to avoid scheduling errors
**Story ID:** story-12

### Test Case: Validate detection of resource double-booking during booking creation
- **ID:** tc-004
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- User is logged in with Scheduler role
- Resource allocation database is accessible
- At least one resource is already booked for a specific time slot (e.g., Conference Room A booked from 9:00 AM to 10:00 AM)
- Booking creation interface is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the booking creation page | Booking form is displayed with resource selection and time slot fields |
| 2 | Select a resource that is already booked for the selected time slot (e.g., Conference Room A) | Resource is selected in the form |
| 3 | Select the same date and time slot for which the resource is already booked (e.g., 9:00 AM to 10:00 AM) | System immediately displays a real-time double-booking alert specifying the resource name, conflicting booking ID, and time details |
| 4 | Attempt to save the booking by clicking the Save or Submit button | System blocks the save operation and displays an error message indicating that the resource is already booked and the booking cannot be saved |

**Postconditions:**
- No new booking is created in the database
- Existing resource booking remains unchanged
- Double-booking alert remains visible on the screen
- Scheduler remains on the booking creation page

---

### Test Case: Verify booking creation succeeds when resource is available
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in with Scheduler role
- Resource allocation database is accessible
- At least one resource is available without any bookings for the selected time slot
- Booking creation interface is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the booking creation page | Booking form is displayed with all necessary fields |
| 2 | Select an available resource that has no bookings for the desired time slot (e.g., Meeting Room B) | Resource is selected and displayed in the form |
| 3 | Select a date and time slot for which the resource is available (e.g., 1:00 PM to 2:00 PM) | No conflict alerts or double-booking warnings are shown, form remains in valid state |
| 4 | Complete all other required booking information (purpose, attendees, notes, etc.) | All fields are filled correctly |
| 5 | Submit the booking by clicking the Save or Submit button | Booking is saved successfully, success confirmation message is displayed, and the booking appears in the system |

**Postconditions:**
- New booking is created and stored in the resource allocation database
- Resource is marked as booked for the selected time slot
- Confirmation message is displayed to the scheduler
- Booking is visible in the schedule view

---

### Test Case: Ensure double-booking detection latency is under 1 second
- **ID:** tc-006
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with Scheduler role
- Resource allocation database contains multiple existing bookings
- Performance measurement tools are available (browser developer tools, network tab, or stopwatch)
- At least one resource has an existing booking to trigger double-booking detection

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the booking creation page | Booking form is displayed |
| 2 | Prepare timing measurement tool (start browser network monitoring or ready stopwatch) | Timing tool is ready to measure response time |
| 3 | Start timer and immediately select a resource that is already booked for a specific time slot | Resource selection is registered |
| 4 | Select the time slot that causes a double-booking conflict | Double-booking alert appears on the screen |
| 5 | Stop timer when the alert is fully visible and measure the elapsed time | Elapsed time from resource and time selection to alert display is less than 1 second (under 1000 milliseconds) |
| 6 | Verify the alert contains accurate resource and booking conflict details | Alert displays correct resource name, conflicting booking ID, and time information |

**Postconditions:**
- Performance requirement of under 1 second latency is validated
- Double-booking detection system meets performance standards
- No booking is created
- Alert remains visible for scheduler review

---

## Story: As Scheduler, I want the system to handle concurrent scheduling inputs without missing conflicts
**Story ID:** story-20

### Test Case: Validate conflict detection under concurrent booking submissions
- **ID:** tc-001
- **Type:** edge-case
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- Scheduling system is operational and accessible
- Database has transaction support enabled
- At least 2 scheduler accounts are authenticated and active
- Test environment can support 100 concurrent connections
- Database is populated with existing bookings for conflict testing
- API endpoint POST /api/bookings is available and responding

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Prepare 100 booking submission requests with overlapping time slots (e.g., 50 bookings for Room A from 10:00-11:00, 50 bookings for Room A from 10:30-11:30) | Test data is prepared with intentional time overlaps across multiple resources |
| 2 | Execute automated script or load testing tool to simulate 100 concurrent booking submissions to POST /api/bookings endpoint | All 100 requests are sent simultaneously within a 1-second window |
| 3 | Monitor system response for each submission and capture all conflict detection alerts | System processes all 100 submissions and returns responses for each request |
| 4 | Verify that all overlapping bookings are identified as conflicts with appropriate error messages | System detects 100% of conflicts accurately - all overlapping time slots are flagged with conflict alerts |
| 5 | Query the database to retrieve all bookings created during the concurrent submission test | Database query returns only the bookings that were successfully saved |
| 6 | Verify that no conflicting bookings exist in the database by checking for time overlaps on the same resources | Database contains only conflict-free bookings - no two bookings overlap for the same resource |
| 7 | Review system logs for any race condition errors, deadlocks, or transaction failures | No race conditions, deadlocks, or transaction integrity issues are logged |

**Postconditions:**
- Database contains only valid, non-conflicting bookings
- All conflicting booking attempts are rejected and logged
- System remains stable and responsive
- Transaction logs show proper atomic operations
- No orphaned or incomplete booking records exist

---

### Test Case: Ensure no data loss or errors during concurrent submissions
- **ID:** tc-002
- **Type:** edge-case
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Scheduling system is operational and accessible
- Database has sufficient capacity for concurrent transactions
- Multiple scheduler accounts (minimum 10) are authenticated
- Test environment supports concurrent connections
- Baseline booking count is recorded in database
- API endpoint POST /api/bookings is available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Record the current count of bookings in the database as baseline | Baseline booking count is documented (e.g., 150 existing bookings) |
| 2 | Prepare 100 valid booking submissions with non-overlapping time slots across different resources | Test data contains 100 unique, valid booking requests with no conflicts |
| 3 | Execute concurrent submission of all 100 valid bookings using multiple scheduler accounts simultaneously | All 100 booking requests are submitted concurrently to the system |
| 4 | Monitor API responses for each submission and capture HTTP status codes and response messages | All submissions receive responses (either success 201 or appropriate error codes) |
| 5 | Verify that all valid bookings receive success responses (HTTP 201 Created) without errors | 100 success responses are received with no 500-series errors or timeout failures |
| 6 | Query the database and count total bookings after concurrent submission | Database count shows baseline + 100 bookings (e.g., 250 total bookings) |
| 7 | Verify data integrity by checking that all submitted booking details match database records | All 100 bookings are saved with complete and accurate data - no data loss or corruption |
| 8 | Review application logs and database logs for any errors, warnings, or transaction rollbacks | No errors, data loss warnings, or unexpected transaction rollbacks are logged |
| 9 | Check for duplicate bookings or orphaned records in the database | No duplicate bookings exist and no orphaned or incomplete records are found |

**Postconditions:**
- All 100 valid bookings are successfully saved in database
- No data loss or corruption occurred
- Database integrity is maintained
- System logs show successful concurrent processing
- No duplicate or orphaned records exist
- System performance remains within acceptable parameters

---

## Story: As Scheduler, I want the system to validate all mandatory fields before scheduling to avoid incomplete bookings
**Story ID:** story-21

### Test Case: Verify validation blocks booking submission with missing mandatory fields
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Scheduler is logged into the system with valid credentials
- Booking form is accessible and loaded completely
- All mandatory fields are identified (e.g., Date, Time, Resource, Attendees)
- Frontend and backend validation are both enabled
- Network connection is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the booking creation form | Booking form is displayed with all mandatory fields clearly marked (e.g., with asterisks) |
| 2 | Leave the 'Date' mandatory field empty and click or tab to the next field | Inline validation error message appears below the 'Date' field (e.g., 'Date is required') |
| 3 | Leave the 'Time' mandatory field empty and click or tab to the next field | Inline validation error message appears below the 'Time' field (e.g., 'Time is required') |
| 4 | Leave the 'Resource' mandatory field empty and click or tab to the next field | Inline validation error message appears below the 'Resource' field (e.g., 'Resource is required') |
| 5 | Leave the 'Attendees' mandatory field empty and click or tab to the next field | Inline validation error message appears below the 'Attendees' field (e.g., 'At least one attendee is required') |
| 6 | Verify that all inline error messages are displayed simultaneously for all empty mandatory fields | All mandatory fields with missing data show inline validation error messages |
| 7 | Attempt to click the 'Submit' or 'Create Booking' button with mandatory fields still empty | Submission is blocked and the button either remains disabled or shows a validation summary error message |
| 8 | Verify that a summary error message is displayed at the top of the form indicating incomplete submission | Error message appears (e.g., 'Please complete all mandatory fields before submitting') |
| 9 | Verify that no API call to POST /api/bookings is made by checking network traffic | No POST request is sent to the backend - frontend validation prevents submission |

**Postconditions:**
- No booking is created in the database
- Form remains in edit mode with error messages displayed
- User remains on the booking form page
- All validation error messages are visible to the scheduler

---

### Test Case: Ensure booking submission succeeds when all mandatory fields are filled
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Scheduler is logged into the system with valid credentials
- Booking form is accessible and loaded completely
- All mandatory fields are identified
- Valid test data is prepared for all mandatory fields
- Backend API POST /api/bookings is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the booking creation form | Booking form is displayed with all fields ready for input |
| 2 | Fill in the 'Date' mandatory field with a valid future date (e.g., tomorrow's date) | Date is accepted and no validation error is shown for this field |
| 3 | Fill in the 'Time' mandatory field with a valid time slot (e.g., 10:00 AM - 11:00 AM) | Time is accepted and no validation error is shown for this field |
| 4 | Select a valid resource from the 'Resource' mandatory field dropdown (e.g., Conference Room A) | Resource is selected and no validation error is shown for this field |
| 5 | Add at least one attendee in the 'Attendees' mandatory field (e.g., john.doe@example.com) | Attendee is added and no validation error is shown for this field |
| 6 | Fill in any other mandatory fields as required by the form | All mandatory fields are completed with valid data |
| 7 | Verify that no validation error messages are displayed on the form | No inline validation errors are shown - all fields display as valid |
| 8 | Verify that the 'Submit' or 'Create Booking' button is enabled and clickable | Submit button is enabled and ready for interaction |
| 9 | Click the 'Submit' or 'Create Booking' button | Form is submitted and a POST request is sent to /api/bookings endpoint |
| 10 | Wait for the system response and verify success confirmation message is displayed | Success message appears (e.g., 'Booking created successfully') with HTTP 201 status |
| 11 | Verify that the booking appears in the scheduler's booking list or calendar view | New booking is visible with all entered details displayed correctly |
| 12 | Query the database to confirm the booking record exists with all mandatory field data | Database contains the new booking record with complete and accurate data |

**Postconditions:**
- Booking is successfully created and saved in database
- Scheduler receives confirmation of successful booking
- Booking appears in the system calendar/schedule
- All mandatory field data is persisted correctly
- Form is either cleared or redirected to booking list view

---

### Test Case: Test validation feedback latency under 500 milliseconds
- **ID:** tc-005
- **Type:** boundary
- **Priority:** Medium
- **Estimated Time:** 12 mins

**Preconditions:**
- Scheduler is logged into the system with valid credentials
- Booking form is accessible and loaded completely
- Browser developer tools or performance monitoring tool is available
- Network latency is within normal parameters (< 100ms)
- System is under normal load conditions

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open browser developer tools and navigate to the Performance or Network tab | Developer tools are open and ready to capture timing metrics |
| 2 | Navigate to the booking creation form | Booking form is fully loaded and ready for input |
| 3 | Start performance recording or prepare to measure time from input to validation feedback | Performance monitoring is active and capturing events |
| 4 | Enter invalid data in the 'Date' field (e.g., past date or invalid format) and tab out of the field | Validation error message appears for the Date field |
| 5 | Measure the time elapsed between losing focus on the field and the validation message appearing | Validation feedback appears within 500 milliseconds (ideally < 300ms) |
| 6 | Clear the 'Date' field, leave it empty, and tab out of the field | Required field validation error message appears for the Date field |
| 7 | Measure the time elapsed between losing focus and the validation message appearing | Validation feedback appears within 500 milliseconds |
| 8 | Enter invalid data in the 'Time' field (e.g., invalid time format) and tab out | Validation error message appears within 500 milliseconds |
| 9 | Enter invalid data in the 'Attendees' field (e.g., invalid email format) and tab out | Validation error message appears within 500 milliseconds |
| 10 | Fill all mandatory fields with valid data and click the Submit button | Form validation completes and submission proceeds or backend validation responds within 500 milliseconds |
| 11 | Review performance metrics and validation timing logs | All validation feedback events occurred within the 500ms threshold |
| 12 | Document the maximum validation latency observed across all field validations | Maximum latency is documented and is less than or equal to 500 milliseconds |

**Postconditions:**
- All validation feedback latencies are within 500ms threshold
- Performance metrics are documented
- No validation delays or UI freezing occurred
- System responsiveness meets performance requirements

---

## Story: As Scheduler, I want the system to handle error scenarios gracefully during conflict detection
**Story ID:** story-22

### Test Case: Verify graceful handling of backend errors during conflict detection
- **ID:** tc-001
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as Scheduler
- Scheduling interface is accessible
- Backend service can be configured to simulate errors
- Test environment has error simulation capability enabled
- At least one scheduling request is ready to be processed

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the scheduling interface and prepare to create or modify a schedule | Scheduling interface loads successfully and displays available options |
| 2 | Configure backend to simulate an error during conflict detection (e.g., database timeout, service unavailable, network error) | Backend error simulation is configured and ready to trigger on next conflict detection request |
| 3 | Initiate conflict detection by attempting to schedule an appointment or resource | System attempts to perform conflict detection and encounters the simulated backend error |
| 4 | Observe the error message displayed to the user | User sees a clear, non-technical error message such as 'We encountered an issue checking for scheduling conflicts. Please try again or contact support if the problem persists.' No technical stack traces or error codes are visible |
| 5 | Verify that retry and cancel options are available in the error message dialog | Error dialog displays 'Retry' and 'Cancel' buttons clearly visible to the user |
| 6 | Click the 'Retry' button to attempt conflict detection again | System reprocesses the conflict detection request. If error persists, same error message appears. If successful, conflict detection completes normally |
| 7 | Trigger the error scenario again and click 'Cancel' button | Operation is cancelled gracefully, user returns to previous screen or scheduling interface without data loss, and no system crash occurs |
| 8 | Verify system remains stable and responsive after error handling | System continues to function normally, other features remain accessible, and user can perform other scheduling operations |

**Postconditions:**
- System remains stable and operational
- User session is maintained without logout
- No data corruption has occurred
- Error has been logged in system error logs
- User can continue with other scheduling tasks

---

### Test Case: Ensure errors are logged with sufficient detail
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in as Scheduler
- System error logging is enabled and accessible
- Access to system logs or logging dashboard is available
- Backend can be configured to trigger specific error scenarios
- Timestamp synchronization is working correctly

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Access the system error logs or logging dashboard before triggering the error | Error logs are accessible and current log entries are visible with timestamps |
| 2 | Note the current timestamp and prepare to trigger an error scenario | Current timestamp is recorded for log verification purposes |
| 3 | Configure backend to simulate a specific error during conflict detection (e.g., database connection failure) | Error simulation is configured with identifiable characteristics |
| 4 | Trigger the error scenario by initiating conflict detection from the scheduling interface | Conflict detection fails with the simulated error and user sees error message |
| 5 | Access the system error logs immediately after the error occurs | New error log entry is created and visible in the logging system |
| 6 | Verify the error log contains accurate timestamp matching the time of error occurrence | Log entry shows timestamp within seconds of when the error was triggered |
| 7 | Verify the error log contains user context information (user ID, username, or session ID) | Log entry includes user identification information showing which Scheduler triggered the error |
| 8 | Verify the error log contains operation context (conflict detection, scheduling details, affected resources) | Log entry includes details about what operation was being performed and which resources or schedules were involved |
| 9 | Verify the error log contains technical error details (error type, error code, stack trace if applicable) | Log entry includes sufficient technical information for developers to diagnose the issue, including error type and relevant stack trace |
| 10 | Verify the error log contains severity level classification | Log entry is marked with appropriate severity level (e.g., ERROR, CRITICAL) for proper alerting and prioritization |
| 11 | Trigger multiple different error scenarios and verify each is logged distinctly | Each error scenario creates a separate, identifiable log entry with scenario-specific details |

**Postconditions:**
- All triggered errors are logged in the system
- Error logs contain complete diagnostic information
- Logs are accessible for support team review
- No sensitive user information is exposed in logs
- Log storage is functioning correctly

---

