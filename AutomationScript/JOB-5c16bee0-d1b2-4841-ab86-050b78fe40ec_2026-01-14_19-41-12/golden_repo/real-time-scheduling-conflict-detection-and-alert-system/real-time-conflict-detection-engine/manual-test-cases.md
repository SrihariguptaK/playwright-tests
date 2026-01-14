# Manual Test Cases

## Story: As Scheduler, I want to receive real-time alerts for overlapping appointments to prevent double bookings
**Story ID:** story-11

### Test Case: Validate detection of overlapping appointments with real-time alert
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Scheduler role
- Scheduling system is operational and accessible
- At least one existing appointment is present in the system (e.g., Appointment A scheduled from 10:00 AM to 11:00 AM)
- User has permissions to create and modify appointments
- Audit logging is enabled and functioning

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the appointment creation page | Appointment creation form is displayed with all required fields (date, time, duration, resource) |
| 2 | Enter appointment details that overlap with existing Appointment A (e.g., start time 10:30 AM, end time 11:30 AM on the same date) | Form accepts the input and fields are populated correctly |
| 3 | Click 'Save' or 'Create Appointment' button | System detects the time conflict and displays a real-time alert notification with conflict details including overlapping appointment information, time range, and affected resources |
| 4 | Review the alert details displayed on screen | Alert clearly shows the conflicting appointment details, time overlap period, and provides an 'Acknowledge' button or option |
| 5 | Click the 'Acknowledge' button on the alert | Alert is dismissed from the UI and a confirmation message indicates the acknowledgment was recorded |
| 6 | Navigate to the conflict audit log or system logs section | Audit log page displays successfully with search and filter options |
| 7 | Search for the recent conflict entry using appointment details or timestamp | Conflict log entry is found showing the detected overlap, timestamp of detection, user who acknowledged it, and acknowledgment timestamp |

**Postconditions:**
- Conflict alert has been acknowledged and dismissed
- Audit log contains complete record of the conflict detection and acknowledgment
- System is ready for next appointment operation
- No duplicate log entries exist for the same conflict

---

### Test Case: Verify system performance under concurrent appointment creations
- **ID:** tc-002
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- Multiple scheduler users are logged in simultaneously (minimum 5 users)
- Scheduling system is operational with normal load
- Performance monitoring tools are active and configured
- Test data includes multiple overlapping appointment scenarios
- System clock is synchronized across all test environments

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Prepare 10-15 appointment creation requests with intentional overlaps across different time slots | Test data is prepared with documented overlap scenarios and expected conflicts |
| 2 | Initiate concurrent appointment creation from multiple scheduler accounts simultaneously (simulate peak load) | All appointment creation requests are submitted to the system within a 2-second window |
| 3 | Monitor and record the time taken for each conflict detection alert to appear | All conflict alerts are displayed within 1 second of appointment submission for each overlapping appointment |
| 4 | Verify that each scheduler receives alerts relevant to their appointment creations | All schedulers receive their respective conflict alerts promptly with correct conflict details and no missing notifications |
| 5 | Check each scheduler's UI for alert delivery completeness | Each scheduler sees only their relevant alerts with complete information about the conflicts |
| 6 | Navigate to system logs and error logs section | System logs interface loads successfully showing recent activity |
| 7 | Review system logs for any errors, exceptions, or missed conflict detections during the concurrent operations | No errors, exceptions, or warnings are present in the logs; all conflicts are logged correctly with accurate timestamps |
| 8 | Verify performance metrics show detection latency remained under 1 second threshold | Performance monitoring data confirms 100% of conflict detections occurred within 1 second latency requirement |

**Postconditions:**
- All concurrent appointments have been processed
- All conflicts have been detected and logged
- System performance metrics are documented
- No system errors or degradation occurred
- System has returned to normal operational state

---

### Test Case: Ensure no alerts for non-overlapping appointments
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in with Scheduler role
- Scheduling system is operational
- Existing appointments are present in the system with known time slots
- Alert notification system is enabled
- System logs are accessible and cleared of previous test data

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the appointment creation page | Appointment creation form is displayed with all required fields |
| 2 | Create first appointment with specific time slot (e.g., 9:00 AM to 10:00 AM) | Appointment is created successfully without any alerts, confirmation message is displayed |
| 3 | Create second appointment with non-overlapping time slot (e.g., 10:00 AM to 11:00 AM - immediately after first appointment) | Appointment is created successfully without any conflict alerts or warnings |
| 4 | Create third appointment with completely separate time slot (e.g., 2:00 PM to 3:00 PM) | Appointment is created successfully with no alerts displayed |
| 5 | Verify the UI notification area or alert panel | No conflict alerts or notifications are visible in the UI |
| 6 | Navigate to the system logs or conflict log section | Logs interface loads successfully |
| 7 | Search for conflict records related to the recently created appointments | No conflict records are found for the non-overlapping appointments; search returns zero results |
| 8 | Check the scheduler's notification history or alert inbox | No alert notifications are present for the created appointments; notification area is empty or shows only unrelated items |

**Postconditions:**
- Three non-overlapping appointments exist in the system
- No conflict alerts were generated or displayed
- System logs contain no conflict records for these appointments
- Scheduler received no false positive alerts
- System is ready for next test scenario

---

## Story: As Scheduler, I want to receive alerts for resource double-bookings to avoid scheduling conflicts
**Story ID:** story-12

### Test Case: Validate detection of resource double-bookings with alert
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Scheduler role
- Resource management system is operational
- At least one resource exists in the system (e.g., Conference Room A)
- An existing appointment has Resource A assigned from 10:00 AM to 11:00 AM
- User has permissions to assign resources to appointments
- Audit logging is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the appointment creation or resource assignment page | Resource assignment interface is displayed with available resources listed |
| 2 | Create a new appointment or select an existing appointment for the same time period (10:00 AM to 11:00 AM) | Appointment form is displayed with resource selection dropdown or field |
| 3 | Select and assign the same resource (Resource A) that is already booked for the overlapping time period | Resource is selected in the form |
| 4 | Click 'Save' or 'Assign Resource' button | System detects the resource double-booking and immediately displays a real-time alert with conflict details including resource name, conflicting appointment details, and time overlap |
| 5 | Review the alert notification displayed on screen | Alert clearly shows the resource conflict details, including resource name, both conflicting appointments, time ranges, and provides an 'Acknowledge' option |
| 6 | Click the 'Acknowledge' button on the alert | Alert is dismissed from the UI and system displays confirmation that acknowledgment was recorded |
| 7 | Navigate to the conflict audit log or resource conflict log section | Audit log interface loads successfully with filter and search capabilities |
| 8 | Search for the recent resource conflict entry using resource name or timestamp | Conflict log entry is displayed showing the resource double-booking details, detection timestamp, conflicting appointments, user who acknowledged, and acknowledgment timestamp |

**Postconditions:**
- Resource double-booking alert has been acknowledged
- Complete audit trail exists for the conflict detection and acknowledgment
- System is ready for next resource assignment operation
- Resource conflict is documented in the system logs

---

### Test Case: Verify no alerts for non-conflicting resource assignments
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in with Scheduler role
- Resource management system is operational
- Multiple resources are available in the system (e.g., Conference Room A, Conference Room B, Projector 1)
- Some existing appointments with resource assignments are present
- Alert system is enabled and functioning

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the appointment creation page | Appointment creation form is displayed with resource assignment options |
| 2 | Create first appointment and assign Resource A for time slot 9:00 AM to 10:00 AM | Appointment is created successfully with Resource A assigned, no alerts are displayed, confirmation message appears |
| 3 | Create second appointment and assign Resource B (different resource) for the same time slot 9:00 AM to 10:00 AM | Appointment is created successfully with Resource B assigned, no conflict alerts are generated |
| 4 | Create third appointment and assign Resource A for a non-overlapping time slot 10:00 AM to 11:00 AM | Appointment is created successfully with Resource A assigned for the new time slot, no alerts are displayed |
| 5 | Verify the UI notification area for any alerts | No conflict alerts or notifications are visible in the user interface |
| 6 | Navigate to the system logs or resource conflict logs section | Logs interface loads successfully |
| 7 | Search for conflict records related to the recently assigned resources | No conflict records are found for the non-conflicting resource assignments; search returns zero conflict entries |
| 8 | Check the scheduler's notification panel or alert history | No alert notifications are present; notification area shows no resource conflict alerts for the created appointments |

**Postconditions:**
- Multiple appointments with non-conflicting resource assignments exist in the system
- No false positive alerts were generated
- System logs contain no conflict records for these resource assignments
- Resources are correctly assigned without conflicts
- System is ready for next test

---

### Test Case: Test system performance under concurrent resource assignments
- **ID:** tc-006
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- Multiple scheduler users are logged in simultaneously (minimum 5 users)
- Resource management system is operational under normal load
- Multiple resources are available for assignment
- Performance monitoring tools are configured and active
- Test scenarios include intentional resource conflicts prepared
- System time is synchronized across all test clients

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Prepare 10-15 resource assignment scenarios with intentional double-bookings across different resources and time slots | Test data is prepared with documented conflict scenarios and expected outcomes |
| 2 | Initiate concurrent resource assignments from multiple scheduler accounts simultaneously to simulate peak usage | All resource assignment requests are submitted to the system within a 2-second window |
| 3 | Monitor and record the time taken for each conflict detection alert to appear for conflicting assignments | All resource conflict alerts are displayed within 1 second of resource assignment submission |
| 4 | Verify that each scheduler receives alerts for their respective resource conflicts | All schedulers receive their relevant conflict alerts promptly with accurate resource conflict details |
| 5 | Check each scheduler's UI to confirm alert delivery and content accuracy | Each scheduler sees only their relevant resource conflict alerts with complete and accurate information |
| 6 | Navigate to system logs and error logs section | System logs interface loads successfully showing recent resource assignment activity |
| 7 | Review logs for any errors, exceptions, or missed conflict detections during concurrent operations | No errors, exceptions, or warnings are present; all resource conflicts are logged correctly with accurate timestamps and details |
| 8 | Analyze performance metrics to verify detection latency remained under 1 second | Performance data confirms 100% of resource conflict detections occurred within the 1 second latency requirement |
| 9 | Verify no conflicts were missed during the concurrent load test | All intentional conflicts are accounted for in the logs and alerts; detection accuracy is 100% |

**Postconditions:**
- All concurrent resource assignments have been processed
- All resource conflicts have been detected and alerted
- Performance metrics are documented and meet requirements
- No system errors or performance degradation occurred
- System has returned to normal operational state
- Complete audit trail exists for all operations

---

