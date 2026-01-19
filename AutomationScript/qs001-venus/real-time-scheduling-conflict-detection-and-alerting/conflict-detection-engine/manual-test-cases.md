# Manual Test Cases

## Story: As Scheduler, I want to detect overlapping appointments in real-time to prevent double-booking
**Story ID:** story-11

### Test Case: Validate detection of overlapping appointments
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Scheduler role
- User has permissions to create and modify appointments
- Appointment database is accessible and operational
- No existing appointments in the test time slot
- Real-time conflict detection service is running

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the appointment creation page | Appointment creation form is displayed with all required fields |
| 2 | Enter appointment details: Date: Today's date, Start time: 10:00 AM, End time: 11:00 AM, Resource: Conference Room A, Client: Test Client 1 | All appointment details are populated in the form fields |
| 3 | Click 'Save' button to create the appointment | Appointment is saved successfully, confirmation message is displayed, and appointment appears in the schedule |
| 4 | Navigate to create a new appointment | New appointment creation form is displayed |
| 5 | Enter overlapping appointment details: Date: Today's date, Start time: 10:30 AM, End time: 11:30 AM, Resource: Conference Room A, Client: Test Client 2 | Appointment details are entered in the form |
| 6 | Click 'Save' button or tab out of the time field to trigger validation | System detects conflict within 1 second and displays conflict warning message showing the overlapping appointment details (10:00 AM - 11:00 AM with Test Client 1) |
| 7 | Attempt to save the overlapping appointment without providing override justification | System prevents saving the appointment and displays conflict error message: 'Cannot save appointment due to conflict with existing appointment. Override required.' |
| 8 | Verify the conflicting appointment details are displayed including: original appointment time, resource, and client information | Conflict details clearly show: Appointment 1 (10:00 AM - 11:00 AM, Conference Room A, Test Client 1) conflicts with new appointment (10:30 AM - 11:30 AM, Conference Room A, Test Client 2) |

**Postconditions:**
- Only the first appointment (10:00 AM - 11:00 AM) exists in the system
- Overlapping appointment is not saved
- Conflict detection log entry is created
- No double-booking exists in the schedule

---

### Test Case: Verify configurable conflict detection rules
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- User is logged in with Admin or Scheduler role
- User has permissions to configure conflict detection rules
- Conflict rules configuration interface is accessible
- At least one default conflict rule exists in the system
- Test appointment types are defined in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to Settings > Conflict Detection Rules configuration page | Conflict detection rules configuration page is displayed showing existing rules |
| 2 | Click 'Add New Rule' button | New rule creation form is displayed with fields for rule name, appointment type, overlap threshold, and priority |
| 3 | Configure a new conflict rule: Rule Name: 'VIP Client Rule', Appointment Type: 'VIP Consultation', Overlap Allowed: 0 minutes, Priority: High, Status: Active | Rule details are entered in all fields |
| 4 | Click 'Save Rule' button | Rule is saved successfully, confirmation message is displayed, and 'VIP Client Rule' appears in the active rules list |
| 5 | Navigate to appointment creation page | Appointment creation form is displayed |
| 6 | Create first appointment: Type: 'VIP Consultation', Date: Tomorrow, Time: 2:00 PM - 3:00 PM, Resource: Room 1 | VIP appointment is created successfully |
| 7 | Create second appointment: Type: 'VIP Consultation', Date: Tomorrow, Time: 2:30 PM - 3:30 PM, Resource: Room 1 | System applies 'VIP Client Rule' and immediately detects conflict, displaying error message that no overlap is allowed for VIP consultations |
| 8 | Navigate back to Conflict Detection Rules configuration | Rules configuration page is displayed |
| 9 | Modify 'VIP Client Rule': Change Overlap Allowed from 0 minutes to 15 minutes, click 'Save' | Rule modification is saved successfully with confirmation message |
| 10 | Return to appointment creation and attempt to create the same overlapping appointment: Type: 'VIP Consultation', Date: Tomorrow, Time: 2:30 PM - 3:30 PM, Resource: Room 1 | System applies updated rule and still flags conflict because overlap (30 minutes) exceeds the allowed threshold (15 minutes) |
| 11 | Create a different overlapping appointment: Type: 'VIP Consultation', Date: Tomorrow, Time: 2:50 PM - 3:50 PM, Resource: Room 1 | System applies updated rule and allows the appointment because overlap (10 minutes) is within the allowed threshold (15 minutes) |

**Postconditions:**
- Modified conflict detection rule is active and applied
- Appointments created according to rule thresholds are saved
- Appointments violating rule thresholds are blocked
- Rule change is logged in audit trail

---

### Test Case: Ensure conflict detection latency is under 1 second
- **ID:** tc-003
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- User is logged in with Scheduler role
- Performance monitoring tools are available and configured
- System is running under normal load conditions
- Network latency is within acceptable range (<100ms)
- Test appointments and resources are prepared
- Browser developer tools or performance monitoring enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open browser developer tools and navigate to Network tab to monitor API response times | Developer tools are open and ready to capture network activity |
| 2 | Navigate to appointment creation page and create a baseline appointment: Date: Today, Time: 3:00 PM - 4:00 PM, Resource: Room A | Appointment is created successfully |
| 3 | Start timer and create a conflicting appointment: Date: Today, Time: 3:30 PM - 4:30 PM, Resource: Room A | Conflict detection is triggered |
| 4 | Measure the time from clicking 'Save' or tabbing out of time field until conflict warning appears on screen | Conflict is detected and displayed within 1 second (≤1000ms), verified by timestamp in developer tools and visual observation |
| 5 | Check the Network tab for the conflict detection API call response time | API response time for POST /api/appointments or conflict validation endpoint is under 1 second |
| 6 | Update an existing appointment to create a conflict: Change the 3:00 PM appointment end time to 5:00 PM, creating overlap with another appointment at 4:30 PM | System detects conflict during update operation within 1 second |
| 7 | Verify update conflict detection latency in Network tab | PUT /api/appointments/{id} response time shows conflict detection completed in under 1 second |
| 8 | Prepare to simulate high load: Open 5 browser tabs/windows with appointment creation forms | Multiple appointment creation interfaces are ready |
| 9 | Simultaneously create 5 appointments with overlapping times across all tabs within a 10-second window: Tab 1: 5:00-6:00 PM, Tab 2: 5:15-6:15 PM, Tab 3: 5:30-6:30 PM, Tab 4: 5:45-6:45 PM, Tab 5: 5:50-6:50 PM, all for Resource: Room B | All conflict detections are triggered |
| 10 | Monitor and record the conflict detection response time for each concurrent appointment creation | Each conflict detection completes within 1 second despite concurrent load, system maintains SLA requirements with latency ≤1000ms for all 5 operations |
| 11 | Review performance monitoring logs or metrics dashboard for conflict detection latency statistics | Average, median, and 95th percentile latency metrics all show values under 1 second for the test period |

**Postconditions:**
- All conflict detection operations completed within 1 second SLA
- Performance metrics are logged and available for review
- System maintained performance under concurrent load
- No appointments with conflicts were saved
- Performance test results are documented

---

## Story: As Scheduler, I want the system to support configurable conflict detection rules to adapt to different scheduling scenarios
**Story ID:** story-14

### Test Case: Validate creation and modification of conflict detection rules
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in with Admin role
- User has permissions to manage conflict detection rules
- Conflict rule configuration UI is accessible
- Database connection is active
- At least one existing conflict rule is present for reference

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to Settings > Conflict Detection Rules or Administration > Rule Management | Conflict rule configuration UI is displayed showing a list of existing rules with columns for rule name, type, status, and actions |
| 2 | Review the existing rules displayed in the list | All existing conflict detection rules are visible with their current configurations including rule names, appointment types, overlap thresholds, and active/inactive status |
| 3 | Click 'Create New Rule' or 'Add Rule' button | New rule creation form is displayed with empty fields for: Rule Name, Description, Appointment Type, Overlap Threshold (minutes), Priority Level, Exception Cases, and Active Status toggle |
| 4 | Enter new rule details: Rule Name: 'Standard Consultation Rule', Description: 'Default rule for standard consultations', Appointment Type: 'Standard Consultation', Overlap Threshold: 0 minutes, Priority: Medium, Active: Yes | All fields are populated with the entered values |
| 5 | Click 'Save' button | Rule is saved successfully, success confirmation message is displayed ('Rule created successfully'), and the page returns to the rules list view |
| 6 | Verify the new rule 'Standard Consultation Rule' appears in the rules list | New rule is visible in the list with all configured details displayed correctly: Name, Type, Overlap: 0 min, Priority: Medium, Status: Active |
| 7 | Locate an existing rule in the list and click 'Edit' or the rule name to modify it | Rule modification form is displayed with all current values pre-populated in the fields |
| 8 | Modify the rule: Change Overlap Threshold from current value to 10 minutes, Update Description to include 'Updated on [current date]' | Modified values are reflected in the form fields |
| 9 | Click 'Save Changes' button | Changes are saved successfully, confirmation message is displayed ('Rule updated successfully'), and the updated rule shows the new values in the rules list |
| 10 | Verify the modified rule displays updated information in the rules list | Rule shows updated Overlap Threshold (10 minutes) and updated description, modification timestamp is updated |
| 11 | Navigate away from the rules page and return to verify persistence | All created and modified rules persist with their saved configurations intact |

**Postconditions:**
- New conflict detection rule is created and active in the system
- Modified rule changes are persisted in the database
- All rule changes are logged in the audit trail
- Rules are immediately available for conflict detection operations

---

### Test Case: Verify rule validation and error handling
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- User is logged in with Admin role
- User has permissions to create and modify conflict rules
- Conflict rule configuration UI is accessible
- System validation rules are active and configured

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to Settings > Conflict Detection Rules configuration page | Conflict rule configuration UI is displayed |
| 2 | Click 'Create New Rule' button | New rule creation form is displayed with empty fields |
| 3 | Enter invalid rule syntax in the Overlap Threshold field: Enter text 'invalid' instead of a numeric value | Field accepts the input temporarily |
| 4 | Click 'Save' button to attempt saving the rule with invalid syntax | System displays validation error message: 'Overlap Threshold must be a numeric value' or 'Invalid input format', error is highlighted on the Overlap Threshold field, and rule is not saved |
| 5 | Clear the Overlap Threshold field and leave Rule Name field empty, then click 'Save' | System displays validation error: 'Rule Name is required' and prevents saving |
| 6 | Enter a negative number in Overlap Threshold field: -5 | System displays validation error: 'Overlap Threshold must be a positive number or zero' and prevents saving |
| 7 | Enter an excessively large number in Overlap Threshold field: 999999 | System displays validation error: 'Overlap Threshold exceeds maximum allowed value' or accepts if within business logic limits |
| 8 | Correct all validation errors: Rule Name: 'Test Valid Rule', Overlap Threshold: 15 (valid numeric value), Appointment Type: Select from dropdown, Priority: Medium | All fields contain valid values, no validation errors are displayed |
| 9 | Click 'Save' button | Rule is accepted and saved successfully, confirmation message is displayed: 'Rule created successfully', and rule appears in the rules list |
| 10 | Attempt to create a duplicate rule with the same Rule Name: 'Test Valid Rule' | System displays validation error: 'A rule with this name already exists' and prevents saving the duplicate |
| 11 | Verify that the rules list shows only the valid saved rule without any invalid entries | Only valid, successfully saved rules are displayed in the list, no invalid rules were persisted |

**Postconditions:**
- Only valid rules are saved in the system
- Invalid rule attempts are rejected and logged
- No corrupt or invalid data exists in the rules database
- User receives clear feedback on validation errors

---

### Test Case: Ensure dynamic application of rules during conflict detection
- **ID:** tc-006
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 14 mins

**Preconditions:**
- User is logged in with Admin or Scheduler role
- User has permissions to configure rules and create appointments
- Conflict detection service is running and operational
- No existing appointments in the test time slots
- At least one configurable rule exists or can be created

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to Settings > Conflict Detection Rules configuration | Conflict rules configuration page is displayed |
| 2 | Create a new rule allowing specific overlap: Rule Name: 'Flexible Meeting Rule', Appointment Type: 'Team Meeting', Overlap Allowed: 20 minutes, Priority: Low, Status: Active | Rule is created and saved successfully |
| 3 | Click 'Save' and verify the rule status shows as 'Active' | Rule is active and displayed in the active rules list with status indicator showing 'Active' or green checkmark |
| 4 | Navigate to appointment creation page | Appointment creation form is displayed |
| 5 | Create first appointment: Type: 'Team Meeting', Date: Tomorrow, Start Time: 10:00 AM, End Time: 11:00 AM, Resource: Conference Room C | Appointment is created successfully and appears in the schedule |
| 6 | Create second overlapping appointment within allowed threshold: Type: 'Team Meeting', Date: Tomorrow, Start Time: 10:45 AM (15 minutes overlap), End Time: 11:45 AM, Resource: Conference Room C | System applies 'Flexible Meeting Rule', calculates overlap as 15 minutes, determines it is within the 20-minute threshold, and does NOT flag a conflict |
| 7 | Click 'Save' on the second appointment | Appointment is saved successfully without conflict warning, confirmation message is displayed, and both appointments appear in the schedule |
| 8 | Create third overlapping appointment exceeding allowed threshold: Type: 'Team Meeting', Date: Tomorrow, Start Time: 10:30 AM (30 minutes overlap), End Time: 11:30 AM, Resource: Conference Room C | System applies 'Flexible Meeting Rule', calculates overlap as 30 minutes, determines it exceeds the 20-minute threshold |
| 9 | Observe system response when attempting to save the third appointment | System flags a conflict, displays error message: 'Appointment overlap (30 minutes) exceeds allowed threshold (20 minutes) for Team Meeting type', and prevents saving without override |
| 10 | Verify conflict details show: Conflicting appointment time, overlap duration (30 minutes), allowed threshold (20 minutes), and rule name applied | All conflict details are clearly displayed including which rule was applied and why the conflict was flagged |
| 11 | Cancel the third appointment creation and verify only the two valid appointments exist in the schedule | Schedule shows only the first appointment (10:00-11:00 AM) and second appointment (10:45-11:45 AM), third conflicting appointment was not saved |

**Postconditions:**
- Configured rule is actively applied during conflict detection
- Appointments within overlap threshold are successfully saved
- Appointments exceeding overlap threshold are blocked
- Rule application is logged for audit purposes
- Schedule integrity is maintained according to configured rules

---

## Story: As Scheduler, I want the system to handle concurrent scheduling updates without missing conflicts to maintain data integrity
**Story ID:** story-16

### Test Case: Validate conflict detection under concurrent schedule updates
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- Scheduling system is operational and accessible
- Multiple test user accounts with scheduler role are created and authenticated
- Scheduling database has concurrency controls enabled
- Test appointments with overlapping time slots are prepared
- System logging is enabled and configured
- API endpoint PUT /api/appointments/{id} is available
- Network connectivity is stable for all test users

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Set up 5 concurrent user sessions with valid authentication tokens | All 5 user sessions are authenticated and ready to perform schedule updates |
| 2 | Prepare overlapping appointment data: User1 schedules Room A from 10:00-11:00, User2 schedules Room A from 10:30-11:30, User3 schedules Room A from 10:15-11:15 | Test data is prepared with intentional time and resource conflicts |
| 3 | Simultaneously trigger PUT /api/appointments/{id} requests from all 5 users within a 100ms window | System receives all concurrent update requests without connection errors or timeouts |
| 4 | Monitor API responses for each concurrent request | System processes all updates and returns appropriate HTTP status codes (200 for success, 409 for conflicts) without errors or crashes |
| 5 | Query the scheduling database to retrieve all appointments created in the test window | All valid appointments are saved correctly, conflicting appointments are flagged with conflict status |
| 6 | Verify conflict detection results by checking each overlapping appointment for conflict flags | All 3 overlapping Room A appointments are detected and flagged as conflicts with no false negatives |
| 7 | Check conflict alert queue or notification system for generated alerts | Conflict alerts are generated for all detected conflicts (minimum 2 conflicts for the 3 overlapping appointments) |
| 8 | Access system logs and filter for concurrency events during the test execution window | System logs contain entries for all 5 concurrent update requests with timestamps, user IDs, and appointment IDs |
| 9 | Verify log entries include conflict detection events with details of conflicting appointments | All conflict events are logged accurately with conflict type, affected appointments, and detection timestamp |
| 10 | Validate data integrity by checking for duplicate appointments or missing records | No data corruption detected, all appointments are uniquely identified, no records are lost or duplicated |

**Postconditions:**
- All concurrent updates are processed and recorded in the database
- Conflict flags are accurately set for overlapping appointments
- System logs contain complete audit trail of concurrent operations
- No data corruption or inconsistencies exist in the scheduling database
- Conflict alerts are queued for user notification
- System remains stable and operational for subsequent operations

---

### Test Case: Ensure system performance under concurrent load
- **ID:** tc-002
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 25 mins

**Preconditions:**
- Scheduling system is operational with performance monitoring enabled
- Load testing tools are configured and ready (e.g., JMeter, LoadRunner)
- Performance baseline metrics are established
- System resource monitoring tools are active (CPU, memory, database connections)
- Test dataset with 1000+ appointments is loaded in the database
- Network bandwidth is sufficient for high-volume concurrent requests
- Performance SLA threshold is defined: conflict detection latency < 1 second

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Configure load testing tool to simulate 100 concurrent users performing schedule updates | Load testing tool is configured with 100 virtual users, each with valid authentication credentials |
| 2 | Prepare test data with 500 appointment update requests including 50 intentional conflicts | Test dataset is loaded with varied appointment times, resources, and conflict scenarios |
| 3 | Start system resource monitoring for CPU usage, memory consumption, database connections, and network I/O | Monitoring dashboards display real-time metrics with baseline values recorded |
| 4 | Initiate load test to generate high volume of concurrent schedule updates over a 5-minute duration | Load test executes successfully, generating 500 PUT /api/appointments/{id} requests from 100 concurrent users |
| 5 | Monitor API response times for each request during the load test | System responds to all requests with response times recorded for analysis |
| 6 | Measure conflict detection latency by calculating time between request receipt and conflict flag creation | Conflict detection latency is measured for all 50 conflict scenarios |
| 7 | Verify that 95th percentile conflict detection latency is under 1 second | 95% of conflict detections complete within 1 second, meeting performance SLA |
| 8 | Analyze CPU usage metrics during peak concurrent load | CPU usage remains below 80% threshold, indicating sufficient processing capacity |
| 9 | Review memory consumption patterns throughout the load test | Memory usage stays within acceptable limits (below 85%), no memory leaks detected |
| 10 | Check database connection pool utilization and query performance | Database connections are managed efficiently, no connection pool exhaustion, query execution times remain optimal |
| 11 | Verify system throughput by calculating successful transactions per second | System maintains minimum throughput of 10 transactions per second under concurrent load |
| 12 | Review error logs for any failures, timeouts, or exceptions during load test | Error rate is below 1%, no critical errors or system crashes occurred |

**Postconditions:**
- System maintains conflict detection latency under 1 second for 95% of requests
- All system resources operate within defined performance thresholds
- No performance degradation or system instability after load test completion
- Performance metrics are documented for baseline comparison
- System successfully processes high volume of concurrent updates without data loss
- Database integrity is maintained with no corruption or inconsistencies

---

