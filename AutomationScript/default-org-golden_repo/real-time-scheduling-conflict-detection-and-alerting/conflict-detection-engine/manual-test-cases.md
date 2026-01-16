# Manual Test Cases

## Story: As Scheduler, I want to detect overlapping appointments to prevent double-booking resources
**Story ID:** story-11

### Test Case: Detect overlapping appointments for the same resource
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Scheduler role
- Scheduling system is accessible and operational
- Resource A exists in the system and is available
- No existing appointments for Resource A in the test time window
- User has permissions to create appointments

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the appointment creation page | Appointment creation form is displayed with all required fields |
| 2 | Select Resource A from the resource dropdown | Resource A is selected and displayed in the resource field |
| 3 | Set appointment start time to 10:00 and end time to 11:00 | Time fields are populated with 10:00 to 11:00 |
| 4 | Fill in all other required appointment details and click Save | Appointment is saved successfully and confirmation message is displayed |
| 5 | Navigate back to appointment creation page to create a second appointment | New appointment creation form is displayed |
| 6 | Select Resource A from the resource dropdown | Resource A is selected and displayed in the resource field |
| 7 | Set appointment start time to 10:30 and end time to 11:30 | Time fields are populated with 10:30 to 11:30 |
| 8 | Fill in all other required appointment details and click Save | System detects overlap and flags conflict immediately with a conflict warning message |
| 9 | Review conflict details displayed in the UI | Conflict information shows both appointment times (10:00-11:00 and 10:30-11:30), appointment IDs, and Resource A identifier |

**Postconditions:**
- First appointment remains saved in the system
- Second appointment is not saved due to conflict
- Conflict details are logged in the system
- Scheduler is aware of the conflict and can take corrective action

---

### Test Case: Ensure conflict detection latency is under 2 seconds
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in with Scheduler role
- Scheduling system is operational
- At least one existing appointment is present in the system
- Timer or performance monitoring tool is available
- System is under normal load conditions

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Start timer and navigate to appointment creation or update page | Page loads successfully and timer is running |
| 2 | Create or update an appointment that overlaps with an existing appointment | Appointment details are entered successfully |
| 3 | Click Save and measure time until conflict detection completes | System processes conflict detection and displays result within 2 seconds |
| 4 | Verify conflict flag appears in UI immediately after detection | Conflict flag is visible without noticeable delay, clearly indicating the overlap |
| 5 | Simulate concurrent operations by having multiple users create appointments simultaneously | System handles concurrent requests without errors |
| 6 | Measure conflict detection latency during concurrent operations | System maintains latency under 2 seconds SLA during concurrent operations with no performance degradation |

**Postconditions:**
- Conflict detection performance meets SLA requirements
- System remains responsive under load
- All conflict detections are logged with timestamps
- No appointments are saved with undetected conflicts

---

### Test Case: Support conflict detection across time zones
- **ID:** tc-003
- **Type:** edge-case
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- User is logged in with Scheduler role
- System supports multiple time zones
- Resource is available for scheduling
- User's time zone is configured in their profile
- System can handle time zone conversions

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to appointment creation page | Appointment creation form is displayed |
| 2 | Select a resource and set time zone to 'America/New_York' (Time Zone A) | Time zone A is selected and displayed |
| 3 | Create an appointment from 14:00 to 15:00 EST and save | Appointment is saved successfully with correct time zone metadata (EST) displayed in confirmation |
| 4 | Navigate to create a new appointment for the same resource | New appointment creation form is displayed |
| 5 | Select the same resource and set time zone to 'Europe/London' (Time Zone B) | Time zone B is selected and displayed |
| 6 | Create an overlapping appointment from 19:00 to 20:00 GMT (equivalent to 14:00-15:00 EST) and attempt to save | System detects conflict considering time zone differences and displays conflict warning |
| 7 | Review the conflict alert details | Conflict alert shows appointment times adjusted to user's time zone with both original time zones indicated (14:00-15:00 EST and 19:00-20:00 GMT shown as equivalent) |
| 8 | Verify that both appointments display correct local times in the conflict details | System correctly converts and displays times, clearly showing the overlap despite different time zone representations |

**Postconditions:**
- First appointment remains saved with Time Zone A metadata
- Second appointment is blocked due to detected conflict
- Time zone conversion is accurate and logged
- Conflict alert displays times in user's preferred time zone

---

## Story: As Scheduler, I want to detect double-booking of resources across multiple schedules to avoid resource conflicts
**Story ID:** story-12

### Test Case: Detect double-booking of resource across multiple schedules
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in with Scheduler role
- Multiple schedules (Schedule 1 and Schedule 2) exist in the system
- Resource B exists and is shared across both schedules
- User has access to both Schedule 1 and Schedule 2
- No existing appointments for Resource B in the test time window
- System can aggregate data from multiple calendars

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to Schedule 1 appointment creation page | Schedule 1 appointment creation form is displayed |
| 2 | Select Resource B from the resource dropdown | Resource B is selected and displayed |
| 3 | Set appointment start time to 14:00 and end time to 15:00 | Time fields show 14:00 to 15:00 |
| 4 | Fill in all required appointment details and click Save | Appointment is saved successfully in Schedule 1 with confirmation message displayed |
| 5 | Navigate to Schedule 2 appointment creation page | Schedule 2 appointment creation form is displayed |
| 6 | Select Resource B from the resource dropdown | Resource B is selected and displayed |
| 7 | Set appointment start time to 14:30 and end time to 15:30 | Time fields show 14:30 to 15:30 |
| 8 | Fill in all required appointment details and click Save | System detects double-booking across schedules and flags conflict immediately with warning message |
| 9 | Review conflict details displayed in the UI | Conflict information shows both appointments (14:00-15:00 from Schedule 1 and 14:30-15:30 from Schedule 2), appointment IDs, Resource B identifier, and both schedule names |

**Postconditions:**
- Appointment in Schedule 1 remains saved
- Appointment in Schedule 2 is blocked due to conflict
- Conflict is logged with details of both schedules
- Resource B availability status is accurate across both schedules

---

### Test Case: Ensure conflict detection latency under 3 seconds
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in with Scheduler role
- Multiple schedules are configured in the system
- At least one existing appointment exists that can cause a double-booking
- Timer or performance monitoring tool is available
- System is operational under normal load

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Start timer and navigate to appointment creation page in any schedule | Appointment creation form loads and timer is running |
| 2 | Create or update an appointment that causes a double-booking with an existing appointment in another schedule | All appointment details are entered successfully |
| 3 | Click Save and measure time until conflict detection completes | System detects conflict and displays result within 3 seconds |
| 4 | Stop timer and record the latency | Recorded latency is under 3 seconds |
| 5 | Verify conflict alert is visible in the UI | Alert is displayed promptly in UI with clear conflict details and no noticeable delay |

**Postconditions:**
- Conflict detection latency meets the 3-second SLA
- Conflict alert is visible to the user
- Performance metrics are logged
- Double-booked appointment is not saved

---

### Test Case: Prevent saving double-booked appointments without override
- **ID:** tc-006
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- Two user accounts exist: one with override permission and one without
- User without override permission is logged in
- Multiple schedules exist in the system
- An existing appointment creates potential for double-booking
- System has role-based access control configured

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | As user without override permission, navigate to appointment creation page | Appointment creation form is displayed |
| 2 | Create an appointment that double-books a resource already scheduled in another schedule | Appointment details are entered |
| 3 | Attempt to save the double-booked appointment | System blocks save operation and displays error message indicating double-booking conflict and insufficient permissions to override |
| 4 | Verify that the appointment was not saved to the system | Appointment does not appear in any schedule and database shows no new record |
| 5 | Log out and log in as user with override permission | User with override permission is successfully logged in |
| 6 | Navigate to appointment creation page and create the same double-booked appointment | Appointment details are entered and conflict is detected |
| 7 | Acknowledge the conflict warning and select the override option | Override option is available and can be selected |
| 8 | Attempt to save with override permission enabled | System allows save operation, displays confirmation message, and shows override warning acknowledgment |
| 9 | Verify the override action is logged in the system | System logs override action with user ID, timestamp, appointment details, and reason for override |

**Postconditions:**
- Users without override permission cannot save double-booked appointments
- Users with override permission can save double-booked appointments
- All override actions are logged with complete audit trail
- System maintains data integrity and access control

---

## Story: As Scheduler, I want the system to handle concurrent scheduling updates without conflicts to maintain data integrity
**Story ID:** story-19

### Test Case: Handle concurrent scheduling updates without data corruption
- **ID:** tc-019-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Scheduling system is operational and accessible
- At least 2 scheduler user accounts are active and authenticated
- Test appointment exists in the system with ID and version number
- Database concurrency controls are enabled
- Network connectivity is stable for all test users

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | User 1 opens the existing appointment for editing and loads appointment details | Appointment details are displayed with current version number and all fields are editable |
| 2 | User 2 simultaneously opens the same appointment for editing | Appointment details are displayed to User 2 with the same version number as User 1 |
| 3 | User 1 modifies the appointment time from 2:00 PM to 3:00 PM and clicks Save | System successfully saves User 1's changes, increments version number, and displays success confirmation |
| 4 | User 2 modifies the appointment location and clicks Save without refreshing | System detects version mismatch and prevents save operation, displaying conflict error message |
| 5 | Verify conflict notification is displayed to User 2 | Conflict notification appears within 2 seconds stating 'This appointment has been modified by another user. Please refresh and try again.' |
| 6 | User 2 clicks Refresh button to reload the appointment | Updated appointment data with User 1's changes is displayed with new version number |
| 7 | User 2 reapplies their location change and clicks Save | System successfully saves User 2's changes with correct version number and displays success confirmation |
| 8 | Verify final appointment data in database | Appointment contains both User 1's time change (3:00 PM) and User 2's location change with no data corruption or loss |

**Postconditions:**
- Appointment data is consistent and contains all valid changes
- No data corruption occurred during concurrent updates
- Version number is correctly incremented
- All users can view the final updated appointment
- System audit log records both update attempts and conflict resolution

---

### Test Case: Maintain performance under high concurrency
- **ID:** tc-019-002
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 25 mins

**Preconditions:**
- Scheduling system is operational with full resources allocated
- 100 scheduler user accounts are created and authenticated
- Test dataset contains at least 500 appointments
- Performance monitoring tools are configured and running
- Load testing environment is set up with concurrent user simulation capability
- Baseline performance metrics are documented (response time SLA is defined)

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Configure load testing tool to simulate 100 concurrent scheduler users | Load testing tool is configured with 100 virtual users ready to execute scheduling operations |
| 2 | Start performance monitoring and capture baseline metrics (CPU, memory, database connections) | Performance monitoring dashboard shows current system metrics and is recording data |
| 3 | Initiate concurrent load test with all 100 users performing read operations (viewing appointments) | All 100 users successfully retrieve appointment data with response times within SLA (< 2 seconds) |
| 4 | Execute concurrent write operations with 100 users creating new appointments simultaneously | System processes all create requests with response times within SLA, no timeouts or errors occur |
| 5 | Execute concurrent update operations with 100 users modifying different appointments simultaneously | All update operations complete successfully within SLA, no deadlocks or transaction failures occur |
| 6 | Execute mixed operations with 50 users reading, 30 users updating, and 20 users creating appointments simultaneously | System handles mixed workload with all operations completing within SLA thresholds |
| 7 | Monitor system resource utilization during peak concurrent load | CPU utilization remains below 80%, memory usage is stable, database connection pool has available connections |
| 8 | Review performance metrics and calculate average response times across all operations | Average response time is within SLA, 95th percentile response time does not exceed 3 seconds, zero failed transactions |
| 9 | Verify data integrity by checking random sample of 50 appointments created/updated during test | All sampled appointments contain correct data with no corruption, duplicates, or missing information |

**Postconditions:**
- System maintains stable performance under 100 concurrent users
- No performance degradation observed during sustained load
- All transactions completed successfully without data loss
- System resources return to normal levels after load test completion
- Performance test results are documented and meet SLA requirements

---

## Story: As Scheduler, I want the system to support multiple calendar formats for conflict detection to ensure compatibility
**Story ID:** story-20

### Test Case: Parse and detect conflicts from iCal format
- **ID:** tc-020-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Scheduling system is operational and accessible
- Scheduler user account is authenticated
- Valid iCal (.ics) test file is prepared with multiple calendar events
- System has iCal parser module enabled
- At least one existing appointment in the system to create potential conflicts

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to calendar import section and select 'Import Calendar' option | Import dialog opens with file upload interface and format selection options |
| 2 | Select iCal format option and browse to upload the prepared .ics test file | File is selected and filename is displayed in the upload field |
| 3 | Click 'Import' button to upload and process the iCal file | System displays processing indicator and begins parsing the iCal data |
| 4 | Verify parsing completion and review import summary | System displays success message showing number of events parsed (e.g., '15 events successfully imported'), data is normalized and stored in system format |
| 5 | Navigate to calendar view and verify imported iCal events are displayed | All imported events from iCal file are visible with correct dates, times, titles, and descriptions |
| 6 | Create a new appointment that conflicts with an imported iCal event (same date/time) | System allows appointment creation form to be filled with conflicting time slot |
| 7 | Attempt to save the conflicting appointment | System detects the conflict with the iCal imported event and displays conflict warning message: 'Conflict detected with existing event: [Event Name] at [Time]' |
| 8 | Review conflict details showing both the new appointment and the conflicting iCal event | Conflict details panel displays both appointments side-by-side with overlapping time highlighted, iCal source is indicated |
| 9 | Verify format-specific metadata is preserved by viewing iCal event properties | iCal-specific fields (UID, SEQUENCE, DTSTAMP) are preserved and displayed in event metadata |

**Postconditions:**
- iCal calendar data is successfully imported and stored
- All iCal events are normalized and accessible in the system
- Conflict detection accurately identifies overlaps with iCal events
- Format-specific metadata is preserved for audit purposes
- No data loss or corruption occurred during import

---

### Test Case: Parse and detect conflicts from Google Calendar format
- **ID:** tc-020-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Scheduling system is operational and accessible
- Scheduler user account is authenticated
- Google Calendar API integration is configured and enabled
- Test Google Calendar account exists with OAuth credentials configured
- Test Google Calendar contains at least 5 events
- System has valid OAuth tokens for Google Calendar access

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to calendar sync section and select 'Connect Google Calendar' option | System displays Google Calendar integration interface with 'Authorize' button |
| 2 | Click 'Authorize' button to initiate OAuth authentication flow | Google OAuth consent screen opens in new window requesting calendar access permissions |
| 3 | Grant calendar read permissions and complete OAuth authorization | Authorization completes successfully, system receives OAuth token, and user is redirected back to scheduling system |
| 4 | Click 'Sync Now' button to retrieve Google Calendar events via API | System initiates API call to Google Calendar, displays sync progress indicator |
| 5 | Monitor sync process and wait for completion | Sync completes successfully with message 'Google Calendar synced: X events imported', data is parsed and normalized |
| 6 | Navigate to calendar view and verify Google Calendar events are displayed | All synced Google Calendar events appear with correct dates, times, attendees, and descriptions, Google Calendar icon indicates source |
| 7 | Verify Google Calendar-specific metadata is preserved by viewing event details | Google Calendar event ID, organizer email, and attendee list are preserved and displayed in event properties |
| 8 | Create a new appointment with date/time that conflicts with a synced Google Calendar event | Appointment creation form accepts the conflicting time slot details |
| 9 | Attempt to save the conflicting appointment | System detects conflict with Google Calendar event and displays warning: 'Conflict detected with Google Calendar event: [Event Name] at [Time]' |
| 10 | Review conflict resolution options and verify accuracy of conflict detection | Conflict panel shows both appointments with overlapping time range highlighted, Google Calendar source is clearly indicated, conflict detection is accurate to the minute |
| 11 | Verify no data loss by comparing event count before and after sync | All Google Calendar events are accounted for, no events missing or duplicated, event data matches source calendar |

**Postconditions:**
- Google Calendar is successfully connected via OAuth
- All Google Calendar events are synced and normalized in the system
- Conflict detection accurately identifies overlaps with Google Calendar events
- Google Calendar-specific metadata is preserved
- No data loss or corruption occurred during sync
- OAuth token is securely stored for future syncs

---

## Story: As Scheduler, I want the system to support multi-time zone scheduling to accurately detect conflicts globally
**Story ID:** story-22

### Test Case: Verify appointment creation with time zone data
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as a Scheduler with appointment creation permissions
- Scheduling system is accessible and operational
- At least two different time zones are available in the system (e.g., EST and PST)
- User profile has a default local time zone configured
- Database is configured to store time zone metadata

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the appointment creation page | Appointment creation form is displayed with all required fields including time zone selector |
| 2 | Enter appointment title as 'Global Team Meeting' | Title field accepts and displays the entered text |
| 3 | Select date as current date + 7 days | Date picker displays the selected date correctly |
| 4 | Set appointment start time to 10:00 AM | Time field displays 10:00 AM |
| 5 | Set appointment end time to 11:00 AM | Time field displays 11:00 AM |
| 6 | Select time zone A (e.g., America/New_York - EST) from the time zone dropdown | Time zone dropdown displays 'America/New_York (EST)' as selected |
| 7 | Click 'Save' or 'Create Appointment' button | System processes the request and displays success confirmation message. Appointment is saved with correct time zone metadata including zone identifier, offset, and DST information |
| 8 | Navigate to appointment details page to verify stored data | Appointment details show: Title='Global Team Meeting', Date=selected date, Time=10:00 AM - 11:00 AM, Time Zone=America/New_York (EST) |
| 9 | Change user profile time zone to time zone B (e.g., America/Los_Angeles - PST) | User profile successfully updated to PST time zone |
| 10 | View the same appointment in the calendar or appointment list | Appointment time is automatically converted and displayed correctly in local time (PST): 7:00 AM - 8:00 AM with indication that original time zone is EST |
| 11 | Verify time zone conversion calculation manually (EST to PST = -3 hours) | Displayed time matches expected conversion: 10:00 AM EST = 7:00 AM PST |

**Postconditions:**
- Appointment is successfully stored in database with complete time zone metadata
- Appointment is visible in calendar views with correct time conversions
- Time zone data integrity is maintained for future conflict detection
- User can view appointment in any time zone with accurate conversions
- System logs record the appointment creation with time zone information

---

### Test Case: Detect conflicts across different time zones
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in as a Scheduler with appointment creation permissions
- Scheduling system is operational with conflict detection enabled
- Multiple time zones are configured in the system (e.g., EST, PST, GMT)
- Database supports time zone storage and conversion
- No existing appointments in the test time window
- Conflict detection algorithm is active and functioning

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to appointment creation page | Appointment creation form is displayed with all fields including time zone selector |
| 2 | Create first appointment: Title='Meeting A', Date=current date + 5 days, Time=2:00 PM - 3:00 PM, Time Zone=America/New_York (EST) | First appointment is successfully created and saved with EST time zone |
| 3 | Verify first appointment is displayed in calendar | Meeting A appears in calendar at 2:00 PM - 3:00 PM EST |
| 4 | Navigate to create a second appointment | New appointment creation form is displayed |
| 5 | Create second appointment with overlapping time in different time zone: Title='Meeting B', Date=same date as Meeting A, Time=11:00 AM - 12:00 PM, Time Zone=America/Los_Angeles (PST) | System begins processing the appointment creation request |
| 6 | Click 'Save' or 'Create Appointment' button | System performs time zone conversion (11:00 AM PST = 2:00 PM EST) and detects conflict with Meeting A |
| 7 | Observe system response to conflict detection | System displays conflict warning message indicating: 'Conflict detected: This appointment overlaps with Meeting A (2:00 PM - 3:00 PM EST / 11:00 AM - 12:00 PM PST)' |
| 8 | Review conflict details provided by the system | Conflict message shows both appointments with their respective time zones and the converted overlapping time period |
| 9 | Attempt to create third appointment with partial overlap: Title='Meeting C', Date=same date, Time=11:30 AM - 12:30 PM, Time Zone=America/Los_Angeles (PST) | System detects partial conflict (11:30 AM - 12:00 PM PST overlaps with 2:30 PM - 3:00 PM EST portion of Meeting A) and displays appropriate conflict warning |
| 10 | Create fourth appointment with no overlap: Title='Meeting D', Date=same date, Time=12:00 PM - 1:00 PM, Time Zone=America/Los_Angeles (PST) | System converts time (12:00 PM PST = 3:00 PM EST), detects no conflict, and successfully creates the appointment |
| 11 | Verify all appointments in calendar view with user time zone set to GMT | All appointments are displayed with correct time conversions to GMT: Meeting A at 7:00 PM - 8:00 PM GMT, Meeting D at 8:00 PM - 9:00 PM GMT |

**Postconditions:**
- System accurately detected conflicts across different time zones
- Conflicting appointments were prevented or flagged appropriately
- Non-conflicting appointments were created successfully
- All appointments maintain correct time zone metadata
- Conflict detection logs are recorded for audit purposes
- Calendar displays all appointments with accurate time zone conversions

---

