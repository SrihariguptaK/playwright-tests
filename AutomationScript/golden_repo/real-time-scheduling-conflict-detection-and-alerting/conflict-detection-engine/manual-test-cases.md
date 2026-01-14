# Manual Test Cases

## Story: As Scheduler, I want the system to detect scheduling conflicts within 2 seconds to enable immediate action
**Story ID:** story-12

### Test Case: Verify conflict detection within 2 seconds
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Scheduler role
- Scheduling system is operational and accessible
- At least one existing booking is present in the system
- System clock is synchronized
- Conflict detection service is running

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the scheduling interface and note the current timestamp | Scheduling interface loads successfully with booking creation form displayed |
| 2 | Create a new booking entry that overlaps with an existing booking (same resource, overlapping time slot) | Booking submission is processed and conflict detection is triggered |
| 3 | Record the timestamp when conflict notification appears and calculate the time difference from submission | System detects and displays the conflict within 2 seconds of booking submission |
| 4 | Navigate to an existing booking and update it to create a resource over-allocation (assign more resources than available) | Booking update is submitted successfully |
| 5 | Monitor for conflict detection notification and measure response time | Conflict is detected and logged promptly within 2 seconds, with notification displayed to the scheduler |
| 6 | Access the conflict logs via the system interface or API endpoint GET /api/conflicts | Conflict logs are accessible and displayed |
| 7 | Verify that all conflicts from previous steps are recorded in the logs with accurate timestamps and relevant metadata (booking IDs, resource names, conflict type) | All conflicts are recorded with correct timestamps showing detection within 2 seconds, including complete metadata for each conflict |

**Postconditions:**
- All test conflicts are logged in the system
- No bookings are permanently saved with conflicts
- System remains in operational state
- Test data can be cleaned up or retained for audit

---

### Test Case: Test detection under concurrent scheduling inputs
- **ID:** tc-002
- **Type:** edge-case
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Multiple test user accounts with Scheduler role are available
- Scheduling system is operational with adequate resources
- Performance monitoring tools are configured and accessible
- Test environment can simulate concurrent users
- Baseline performance metrics are documented

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Set up simulation environment to create 5-10 concurrent scheduler sessions | All concurrent sessions are established and authenticated successfully |
| 2 | Simultaneously create multiple overlapping bookings from different scheduler sessions targeting the same resources and time slots | All booking requests are submitted concurrently to the system |
| 3 | Monitor each session for conflict detection notifications and record the detection time for each conflict | System detects conflicts for all overlapping bookings without delay, all within 2 seconds of submission |
| 4 | Access system performance metrics dashboard or API to retrieve detection latency measurements during the concurrent load | Performance metrics are retrieved successfully showing individual detection times |
| 5 | Analyze the performance data to verify that all conflict detections occurred within the 2-second threshold | Detection latency remains under 2 seconds for all concurrent requests, with no performance degradation |
| 6 | Review conflict logs to create a comprehensive list of all expected conflicts based on the concurrent bookings created | Complete list of expected conflicts is compiled |
| 7 | Cross-reference the conflict logs against the expected conflicts list to verify completeness | All conflicts are identified accurately with no missed detections, 100% detection rate confirmed |

**Postconditions:**
- All concurrent test sessions are closed
- System performance returns to baseline levels
- All test conflicts are logged
- Performance metrics are documented for future reference
- Test bookings are cleaned up from the system

---

## Story: As Scheduler, I want to configure conflict detection rules to tailor alerts to my resource types
**Story ID:** story-14

### Test Case: Validate rule configuration and application
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in with Scheduler role and appropriate permissions
- Conflict rule configuration interface is accessible
- At least two different resource types exist in the system
- Current conflict detection rules are documented
- System configuration database is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the conflict rule configuration interface via the system menu or direct URL | Conflict rule configuration interface loads successfully |
| 2 | Review the displayed current rules for all resource types, noting existing settings and thresholds | Current rules are displayed clearly with all configured parameters visible including resource types, overlap thresholds, and enabled/disabled checks |
| 3 | Select a specific resource type (e.g., Conference Room) and modify its rules with valid settings: set allowable overlap time to 15 minutes and enable buffer time check | Rule modification interface accepts the changes and displays updated values |
| 4 | Click the Save button to persist the rule changes | System validates the rules, displays a success confirmation message, and rules are saved successfully |
| 5 | Verify the saved rules by refreshing the configuration interface and checking that the modified settings persist | Modified rules are displayed correctly showing the 15-minute overlap allowance and enabled buffer time check |
| 6 | Attempt to create a new rule with invalid syntax (e.g., negative overlap time of -10 minutes) | System displays validation error indicating invalid input |
| 7 | Attempt to save conflicting rules (e.g., set minimum booking duration longer than maximum booking duration for the same resource type) | System rejects the changes with a descriptive error message explaining the logical conflict between the rules |
| 8 | Correct the invalid rules to valid settings and attempt to save again | System accepts the corrected rules and saves them successfully with confirmation message |

**Postconditions:**
- Valid rule changes are persisted in the configuration database
- Invalid rule attempts are rejected without affecting existing rules
- System maintains data integrity
- Audit log contains record of rule modification attempts

---

### Test Case: Verify detection engine applies updated rules
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- User is logged in with Scheduler role
- Conflict rule configuration interface is accessible
- Conflict detection engine is running
- At least one resource type with configurable rules exists
- Booking creation interface is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the conflict rule configuration interface and document the current rules for a specific resource type (e.g., Meeting Room) | Current rules are displayed and documented, showing default settings |
| 2 | Modify the conflict detection rules for Meeting Room resource type: set allowable overlap to 30 minutes and disable strict time slot enforcement | Rule modifications are entered successfully |
| 3 | Save the updated rules and note the exact timestamp of the save action | System saves the rules successfully and displays confirmation with timestamp |
| 4 | Wait and monitor the system status for up to 1 minute to allow rule propagation to the detection engine | System indicates that rules are being applied or shows active status |
| 5 | After 1 minute has elapsed, verify via system logs or admin interface that the updated rules have been applied to the detection engine | Rules are applied to the detection engine within 1 minute of saving, confirmed by system logs or status indicators |
| 6 | Navigate to the booking creation interface and create a new booking for a Meeting Room resource | Booking creation form is displayed and ready for input |
| 7 | Create a booking that overlaps with an existing Meeting Room booking by exactly 25 minutes (within the new 30-minute allowable overlap threshold) | Booking is submitted successfully |
| 8 | Observe the system response and check for conflict notifications | No conflict is detected or alerted because the 25-minute overlap is within the configured 30-minute allowable threshold, demonstrating that updated rules are active |
| 9 | Create another booking that overlaps by 35 minutes (exceeding the 30-minute threshold) | Booking is submitted successfully |
| 10 | Observe the system response for conflict detection | Conflict is detected and notification is displayed because the 35-minute overlap exceeds the configured threshold, confirming conflict detection behaves according to updated rules |

**Postconditions:**
- Updated rules are active in the detection engine
- Conflict detection behaves according to new rule parameters
- Test bookings demonstrate rule application
- System logs reflect rule changes and detection behavior
- Test bookings can be removed or retained for further testing

---

## Story: As Scheduler, I want the system to log all detected conflicts with timestamps and metadata for audit and analysis
**Story ID:** story-15

### Test Case: Verify logging of detected conflicts with metadata
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- User has authorized access to the conflict logging system
- Conflict detection engine is running and operational
- Centralized logging database is accessible and has sufficient storage
- API endpoint GET /api/conflict-logs is available
- At least two bookings exist that can create a conflict scenario
- Detection rule version is configured and active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Create two overlapping bookings for the same resource to trigger a conflict detection event | Conflict is detected by the system and conflict detection engine processes the event |
| 2 | Verify that the conflict is logged automatically by checking the logging service status | Logging service confirms that the conflict event has been recorded with a unique log entry ID |
| 3 | Check that the log entry contains an accurate timestamp of when the conflict was detected | Timestamp is present in ISO 8601 format and matches the time of conflict detection within acceptable margin (±1 second) |
| 4 | Verify that the log entry includes metadata for involved bookings (booking IDs, booking times, user information) | All involved booking IDs are present with complete booking details including start time, end time, and associated user information |
| 5 | Verify that the log entry includes resource information (resource ID, resource name, resource type) | Complete resource details are logged including resource ID, name, and type |
| 6 | Verify that the detection rule version used is recorded in the log entry | Detection rule version number is present and matches the currently active rule version |
| 7 | Send a GET request to /api/conflict-logs endpoint with appropriate authentication credentials | API responds with HTTP 200 status code and returns the conflict log data |
| 8 | Query the logs using the conflict ID or timestamp to retrieve the specific log entry created in previous steps | Log entry is successfully retrieved with all complete details including timestamp, booking IDs, resource information, and detection rule version |
| 9 | Verify that the retrieved log entry matches the expected data structure and contains all required fields | Log entry contains all mandatory fields: conflict_id, timestamp, involved_bookings[], resources[], detection_rule_version, conflict_type, and status |
| 10 | Initiate an export operation for the conflict logs through the API or UI, specifying the desired format (CSV, JSON, or XML) | Export request is accepted and processing begins |
| 11 | Download or retrieve the exported log file | Logs are successfully exported in the requested format with all data intact and properly formatted |
| 12 | Open and verify the exported file contains the conflict log entry with all metadata | Exported file is readable, contains the logged conflict with complete metadata, and data integrity is maintained |

**Postconditions:**
- Conflict log entry remains stored in the centralized database
- Log entry is available for future queries and audits
- Exported log file is saved and accessible for analysis
- No data corruption or loss occurred during logging or export process
- System resources are released and logging service is ready for next event

---

### Test Case: Ensure logging does not impact detection performance
- **ID:** tc-002
- **Type:** edge-case
- **Priority:** High
- **Estimated Time:** 20 mins

**Preconditions:**
- Conflict detection engine is operational with logging enabled
- Performance monitoring tools are configured and ready
- Baseline performance metrics are established
- Test environment has representative load conditions
- System has sufficient resources (CPU, memory, disk I/O)
- Ability to enable/disable logging feature for comparison testing
- Multiple test conflict scenarios are prepared for consistent testing

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Ensure that the logging feature is enabled in the system configuration | Logging feature status is confirmed as enabled through system settings or configuration file |
| 2 | Prepare a set of 10 conflict scenarios with overlapping bookings to ensure consistent testing conditions | Test data is ready with 10 predefined conflict scenarios that can be triggered repeatedly |
| 3 | Clear any existing performance metrics and reset monitoring tools to baseline | Performance monitoring tools are reset and ready to capture fresh metrics |
| 4 | Trigger the first conflict detection scenario and start measuring the detection latency from conflict occurrence to detection completion | Conflict is detected and latency measurement is recorded |
| 5 | Repeat the conflict detection process for all 10 prepared scenarios while recording latency for each detection | All 10 conflicts are detected and individual latency measurements are captured |
| 6 | Calculate the average detection latency with logging enabled across all 10 test runs | Average detection latency is calculated and documented (e.g., 1.2 seconds) |
| 7 | Verify that the average detection latency with logging enabled remains within the acceptable threshold of 2 seconds | Average latency is at or below 2 seconds, meeting the performance requirement |
| 8 | Verify that individual detection latencies do not exceed 2 seconds for any single test run | All individual latency measurements are within the 2-second threshold |
| 9 | Disable the logging feature in the system configuration | Logging feature is successfully disabled and confirmed through system settings |
| 10 | Clear performance metrics and reset monitoring tools again for the second test phase | Monitoring tools are reset and ready for the next measurement phase |
| 11 | Trigger the same 10 conflict detection scenarios used previously and measure detection latency without logging | All 10 conflicts are detected and latency measurements are captured without logging overhead |
| 12 | Calculate the average detection latency with logging disabled across all 10 test runs | Average detection latency without logging is calculated and documented (e.g., 1.1 seconds) |
| 13 | Compare the average detection latency with logging enabled versus logging disabled | Difference in average latency is calculated (e.g., 0.1 seconds difference) |
| 14 | Verify that the performance difference between logging enabled and disabled is not significant (less than 10% degradation or less than 200ms absolute difference) | Performance impact is minimal and within acceptable limits, confirming that logging does not significantly degrade detection performance |
| 15 | Document the performance test results including both average latencies and the percentage difference | Complete performance report is generated showing that logging has no measurable negative impact on conflict detection performance |

**Postconditions:**
- Logging feature is re-enabled to operational state
- Performance metrics are documented and stored for future reference
- System performance remains within acceptable parameters
- No performance degradation is observed in conflict detection
- Test data and scenarios are preserved for regression testing
- Performance baseline is updated if necessary

---

