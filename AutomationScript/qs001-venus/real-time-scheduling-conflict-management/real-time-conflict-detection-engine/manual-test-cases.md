# Manual Test Cases

## Story: As Scheduler, I want to detect overlapping bookings to avoid double scheduling of resources
**Story ID:** story-1

### Test Case: Detect overlapping booking and prevent confirmation
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Scheduler user is logged in with valid credentials
- Scheduling system is operational and accessible
- At least one resource exists in the system with an active booking
- Existing booking: Resource 'Conference Room A' booked from 10:00 AM to 11:00 AM on current date
- Scheduler has permission to create and modify bookings
- Conflict detection service is running and responsive

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the booking creation page | Booking form is displayed with fields for resource selection, date, start time, and end time |
| 2 | Select resource 'Conference Room A' from the resource dropdown | Resource 'Conference Room A' is selected and displayed in the form |
| 3 | Enter current date in the date field | Date is populated correctly in the date field |
| 4 | Enter start time as 10:15 AM and end time as 10:45 AM (overlapping with existing 10:00 AM - 11:00 AM booking) | Time values are entered in the respective fields |
| 5 | Click 'Submit' or 'Confirm Booking' button | System displays conflict warning message indicating 'Resource Conference Room A is already booked from 10:00 AM to 11:00 AM' and booking confirmation button is disabled or blocked |
| 6 | Verify that the booking cannot be saved by attempting to click confirm again | Booking remains unconfirmed and system continues to display conflict warning |
| 7 | Modify the start time to 11:00 AM and end time to 12:00 PM (non-overlapping slot) | Updated time values are displayed in the form fields |
| 8 | Click 'Submit' or 'Confirm Booking' button | System allows booking confirmation without warnings, displays success message, and booking is saved successfully |
| 9 | Navigate to conflict logs section or access logs via API endpoint GET /api/conflicts/logs | Conflict logs interface or API response is displayed |
| 10 | Search for conflict log entry related to 'Conference Room A' for the attempted booking at 10:15 AM - 10:45 AM | Conflict log entry is present showing resource 'Conference Room A', attempted time slot 10:15 AM - 10:45 AM, timestamp of conflict detection, and scheduler user details |

**Postconditions:**
- Original booking for Conference Room A from 10:00 AM to 11:00 AM remains unchanged
- New booking for Conference Room A from 11:00 AM to 12:00 PM is successfully created
- Conflict attempt is logged in the system with complete metadata
- No double booking exists for Conference Room A

---

### Test Case: Verify conflict detection latency under 1 second
- **ID:** tc-002
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Scheduler user is logged in with valid credentials
- Scheduling system is operational with normal load
- Performance monitoring tools are available and configured
- Existing booking: Resource 'Meeting Room B' booked from 2:00 PM to 3:00 PM on current date
- System clock is synchronized and accurate
- Network latency is within normal operational parameters

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open browser developer tools or performance monitoring tool to track response times | Performance monitoring tool is active and recording network requests |
| 2 | Navigate to booking creation page and fill in resource 'Meeting Room B', current date, start time 2:15 PM, end time 2:45 PM | Booking form is populated with conflicting time slot details |
| 3 | Note the current timestamp and click 'Submit' or 'Check Availability' button | System initiates conflict detection request to POST /api/schedule/check-conflict endpoint |
| 4 | Measure the time elapsed from submission to conflict warning display using performance monitoring tool | Conflict detection processing completes and response is received within 1 second (1000 milliseconds) |
| 5 | Observe the UI response and verify conflict warning is displayed | Conflict warning message appears immediately on screen without noticeable delay, displaying 'Resource Meeting Room B is already booked from 2:00 PM to 3:00 PM' |
| 6 | Verify the booking confirmation button state | Booking confirmation button is disabled or blocked, preventing save action |
| 7 | Attempt to click the disabled confirmation button | Booking cannot be saved, system displays message indicating conflict must be resolved first |
| 8 | Review performance monitoring logs to confirm exact latency measurement | Recorded latency shows conflict detection API response time is less than 1000 milliseconds |

**Postconditions:**
- Conflict detection completed within performance requirements
- Booking remains unsaved due to unresolved conflict
- System performance metrics are recorded for analysis
- User is prevented from creating double booking

---

### Test Case: Ensure system logs all detected conflicts
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Scheduler user is logged in with valid credentials
- Admin user credentials are available for log access
- Logging service is operational and connected to database
- Existing booking: Resource 'Projector Unit 5' booked from 9:00 AM to 10:00 AM on current date
- Conflict logs database is accessible and has sufficient storage
- System time is synchronized for accurate timestamp recording

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to booking creation page as Scheduler user | Booking form is displayed and ready for input |
| 2 | Create a conflicting booking attempt by selecting resource 'Projector Unit 5', current date, start time 9:30 AM, end time 10:30 AM | Form is populated with conflicting booking details |
| 3 | Click 'Submit' button to trigger conflict detection | System detects conflict and displays warning message blocking the booking confirmation |
| 4 | Note the exact time of conflict detection for verification purposes | Current timestamp is recorded for comparison with log entry |
| 5 | Log in as Admin user or switch to admin interface | Admin dashboard is displayed with access to system logs |
| 6 | Navigate to conflict logs section or execute API call GET /api/conflicts/logs | Conflict logs interface or API response is displayed showing list of logged conflicts |
| 7 | Query or filter logs for resource 'Projector Unit 5' and the timestamp of the recent conflict attempt | Log entry for the conflicting booking attempt is present in the results |
| 8 | Open the specific log entry and review its contents | Log entry displays complete details including resource name 'Projector Unit 5', attempted time slot 9:30 AM - 10:30 AM, existing booking time 9:00 AM - 10:00 AM, scheduler username, and conflict type |
| 9 | Verify the timestamp in the log entry matches the time when conflict was detected (within acceptable margin of seconds) | Timestamp in log entry accurately reflects the time of conflict detection |
| 10 | Verify resource information accuracy by comparing log data with actual resource details | Resource ID, resource name, and resource type in log entry match the actual resource 'Projector Unit 5' details in the system |
| 11 | Check log metadata for completeness including user ID, session ID, and conflict resolution status | All metadata fields are populated with accurate information showing unresolved conflict status |

**Postconditions:**
- Conflict is logged in the system with complete and accurate metadata
- Log entry is retrievable via both API and admin UI
- Original booking for Projector Unit 5 remains unchanged
- Conflicting booking attempt was not saved
- Audit trail is maintained for compliance purposes

---

## Story: As Scheduler, I want the system to log all detected scheduling conflicts for audit and troubleshooting
**Story ID:** story-6

### Test Case: Verify logging of detected conflicts
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Scheduler user is logged in with valid credentials
- Admin user credentials are available for accessing logs
- Logging service is operational and connected to secure database
- Existing booking: Resource 'Training Room C' booked from 1:00 PM to 2:00 PM on current date
- Admin UI for log access is accessible
- API endpoint GET /api/conflicts/logs is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | As Scheduler user, navigate to booking creation page | Booking form is displayed with all required fields |
| 2 | Select resource 'Training Room C', enter current date, start time 1:30 PM, end time 2:30 PM to create overlapping booking | Form is populated with conflicting booking details |
| 3 | Click 'Submit' button to trigger scheduling conflict | System detects conflict, displays warning message, and blocks booking confirmation |
| 4 | Wait 2 seconds to ensure log write operation completes | System processes and writes log entry to database |
| 5 | Execute API call GET /api/conflicts/logs with appropriate authentication token | API returns HTTP 200 status with JSON response containing array of conflict log entries |
| 6 | Parse API response and search for log entry matching resource 'Training Room C' and timestamp of recent conflict | Log entry is present in API response with all required metadata fields: resourceId, resourceName, attemptedStartTime, attemptedEndTime, existingStartTime, existingEndTime, userId, timestamp, conflictType |
| 7 | Verify log entry metadata completeness by checking each field contains valid data | All metadata fields are populated: resourceId='Training Room C', attemptedStartTime='1:30 PM', attemptedEndTime='2:30 PM', existingStartTime='1:00 PM', existingEndTime='2:00 PM', userId matches scheduler, timestamp is accurate, conflictType='OVERLAP' |
| 8 | Log in to admin UI using admin credentials | Admin dashboard is displayed with navigation menu including conflict logs section |
| 9 | Navigate to conflict logs section in admin UI | Conflict logs page is displayed showing list of logged conflicts with search and filter options |
| 10 | Verify search functionality by entering resource name 'Training Room C' in search field | Search results are filtered to show only conflicts related to 'Training Room C' |
| 11 | Verify filter options by applying date filter for current date | Results are further filtered to show only conflicts from current date |
| 12 | Locate and click on the specific log entry for the recent conflict | Detailed view of log entry is displayed showing all metadata fields with accurate information matching API response |

**Postconditions:**
- Conflict is logged with complete metadata in secure database
- Log entry is accessible via both API and admin UI
- Search and filter functionality is confirmed operational
- Audit trail is maintained for the conflict event
- No data inconsistency between API and UI log displays

---

### Test Case: Test log write performance
- **ID:** tc-005
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- Scheduler user is logged in with valid credentials
- Admin user credentials are available for log verification
- Performance monitoring tools are configured and active
- Multiple resources exist in the system with existing bookings
- Logging database has sufficient capacity and is optimized
- System is under normal operational load
- High-precision timer or monitoring tool is available to measure millisecond-level performance

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Prepare test data: Identify 5 different resources with existing bookings at various time slots | Test data is documented: Resource1 booked 9:00-10:00, Resource2 booked 10:00-11:00, Resource3 booked 11:00-12:00, Resource4 booked 1:00-2:00, Resource5 booked 2:00-3:00 |
| 2 | Start performance monitoring tool to track database write operations and response times | Performance monitoring is active and recording metrics |
| 3 | Trigger first conflict by attempting to book Resource1 from 9:15 AM to 9:45 AM and record timestamp | Conflict detected, warning displayed, timestamp T1 recorded |
| 4 | Immediately trigger second conflict by attempting to book Resource2 from 10:15 AM to 10:45 AM and record timestamp | Conflict detected, warning displayed, timestamp T2 recorded |
| 5 | Immediately trigger third conflict by attempting to book Resource3 from 11:15 AM to 11:45 AM and record timestamp | Conflict detected, warning displayed, timestamp T3 recorded |
| 6 | Immediately trigger fourth conflict by attempting to book Resource4 from 1:15 PM to 1:45 PM and record timestamp | Conflict detected, warning displayed, timestamp T4 recorded |
| 7 | Immediately trigger fifth conflict by attempting to book Resource5 from 2:15 PM to 2:45 PM and record timestamp | Conflict detected, warning displayed, timestamp T5 recorded |
| 8 | Review performance monitoring logs to measure log write duration for each conflict | Performance logs show individual write operation times: Write1, Write2, Write3, Write4, Write5 |
| 9 | Verify each log write operation completed within 100 milliseconds | All write operations (Write1 through Write5) show duration ≤ 100 milliseconds |
| 10 | Monitor system performance metrics including CPU usage, memory usage, and database response time during the test | System performance metrics remain within normal operational ranges with no significant spikes or degradation |
| 11 | Access conflict logs via API GET /api/conflicts/logs | API responds successfully with all 5 conflict log entries |
| 12 | Verify log completeness by checking all 5 conflicts are logged with correct details | All 5 log entries are present with accurate metadata: Resource1-5 conflicts logged with correct timestamps T1-T5, no data loss occurred |
| 13 | Verify log entry order and timestamp accuracy | Log entries are ordered chronologically with timestamps matching T1 through T5 within acceptable margin |

**Postconditions:**
- All 5 conflicts are logged successfully without data loss
- Each log write operation completed within 100 milliseconds performance requirement
- System performance remained stable with no degradation
- Database integrity is maintained
- Logs are retrievable and complete

---

### Test Case: Ensure secure access to logs
- **ID:** tc-006
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 18 mins

**Preconditions:**
- Logging system is operational with access control enabled
- Admin user credentials are available with proper permissions
- Regular scheduler user credentials are available without admin privileges
- Unauthorized user credentials or no credentials are available for negative testing
- Conflict logs exist in the database from previous test activities
- Encryption at rest is configured for the logging database
- Role-based access control (RBAC) is properly configured

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Attempt to access conflict logs API endpoint GET /api/conflicts/logs without authentication token | API returns HTTP 401 Unauthorized status with error message 'Authentication required' |
| 2 | Attempt to access conflict logs API endpoint GET /api/conflicts/logs with invalid or expired authentication token | API returns HTTP 401 Unauthorized status with error message 'Invalid or expired token' |
| 3 | Log in as regular Scheduler user (non-admin) and attempt to access conflict logs via API | API returns HTTP 403 Forbidden status with error message 'Insufficient permissions to access conflict logs' |
| 4 | Log in as regular Scheduler user and attempt to navigate to conflict logs section in UI | Conflict logs menu option is not visible or clicking it displays 'Access Denied' message |
| 5 | Attempt direct URL access to conflict logs page as regular Scheduler user | System redirects to unauthorized page or displays 'Access Denied - Admin privileges required' message |
| 6 | Log out and log in as Admin user with proper credentials | Admin dashboard is displayed with full navigation menu including conflict logs access |
| 7 | Execute API call GET /api/conflicts/logs with valid admin authentication token | API returns HTTP 200 status with JSON response containing conflict log entries |
| 8 | Navigate to conflict logs section in admin UI | Conflict logs page is displayed with full access to search, filter, and view log entries |
| 9 | Access database server or storage system where conflict logs are stored | Database connection is established with appropriate admin credentials |
| 10 | Query the conflict logs table directly and examine data storage format | Log data is stored in encrypted format, sensitive fields are not readable in plain text |
| 11 | Verify encryption configuration by checking database encryption settings | Encryption at rest is enabled with appropriate encryption algorithm (e.g., AES-256), encryption keys are properly managed |
| 12 | Review access control logs to verify all access attempts are logged | System audit logs show all access attempts including unauthorized attempts with user details and timestamps |
| 13 | Verify data encryption policy compliance by reviewing security documentation | Encryption implementation matches organizational security policy requirements for sensitive audit data |

**Postconditions:**
- Unauthorized access attempts are blocked and logged
- Admin access is granted and functional
- Log data encryption at rest is verified and compliant
- Access control mechanisms are functioning correctly
- Security audit trail is maintained for all access attempts
- No unauthorized data exposure occurred during testing

---

## Story: As Scheduler, I want the system to handle concurrent scheduling inputs without conflicts or data loss
**Story ID:** story-8

### Test Case: Verify no data loss under concurrent scheduling inputs
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 30 mins

**Preconditions:**
- Scheduling system is operational and accessible
- Database has transaction support enabled
- Test environment configured to support 100 concurrent connections
- Test data prepared with valid scheduling inputs for 100 users
- Database baseline snapshot taken for comparison
- Monitoring tools configured to track database operations

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Configure load testing tool to simulate 100 concurrent users | Load testing tool successfully configured with 100 user profiles |
| 2 | Prepare unique scheduling data for each of the 100 concurrent users with varying resources, times, and dates | 100 unique scheduling requests prepared and validated |
| 3 | Execute concurrent submission of all 100 schedules simultaneously via POST /api/schedule/save endpoint | All 100 scheduling requests submitted without connection errors or timeouts |
| 4 | Monitor API responses for all 100 requests | All 100 requests return successful HTTP status codes (200 or 201) with confirmation messages |
| 5 | Query the database to count total number of saved schedule records | Database contains exactly 100 new schedule records matching the submitted data |
| 6 | Verify data integrity by comparing each saved record against original submission data | All 100 records contain accurate and complete data with no corruption or missing fields |
| 7 | Check database for duplicate entries or orphaned records | No duplicate or orphaned records found in the database |
| 8 | Execute conflict detection algorithm on all saved schedules | Conflict detection runs successfully and identifies all actual conflicts accurately |
| 9 | Review conflict detection results against expected conflicts based on test data design | 100% accuracy in conflict detection with no false positives or false negatives |
| 10 | Verify database transaction logs for rollback or error entries | Transaction logs show successful commits with no rollbacks or errors |

**Postconditions:**
- All 100 schedules successfully saved in database
- Database integrity maintained with no data loss
- Conflict detection accuracy verified at 100%
- System remains stable and operational
- Test data cleaned up or marked for cleanup

---

### Test Case: Ensure user feedback on concurrent conflicts
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- Scheduling system is operational
- Two test user accounts with scheduler role created and authenticated
- Shared resource available for scheduling (e.g., Conference Room A)
- Real-time notification system enabled
- System logging configured and active
- Both users have active sessions in the scheduling interface

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | User 1 begins creating a schedule for Conference Room A on 2024-01-15 from 10:00 AM to 11:00 AM | Scheduling form populated with resource and time details for User 1 |
| 2 | User 2 simultaneously begins creating a schedule for Conference Room A on 2024-01-15 from 10:30 AM to 11:30 AM (overlapping time) | Scheduling form populated with resource and time details for User 2 |
| 3 | User 1 submits the schedule first | User 1 receives confirmation that schedule was saved successfully |
| 4 | User 2 submits the overlapping schedule within 2 seconds of User 1 | User 2 immediately receives a conflict alert indicating the resource is already booked during the requested time |
| 5 | Verify conflict alert details shown to User 2 | Alert displays conflicting booking details including resource name, conflicting time range, and existing booking information |
| 6 | Check if User 1 also receives notification about the conflict attempt | User 1 receives notification that another user attempted to book the same resource during their scheduled time |
| 7 | User 2 adjusts schedule to Conference Room A from 11:30 AM to 12:30 PM (non-overlapping time) | User 2 successfully modifies the schedule with new time slot |
| 8 | User 2 resubmits the adjusted schedule | Schedule saved successfully with confirmation message and no conflict alerts |
| 9 | Verify both schedules exist in the system without conflicts | Both User 1 and User 2 schedules are saved and visible in the scheduling dashboard |
| 10 | Access system logs and search for concurrent conflict events | Logs contain entries showing the conflict event with timestamps, user IDs, resource details, and conflict resolution outcome |
| 11 | Verify log data accuracy by comparing with actual event timeline | Log timestamps and details match the actual sequence of events accurately |

**Postconditions:**
- Both users have successfully saved schedules without conflicts
- Conflict alerts were delivered immediately to affected users
- System logs contain complete and accurate concurrency conflict data
- No data corruption or loss occurred
- Users remain authenticated and system is operational

---

### Test Case: Test system performance under concurrency
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 45 mins

**Preconditions:**
- Scheduling system deployed in test environment matching production specifications
- Load testing tool configured and validated
- 100 concurrent user profiles created with valid credentials
- System monitoring tools active (CPU, memory, database connections, response times)
- SLA defined with acceptable response time thresholds (e.g., <2 seconds)
- Baseline performance metrics captured
- Test scheduling data prepared for all 100 users

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Configure load testing tool to simulate 100 concurrent scheduling users with realistic usage patterns | Load test configured with 100 virtual users ready to execute scheduling operations |
| 2 | Start system monitoring tools to track CPU usage, memory consumption, database connections, and response times | All monitoring tools active and recording baseline metrics |
| 3 | Initiate load test with gradual ramp-up to 100 concurrent users over 2 minutes | Load test starts successfully with users ramping up smoothly |
| 4 | Monitor system response times during the load test for all scheduling operations | Average response time remains within SLA threshold (e.g., <2 seconds) for 95th percentile |
| 5 | Verify maximum response time does not exceed critical threshold | Maximum response time stays below critical threshold (e.g., <5 seconds) |
| 6 | Monitor CPU usage across all application servers during peak load | CPU usage remains below 80% with no sustained spikes above 90% |
| 7 | Monitor memory consumption during concurrent operations | Memory usage remains stable with no memory leaks detected and stays below 85% capacity |
| 8 | Monitor database connection pool usage | Database connections managed efficiently with no connection pool exhaustion |
| 9 | Monitor disk I/O and network bandwidth utilization | Disk I/O and network bandwidth remain within acceptable limits with no bottlenecks |
| 10 | Review application logs for errors, exceptions, or warnings during the load test | No critical errors, exceptions, or system failures logged during the test |
| 11 | Verify all 100 concurrent users completed their scheduling operations successfully | 100% success rate for all scheduling operations with no failed transactions |
| 12 | Check for any timeout errors or connection failures | Zero timeout errors or connection failures during the entire test duration |
| 13 | Sustain 100 concurrent users for 10 minutes to test system stability | System maintains stable performance throughout the sustained load period |
| 14 | Gradually ramp down concurrent users and monitor system recovery | System resources return to baseline levels smoothly without issues |

**Postconditions:**
- System maintained response times within SLA during 100 concurrent users
- No critical resource exhaustion occurred
- Zero errors or failures logged during the test
- System remains operational and stable
- Performance metrics documented for analysis
- Test data cleaned up from the system

---

## Story: As Scheduler, I want the system to provide detailed conflict metadata to understand and resolve scheduling issues
**Story ID:** story-9

### Test Case: Verify detailed conflict metadata display
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Scheduling system is operational and accessible
- Test user with scheduler role is authenticated
- At least one existing schedule in the system for Conference Room A on 2024-01-15 from 2:00 PM to 3:00 PM
- Conflict detection mechanism is enabled
- Dashboard interface is accessible
- Conflict severity classification rules are configured

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Create a new schedule for Conference Room A on 2024-01-15 from 2:30 PM to 3:30 PM (overlapping with existing booking) | Scheduling form accepts the input and prepares for submission |
| 2 | Submit the conflicting schedule | System detects the conflict and displays a conflict alert immediately |
| 3 | Review the conflict alert message for metadata completeness | Alert includes booking IDs (both existing and attempted), resource name (Conference Room A), conflicting time range (2:30 PM - 3:00 PM), and conflict timestamp |
| 4 | Verify the alert displays the user who created the existing conflicting booking | Alert shows the name or ID of the user who owns the existing booking |
| 5 | Check if the alert includes descriptions or titles of both bookings | Both booking descriptions/titles are displayed in the alert |
| 6 | Navigate to the conflicts dashboard or conflict management section | Dashboard loads successfully showing list of conflicts |
| 7 | Locate the recently triggered conflict in the dashboard | Conflict appears in the dashboard list with summary information |
| 8 | Click on the conflict entry to view detailed metadata | Detailed conflict view opens displaying comprehensive metadata |
| 9 | Verify metadata includes both booking IDs | Both the existing booking ID and attempted booking ID are displayed |
| 10 | Verify metadata includes complete resource information | Resource details displayed including resource name, type, location, and capacity |
| 11 | Verify metadata includes accurate timestamps | Timestamps shown for conflict detection time, existing booking creation time, and attempted booking submission time |
| 12 | Check for conflict severity indicator in the metadata display | Severity indicator is clearly visible (e.g., High, Medium, Low or color-coded) |
| 13 | Verify the severity level matches the expected classification based on conflict type | Severity level is appropriate (e.g., High for complete overlap, Medium for partial overlap) |
| 14 | Check if metadata includes overlap duration information | Overlap duration displayed (e.g., 30 minutes overlap) |

**Postconditions:**
- Conflict alert displayed with complete metadata
- Dashboard shows conflict with detailed information
- Severity indicator clearly visible and accurate
- No data corruption or system errors
- User remains authenticated and can continue working

---

### Test Case: Test metadata retrieval performance
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 20 mins

**Preconditions:**
- Scheduling system is operational
- API endpoint GET /api/conflicts/details is accessible
- At least one conflict exists in the system with ID known for testing
- Test user with scheduler role has valid API authentication token
- Unauthorized test user account created without scheduler role
- Performance monitoring tools configured to measure response times
- Network conditions are stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Prepare API request to GET /api/conflicts/details with valid conflict ID and authentication token | API request properly formatted with required headers and parameters |
| 2 | Start timer and send API request to retrieve conflict metadata | API request sent successfully |
| 3 | Measure the response time from request initiation to complete response receipt | Response received within 1 second (1000ms or less) |
| 4 | Verify HTTP status code of the response | HTTP status code 200 OK returned |
| 5 | Parse the response body to extract conflict metadata | Response body contains valid JSON with conflict metadata structure |
| 6 | Verify presence of booking IDs in the response | Both conflicting booking IDs are present in the response |
| 7 | Verify presence of resource information in the response | Resource name, type, and other resource details are included |
| 8 | Verify presence of timestamp fields in the response | All required timestamp fields (conflict detection time, booking times) are present |
| 9 | Verify presence of conflict severity indicator in the response | Severity field is present with valid value |
| 10 | Verify presence of user information for conflicting bookings | User IDs or names for both bookings are included |
| 11 | Validate data accuracy by comparing response data with database records | All metadata fields match the actual conflict data in the database |
| 12 | Verify no required fields are missing or null | All mandatory fields contain valid non-null values |
| 13 | Repeat API request 5 times to verify consistent performance | All 5 requests return responses within 1 second |
| 14 | Prepare API request using unauthorized user credentials (user without scheduler role) | API request formatted with unauthorized user token |
| 15 | Send API request to GET /api/conflicts/details with unauthorized credentials | API request sent successfully |
| 16 | Verify the response status code for unauthorized access | HTTP status code 403 Forbidden or 401 Unauthorized returned |
| 17 | Verify no conflict metadata is returned in the response body | Response body contains error message indicating access denied, with no sensitive conflict data exposed |
| 18 | Check system logs for unauthorized access attempt | Security log contains entry for denied access attempt with user ID and timestamp |

**Postconditions:**
- Metadata retrieval performance verified at under 1 second
- All required metadata fields confirmed present and accurate
- Access control verified working correctly
- Unauthorized access properly denied and logged
- System remains secure and operational

---

