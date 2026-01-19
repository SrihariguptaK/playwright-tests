# Manual Test Cases

## Story: As Scheduler, I want the system to suggest alternative time slots when conflicts occur to facilitate quick rescheduling
**Story ID:** story-3

### Test Case: Validate generation of alternative time slot suggestions
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with Scheduler role
- Scheduling interface is accessible
- At least one resource with existing bookings is available in the system
- System clock is synchronized and accurate

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the scheduling interface and attempt to create a new schedule that conflicts with an existing booking | System detects the conflict and displays a conflict notification |
| 2 | Observe the time taken for the system to generate alternative time slot suggestions | Alternative time slot suggestions are generated and displayed within 2 seconds of conflict detection |
| 3 | Review the displayed alternative suggestions in the scheduling interface | Suggestions are displayed clearly with time slots, resource names, and availability status. All suggested slots show no conflicts |
| 4 | Select one of the suggested alternative time slots from the list | Selected alternative is highlighted and ready for confirmation |
| 5 | Click the save or apply button to confirm the schedule with the selected alternative | Schedule is updated with the selected alternative time slot, conflict alert is removed, and success confirmation message is displayed |

**Postconditions:**
- Schedule is saved with the alternative time slot
- No conflict alerts are present
- Resource is booked for the new time slot
- System logs the schedule change

---

### Test Case: Ensure suggestions do not conflict with existing schedules
- **ID:** tc-002
- **Type:** edge-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in with Scheduler role
- Multiple resources have existing bookings at various time slots
- Scheduling database contains current and accurate booking data
- System has access to resource availability calendars

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Create a schedule that conflicts with an existing booking to trigger alternative suggestions | System detects conflict and generates alternative time slot suggestions |
| 2 | Review each suggested alternative time slot and cross-reference with the resource availability calendar | All suggested time slots are verified to be free of conflicts with existing schedules |
| 3 | Verify that the resources required for each suggested slot are available and not double-booked | Resources are confirmed available for all suggested time slots with no overlapping bookings |
| 4 | Select one of the suggested alternative time slots | Selected alternative is highlighted for confirmation |
| 5 | Save the schedule with the selected alternative time slot | Schedule is saved successfully without any conflict errors or warnings |
| 6 | Verify the saved schedule in the resource availability calendar | New booking appears in the calendar with no overlapping conflicts |

**Postconditions:**
- Schedule is saved without conflicts
- Resource availability calendar reflects the new booking
- No double-booking exists for any resource
- System maintains data integrity

---

### Test Case: Test performance of suggestion generation under load
- **ID:** tc-003
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- Multiple Scheduler users are logged in simultaneously
- System has sufficient test data with multiple resources and bookings
- Performance monitoring tools are configured and active
- System logs are enabled and accessible
- Load testing environment is prepared

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Simulate 10-20 concurrent schedulers creating conflicting schedules simultaneously | System processes all conflict detections concurrently without errors |
| 2 | Measure the response time for alternative suggestion generation for each concurrent request | Alternative suggestions are generated within 2 seconds for all concurrent requests |
| 3 | Monitor system response times using performance monitoring tools during the load test | System response times remain within SLA requirements (under 2 seconds) throughout the test |
| 4 | Review system logs for any errors, exceptions, or timeout messages during the load test | No errors, exceptions, or significant delays are observed in the system logs |
| 5 | Verify that all generated suggestions across concurrent requests are accurate and conflict-free | All suggestions maintain data integrity and do not contain conflicts despite concurrent processing |

**Postconditions:**
- System performance meets SLA requirements under load
- No errors or data corruption occurred
- System logs document all transactions
- System returns to normal state after load test

---

## Story: As Scheduler, I want to view resource availability calendars to make informed scheduling decisions and avoid conflicts
**Story ID:** story-4

### Test Case: Validate display of resource availability calendar
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in with Scheduler role
- Resource availability data exists in the system
- Multiple resources with various booking statuses are available
- Scheduling interface is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the resource availability view from the main scheduling interface | Resource availability calendar is displayed with current month view showing all resources |
| 2 | Verify that the calendar displays both booked and free time slots with visual differentiation | Booked slots are clearly marked (e.g., different color or pattern) and distinguishable from free slots |
| 3 | Apply a filter to select a specific resource type from the available filter options | Calendar updates to display only resources matching the selected type |
| 4 | Apply a date range filter to view availability for a specific time period (e.g., next week) | Calendar updates to show availability only for the selected date range |
| 5 | Review the filtered calendar to verify booked and free time slots are accurately displayed | All time slots are clearly differentiated, accurate, and match the actual booking records in the system |
| 6 | Click on individual time slots to view detailed booking information | Detailed information about bookings (if booked) or availability confirmation (if free) is displayed |

**Postconditions:**
- Calendar remains in filtered view until user changes filters
- User can proceed to create schedules based on viewed availability
- No data is modified during the viewing process

---

### Test Case: Ensure real-time updates of availability calendar
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Scheduler role
- Resource availability calendar is open and displayed
- System supports real-time data synchronization
- At least one resource with available time slots exists

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Note the current availability status of a specific resource and time slot in the calendar | Current availability status is clearly visible (e.g., free slot shown in available state) |
| 2 | Create or modify a schedule that affects the noted resource's availability (book a previously free slot) | Schedule is created/modified successfully and saved to the system |
| 3 | Observe the availability calendar without manually refreshing the page | Calendar automatically updates within 2 seconds to reflect the new booking status |
| 4 | Manually refresh the calendar view using the refresh button or page reload | Latest availability data is displayed, confirming the booking change is persisted |
| 5 | Verify that no stale or outdated data is shown by comparing calendar with the scheduling database records | Calendar accurately reflects current bookings with no discrepancies or stale data |
| 6 | Delete or cancel the recently created booking | Calendar updates within 2 seconds to show the time slot as available again |

**Postconditions:**
- Calendar displays current real-time availability
- All changes are reflected accurately
- System maintains data synchronization
- No stale data remains in the interface

---

### Test Case: Verify access control for availability calendar
- **ID:** tc-006
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Multiple user accounts exist with different roles (Scheduler and non-Scheduler roles)
- Role-based access control is configured in the system
- System logging is enabled for security audit
- Authentication system is functioning properly

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in to the system using credentials for a user with Scheduler role | User is successfully authenticated and logged in |
| 2 | Navigate to the resource availability calendar view | Access is granted and the availability calendar is displayed without errors |
| 3 | Log out from the Scheduler account | User is successfully logged out and returned to login page |
| 4 | Log in using credentials for a user without Scheduler role (e.g., Viewer or Guest role) | User is successfully authenticated with limited permissions |
| 5 | Attempt to navigate to the resource availability calendar view | Access is denied with an appropriate error message (e.g., 'Access Denied: Insufficient Permissions') |
| 6 | Verify that the user is not able to bypass access control through direct URL access | Direct URL access is blocked and same access denied message is displayed |
| 7 | Review system security logs for both access attempts | Both successful access (Scheduler) and denied access (non-Scheduler) attempts are logged with timestamp, user ID, and action details for audit purposes |

**Postconditions:**
- Access control is enforced correctly
- Unauthorized users cannot view availability calendar
- All access attempts are logged for security audit
- System security integrity is maintained

---

## Story: As Scheduler, I want the system to log all detected conflicts and resolutions to support audit and reporting
**Story ID:** story-5

### Test Case: Validate logging of detected conflicts
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User has valid authentication credentials with scheduler role
- Conflict logs database is accessible and operational
- API endpoint GET /api/conflicts/logs is available
- At least two resources or time slots exist that can create a conflict
- System logging service is running and configured correctly

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Create a scheduling conflict by assigning the same resource to two overlapping time slots | System detects the conflict and displays a conflict notification to the user |
| 2 | Verify the conflict event is logged in the database with timestamp, conflict type, affected resources, and conflict details | Conflict event is logged with correct details including timestamp in ISO format, resource IDs, time slot information, and conflict severity |
| 3 | Send GET request to /api/conflicts/logs endpoint with valid authentication token | API returns HTTP 200 status code with logged conflict data in JSON format |
| 4 | Verify the returned conflict log contains the recently created conflict with accurate information including timestamp, resource details, and conflict description | Logged conflict is returned with all accurate information matching the created conflict scenario |
| 5 | Attempt to access conflict logs API endpoint using credentials without proper authorization (non-scheduler role) | API returns HTTP 403 Forbidden status code with appropriate error message |
| 6 | Attempt to access conflict logs API endpoint without authentication token | API returns HTTP 401 Unauthorized status code and access is denied |
| 7 | Verify logs are accessible only to users with scheduler or admin roles by checking role-based access control | Access control is enforced correctly - only authorized users can view logs, unauthorized access attempts are denied and logged |

**Postconditions:**
- Conflict event remains logged in the database
- All access attempts (authorized and unauthorized) are recorded in security audit logs
- System returns to normal operational state
- No data corruption or inconsistencies in conflict logs

---

### Test Case: Verify logging of conflict resolution actions
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- User is authenticated as scheduler with conflict resolution permissions
- At least one active scheduling conflict exists in the system
- Conflict logs database is accessible and operational
- Export functionality is configured and available
- API endpoint for querying logs is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the conflict management interface and locate an existing scheduling conflict | Conflict is displayed with all relevant details including affected resources, time slots, and conflict type |
| 2 | Click the 'Acknowledge' button for the displayed conflict | System displays acknowledgment confirmation and updates conflict status to 'Acknowledged' |
| 3 | Select a resolution action (e.g., reassign resource, modify time slot) and apply the resolution | Conflict is resolved successfully and system displays resolution confirmation message |
| 4 | Verify the resolution action is logged in the database with user ID, timestamp, action type, and resolution details | Resolution action is logged with complete information including scheduler username, timestamp in ISO format, action taken, and before/after state |
| 5 | Send GET request to /api/conflicts/logs endpoint with filter parameters for resolution entries | API returns HTTP 200 status with filtered results showing only resolution log entries |
| 6 | Verify the returned resolution log entries contain accurate data matching the actions performed | Resolution actions are present in logs with accurate user information, timestamps, and resolution details matching the performed actions |
| 7 | Navigate to the conflict logs export interface and select export format (CSV or JSON) | Export format options are displayed and selectable |
| 8 | Click 'Export' button to generate conflict logs export file | System generates export file and initiates download with appropriate filename including timestamp |
| 9 | Open the exported file and verify it contains complete conflict and resolution data | Exported file contains all conflict detection events and resolution actions with complete data including timestamps, user information, conflict details, and resolution outcomes |

**Postconditions:**
- Conflict resolution is permanently logged in the database
- Exported file is saved and contains accurate audit trail data
- Conflict status is updated to 'Resolved' in the system
- All log entries maintain data integrity and consistency

---

### Test Case: Ensure logging does not degrade system performance
- **ID:** tc-003
- **Type:** edge-case
- **Priority:** High
- **Estimated Time:** 20 mins

**Preconditions:**
- Performance monitoring tools are configured and operational
- System baseline performance metrics are documented (SLA thresholds defined)
- Test environment can simulate high volume conflict scenarios
- Resource monitoring tools are available to track CPU, memory, and I/O usage
- Logging service is running with standard configuration

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Record baseline system performance metrics including response time, CPU usage, memory usage, and database I/O | Baseline metrics are captured and documented for comparison |
| 2 | Execute automated script to simulate high volume of conflict detections (minimum 100 conflicts within 1 minute) | System successfully detects and processes all simulated conflicts without crashes or errors |
| 3 | Monitor system response time during high volume conflict detection | System response time remains within SLA thresholds (under 3 seconds for log retrieval as per success metrics) |
| 4 | Verify all conflict events are logged correctly during high volume scenario by querying the logs database | 100% of simulated conflicts are logged with accurate timestamps and details, no missing log entries |
| 5 | Monitor logging service resource usage including CPU utilization, memory consumption, and disk I/O during high volume operations | Logging service resource usage remains within acceptable limits (CPU < 70%, memory < 80% of allocated resources) |
| 6 | Check for system bottlenecks by analyzing performance metrics and identifying any resource contention | No bottlenecks detected in logging operations, database connections remain available, no queue buildup in logging service |
| 7 | Execute standard scheduling operations (create, update, delete schedules) during ongoing logging activity | All scheduling operations complete successfully without errors |
| 8 | Measure scheduling operation completion time and compare against baseline metrics | Scheduling operations complete within normal time ranges with no significant delays (variance < 10% from baseline) |
| 9 | Review system error logs and application logs for any errors or warnings related to logging operations | No errors or critical warnings related to logging service, all operations completed successfully |

**Postconditions:**
- System performance returns to baseline levels
- All simulated conflict logs are stored in database
- No memory leaks or resource exhaustion detected
- System remains stable and operational
- Performance test results are documented for future reference

---

