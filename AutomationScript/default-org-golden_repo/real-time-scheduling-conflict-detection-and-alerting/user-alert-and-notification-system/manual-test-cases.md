# Manual Test Cases

## Story: As Scheduler, I want to receive real-time alerts for scheduling conflicts to take immediate corrective action
**Story ID:** story-13

### Test Case: Verify real-time alert delivery within 5 seconds
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged into the system as a Scheduler
- User has valid alert preferences configured
- Conflict detection service is running and operational
- At least one notification channel is enabled for the user
- System time is synchronized and accurate

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Trigger a scheduling conflict by creating overlapping resource assignments or double-booking a time slot | System detects the conflict and conflict detection service identifies the issue |
| 2 | Start a timer and observe alert delivery to user via configured channels (in-app, email, or SMS) | Alert is received within 5 seconds of conflict detection via the user's configured notification channels |
| 3 | Navigate to the alert log section and check for the timestamp and delivery status of the triggered alert | Alert is logged with correct timestamp, conflict details, delivery status marked as 'Delivered', and associated user information |

**Postconditions:**
- Alert is successfully delivered and logged in the system
- Alert log contains complete audit trail with timestamp
- Conflict remains in the system awaiting resolution
- User notification channels show the alert message

---

### Test Case: Test user alert preference configuration
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged into the system as a Scheduler
- User has access to alert preference settings
- Multiple notification channels are available (in-app, email, SMS)
- User profile exists in the system
- Email service is configured and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to user alert preferences settings page and update alert preferences to receive email only by unchecking other channels | Preferences are saved successfully with confirmation message displayed, and only email channel is selected |
| 2 | Trigger a scheduling conflict by creating a resource conflict or time slot overlap | User receives alert via email only, with no notifications sent to in-app or SMS channels |

**Postconditions:**
- User alert preferences are persisted in the database
- Only email channel is active for future alerts
- Alert is delivered exclusively via email
- No alerts sent to disabled channels (in-app, SMS)

---

### Test Case: Validate alert escalation after unresolved conflict
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged into the system as a Scheduler
- Escalation settings are configured with specific time period
- Designated escalation users are defined in the system
- Conflict detection and alert services are operational
- Initial alert delivery channels are configured

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Trigger a scheduling conflict and verify that the initial alert is sent to the primary scheduler | Initial alert is delivered successfully to the scheduler via configured channels with conflict details |
| 2 | Wait for the configured escalation period to elapse without acknowledging or resolving the conflict | System automatically sends escalation alert to designated users (supervisors/managers) after the configured time period expires, with escalation flag and original conflict details included |

**Postconditions:**
- Escalation alert is logged in the system with escalation timestamp
- Designated escalation users receive the alert
- Original conflict remains unresolved and flagged as escalated
- Alert audit trail shows both initial and escalation alerts

---

## Story: As Scheduler, I want to configure my alert preferences to receive notifications via preferred channels
**Story ID:** story-14

### Test Case: Save and apply alert preferences
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged into the system as a Scheduler
- User has access to alert preference settings page
- Email and SMS notification services are configured and operational
- User has valid email address and phone number in profile
- Alert preference API endpoints are accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the alert preference settings page from user profile or settings menu | Alert preference settings UI is displayed showing all available notification channels (in-app, email, SMS) and frequency options |
| 2 | Select email and SMS as alert channels by checking the respective checkboxes and set frequency to 'immediate' from the dropdown menu, then click Save button | Preferences are saved successfully with a confirmation message displayed, and the selected channels (email and SMS) and frequency (immediate) are persisted |
| 3 | Trigger a scheduling conflict by creating overlapping schedules or resource conflicts | Alerts are received via both email and SMS channels as configured, with immediate delivery and no alerts sent to in-app channel |

**Postconditions:**
- User preferences are saved in the user profile database
- Email and SMS channels are active for the user
- In-app notifications are disabled
- Future alerts will follow the configured preferences
- Preference changes are effective immediately

---

### Test Case: Validate input for alert preferences
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged into the system as a Scheduler
- User has access to alert preference settings page
- Input validation rules are configured in the system
- Alert preference form is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Enter invalid channel values (e.g., unsupported channel type) or invalid frequency values (e.g., negative numbers, non-numeric values) in the alert preference form | Validation errors are displayed next to the invalid fields with clear error messages, and the Save button is disabled or save action is prevented |
| 2 | Correct the inputs by selecting valid channels from the available options and choosing a valid frequency value, then click Save button | Preferences are saved successfully with confirmation message, validation errors are cleared, and the valid preferences are persisted in the system |

**Postconditions:**
- Invalid preferences are not saved to the database
- Valid preferences are successfully persisted
- User receives confirmation of successful save
- System maintains data integrity with validated inputs only

---

## Story: As Scheduler, I want to receive escalation alerts for unresolved scheduling conflicts to ensure timely resolution
**Story ID:** story-16

### Test Case: Trigger escalation alert after unresolved conflict threshold
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 45 mins

**Preconditions:**
- User is logged in with Scheduler role
- Escalation time threshold is configured in system settings (e.g., 30 minutes)
- Designated escalation recipients are configured in the system
- Alert notification system is operational
- At least one scheduling conflict exists in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Create a scheduling conflict in the system by overlapping two resource bookings | Scheduling conflict is detected and created in the system |
| 2 | Verify that initial alert is sent to the primary scheduler | Initial alert is delivered successfully to the primary scheduler with conflict details, timestamp, and alert ID |
| 3 | Monitor the conflict status and wait for the configured escalation time threshold to pass without resolving the conflict | System tracks the elapsed time since initial alert was sent and conflict remains in unresolved status |
| 4 | Verify that escalation alert is automatically triggered after the threshold time has elapsed | Escalation alert is sent to all designated escalation recipients with conflict details, original alert timestamp, and escalation reason |
| 5 | Check that escalation recipients receive the alert through configured notification channels | All designated escalation recipients receive the escalation alert with complete conflict information and escalation context |
| 6 | Have each escalation recipient acknowledge the escalation alert through the system interface | System accepts acknowledgment from each recipient and displays confirmation message |
| 7 | Verify that all acknowledgments are logged in the system with recipient details and timestamps | Acknowledgment log entries are created with user ID, timestamp, alert ID, and acknowledgment status for each recipient |

**Postconditions:**
- Escalation alert is marked as acknowledged in the system
- All escalation events are logged in audit trail
- Conflict remains in system until manually resolved
- Escalation notification history is available for review

---

### Test Case: Validate secure delivery of escalation alerts
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 30 mins

**Preconditions:**
- User authentication system is operational
- SSL/TLS encryption is enabled for alert delivery
- Escalation alert system is configured and active
- Test user accounts with and without proper authorization exist
- At least one escalation alert is ready to be sent

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Trigger an escalation alert from an unresolved conflict | Escalation alert is generated and queued for delivery |
| 2 | Monitor the alert delivery process and verify encryption protocol is used | Alert is delivered using secure HTTPS/TLS protocol with valid SSL certificate |
| 3 | Verify that recipient authentication is required before alert content is displayed | System prompts for authentication credentials before showing escalation alert details |
| 4 | Log in as authorized escalation recipient and access the escalation alert | Alert is delivered securely and displayed with all details intact, authentication token is validated |
| 5 | Log out and attempt to access the escalation alert URL directly without authentication | Access is denied with 401 Unauthorized error, user is redirected to login page |
| 6 | Log in as a user without escalation recipient privileges and attempt to access escalation alerts | Access is denied with 403 Forbidden error, appropriate error message is displayed indicating insufficient permissions |
| 7 | Attempt to intercept or access escalation alert data through API without proper authentication token | API request is rejected with authentication error, no alert data is exposed |
| 8 | Verify that all unauthorized access attempts are logged in security audit trail | Security log entries are created with timestamp, attempted user/IP, resource accessed, and denial reason |

**Postconditions:**
- Escalation alert remains secure and accessible only to authorized recipients
- All unauthorized access attempts are logged
- System security integrity is maintained
- No sensitive data is exposed to unauthorized users

---

## Story: As Scheduler, I want the system to log all alerts and user acknowledgments for audit and compliance
**Story ID:** story-21

### Test Case: Verify alert and acknowledgment logging
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 25 mins

**Preconditions:**
- User is logged in with Scheduler role
- Audit logging system is enabled and operational
- Database has sufficient storage for log entries
- At least one user with alert recipient privileges exists
- User has authorization to access audit logs
- System time synchronization is accurate

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Create a scheduling conflict that triggers an alert to be sent to a specific user | Alert is generated and queued for delivery to the designated recipient |
| 2 | Send the alert to the target user through the alert notification system | Alert is successfully delivered to the user via configured notification channel |
| 3 | Query the audit logs to verify the alert event was logged | Alert log entry exists with complete details including alert ID, timestamp, recipient user ID, alert type, conflict details, and delivery status |
| 4 | Verify that the logged timestamp matches the actual alert send time within acceptable tolerance | Timestamp in log is accurate within 1 second of actual send time |
| 5 | Log in as the alert recipient user and view the received alert | Alert is displayed in user's notification inbox with all details |
| 6 | Have the user acknowledge the alert by clicking the acknowledge button | System processes acknowledgment and displays confirmation message to user |
| 7 | Query the audit logs to verify the acknowledgment event was logged | Acknowledgment log entry exists with user ID, timestamp, alert ID, and acknowledgment action |
| 8 | Verify that the acknowledgment timestamp is accurate and matches the actual acknowledgment time | Acknowledgment timestamp in log is accurate within 1 second of actual acknowledgment time |
| 9 | Log in as an authorized user with audit access privileges | User successfully authenticates and gains access to audit log interface |
| 10 | Access the audit logs through the system interface using GET /alerts/logs endpoint | Audit log interface loads successfully |
| 11 | Query for the specific alert and acknowledgment log entries created in previous steps | Both alert and acknowledgment log entries are displayed accurately with all details intact |
| 12 | Measure the response time for the audit log query | Audit logs are retrieved and displayed within 2 seconds |
| 13 | Verify that log entries contain all required fields: event type, timestamp, user ID, alert ID, action details, and status | All required fields are present and populated with correct data for both alert and acknowledgment entries |

**Postconditions:**
- Alert event is permanently logged in audit database
- Acknowledgment event is permanently logged in audit database
- Audit trail is complete and accurate for compliance review
- Log entries are timestamped and attributed to correct users
- Audit logs remain accessible for future queries

---

### Test Case: Validate audit log security
- **ID:** tc-004
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 20 mins

**Preconditions:**
- Audit logging system is operational
- Role-based access control is configured and enforced
- Test user accounts exist with different permission levels
- At least one user without audit log access authorization exists
- Audit logs contain test data entries
- Encryption is enabled for audit log storage

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in as a user without audit log access privileges (e.g., basic scheduler role without audit permissions) | User successfully authenticates but has limited role permissions |
| 2 | Attempt to navigate to the audit logs interface through the application menu | Audit logs menu option is not visible or is disabled for this user role |
| 3 | Attempt to directly access the audit logs URL by typing the path in browser | Access is denied with 403 Forbidden error, user is shown an error message indicating insufficient permissions |
| 4 | Attempt to access audit logs via API endpoint GET /alerts/logs without proper authorization token | API returns 401 Unauthorized error with appropriate error message, no log data is returned |
| 5 | Attempt to access audit logs via API with valid authentication but insufficient role permissions | API returns 403 Forbidden error indicating user lacks required permissions, no log data is exposed |
| 6 | Verify that the unauthorized access attempt is logged in the security audit trail | Security log entry is created with timestamp, user ID, attempted resource, and access denial reason |
| 7 | Log in as an authorized administrator and verify audit log data is encrypted at rest | Database inspection shows audit log data is stored in encrypted format |
| 8 | Attempt to modify an existing audit log entry through the database or API | Modification attempt is blocked, audit logs are immutable and tamper-proof |
| 9 | Verify that audit log integrity checks are in place (checksums or digital signatures) | Each log entry has integrity verification mechanism that would detect any tampering |

**Postconditions:**
- Audit logs remain secure and inaccessible to unauthorized users
- All unauthorized access attempts are logged
- Audit log data integrity is maintained
- No sensitive audit information is exposed
- System security posture is verified and compliant

---

