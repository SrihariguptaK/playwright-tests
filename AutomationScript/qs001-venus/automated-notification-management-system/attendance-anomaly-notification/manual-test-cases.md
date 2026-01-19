# Manual Test Cases

## Story: As Supervisor, I want to receive notifications for attendance anomalies to take timely corrective actions
**Story ID:** story-26

### Test Case: Validate notification sent on attendance anomaly detection
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Supervisor account is active and configured in the system
- Supervisor has valid email address and phone number registered
- Attendance tracking system is operational
- Notification service is running and configured
- Anomaly detection rules are properly configured
- Employee records exist in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Record attendance data with an anomaly (e.g., employee arrives 30 minutes late) | System detects the late arrival anomaly based on configured threshold rules and triggers notification generation |
| 2 | Check supervisor's email inbox for notification | Email notification received containing employee name, employee ID, anomaly type (late arrival), timestamp of occurrence, and duration of lateness |
| 3 | Check supervisor's mobile phone for SMS notification | SMS notification received with concise anomaly details including employee name, anomaly type, and timestamp |
| 4 | Open the application and navigate to notifications section | In-app notification is displayed with complete anomaly details including employee information, anomaly type, timestamp, and action buttons |
| 5 | Click on the in-app notification to view full details | Notification expands showing comprehensive information: employee name, ID, department, anomaly type, occurrence time, severity level, and acknowledgment options |
| 6 | Click the 'Acknowledge' button on the notification | Acknowledgment dialog appears with optional comment field |
| 7 | Enter comment 'Contacted employee, valid reason provided' and submit acknowledgment | Success message displayed confirming acknowledgment has been recorded |
| 8 | Navigate to notification logs/audit trail section | Acknowledgment entry is visible with supervisor name, timestamp, comment text, and notification ID |

**Postconditions:**
- Notification is marked as acknowledged in the system
- Acknowledgment and comment are permanently logged in audit trail
- Notification status updated to 'Acknowledged' in database
- Email, SMS, and in-app notifications remain accessible for historical reference

---

### Test Case: Verify notification retry mechanism on failure
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Notification service is operational
- Test environment allows simulation of delivery failures
- Retry mechanism is configured with maximum 3 attempts
- Notification logging is enabled
- Supervisor account exists with valid contact details
- Attendance anomaly detection is functional

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Configure test environment to simulate email delivery failure | Email service mock configured to reject delivery attempts |
| 2 | Record attendance data with anomaly to trigger notification | System detects anomaly and attempts to send notification |
| 3 | Monitor notification service logs for first delivery attempt | First delivery attempt logged with timestamp and failure status |
| 4 | Wait for first retry attempt (based on retry interval configuration) | System automatically initiates second delivery attempt |
| 5 | Check notification logs for second attempt | Second retry attempt logged with timestamp and failure status |
| 6 | Wait for second retry attempt | System automatically initiates third delivery attempt |
| 7 | Check notification logs for third attempt | Third retry attempt logged with timestamp and failure status |
| 8 | Verify system behavior after maximum retries exhausted | System logs final failure status and does not attempt further retries |
| 9 | Query notification logs database for the specific notification ID | All three retry attempts are recorded with individual timestamps, attempt numbers (1, 2, 3), and failure reasons |
| 10 | Restore email service to working state and trigger new anomaly | New notification is successfully delivered on first attempt |
| 11 | Check logs for successful delivery | Successful delivery logged with timestamp and delivery confirmation |

**Postconditions:**
- All retry attempts are permanently logged in system
- Failed notification is marked with final failure status
- System alert generated for notification delivery failure
- Subsequent notifications function normally after service restoration

---

### Test Case: Ensure notifications meet delivery SLA
- **ID:** tc-003
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- Notification service is fully operational
- System clock is synchronized with accurate time source
- Performance monitoring tools are configured
- Multiple employee records exist for testing
- Anomaly detection rules are active
- All notification channels (email, SMS, in-app) are functional
- Test supervisor account is configured

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Record attendance anomaly for Employee A (late arrival at 09:15 AM) | System detects anomaly and records detection timestamp |
| 2 | Record attendance anomaly for Employee B (absence without notice at 09:00 AM) | System detects second anomaly and records detection timestamp |
| 3 | Record attendance anomaly for Employee C (early departure at 04:30 PM) | System detects third anomaly and records detection timestamp |
| 4 | Record attendance anomaly for Employee D (extended break at 12:00 PM) | System detects fourth anomaly and records detection timestamp |
| 5 | Record attendance anomaly for Employee E (late arrival at 09:20 AM) | System detects fifth anomaly and records detection timestamp |
| 6 | Monitor notification delivery for Employee A anomaly | Notification delivered via all channels (email, SMS, in-app) within 10 minutes of anomaly detection |
| 7 | Monitor notification delivery for Employee B anomaly | Notification delivered via all channels within 10 minutes of anomaly detection |
| 8 | Monitor notification delivery for Employee C anomaly | Notification delivered via all channels within 10 minutes of anomaly detection |
| 9 | Monitor notification delivery for Employee D anomaly | Notification delivered via all channels within 10 minutes of anomaly detection |
| 10 | Monitor notification delivery for Employee E anomaly | Notification delivered via all channels within 10 minutes of anomaly detection |
| 11 | Calculate delivery time for each notification (delivery timestamp minus detection timestamp) | All five notifications show delivery time of 10 minutes or less |
| 12 | Query system performance logs for notification processing metrics | Performance logs show average delivery time well within 10-minute SLA |
| 13 | Review system error logs for any delays or failures during test period | No errors, delays beyond SLA, or delivery failures recorded in logs |
| 14 | Generate SLA compliance report from notification system | Report shows 100% compliance with 10-minute delivery SLA for all test notifications |

**Postconditions:**
- All five test notifications successfully delivered within SLA
- Delivery metrics recorded in performance monitoring system
- No outstanding errors or delays in system logs
- SLA compliance documented for audit purposes
- Test data available for performance analysis

---

## Story: As Supervisor, I want to acknowledge attendance anomaly notifications to confirm awareness and initiate follow-up actions
**Story ID:** story-29

### Test Case: Validate supervisor acknowledgment of attendance anomaly
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Supervisor is logged into the system with valid credentials
- At least one unacknowledged attendance anomaly notification exists
- Notification database is accessible
- User has supervisor role with acknowledgment permissions
- Application UI is fully loaded and responsive

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the notifications section in the application | Notifications page loads displaying list of attendance anomaly notifications |
| 2 | Locate the unacknowledged attendance anomaly notification in the list | Notification is displayed with employee name, anomaly type, timestamp, and 'Unacknowledged' status indicator |
| 3 | Click on the notification to view full details | Notification detail view opens showing complete information: employee details, anomaly type, occurrence time, severity, and acknowledgment section |
| 4 | Locate and click the 'Acknowledge' button | Acknowledgment dialog or form appears with optional comment text field |
| 5 | Enter optional comment: 'Spoke with employee - medical emergency, documentation to follow' | Comment text is accepted and displayed in the comment field |
| 6 | Click 'Submit' or 'Confirm' button to complete acknowledgment | Success confirmation message displayed: 'Notification acknowledged successfully' or similar |
| 7 | Verify notification status updated in the notifications list | Notification status changed from 'Unacknowledged' to 'Acknowledged' with supervisor name and timestamp visible |
| 8 | Navigate to system audit logs or acknowledgment history section | Audit log section loads showing acknowledgment records |
| 9 | Search for the recently acknowledged notification in audit logs | Acknowledgment entry found containing: notification ID, supervisor username, acknowledgment timestamp, and comment text |
| 10 | Verify timestamp accuracy in acknowledgment record | Timestamp matches the time of acknowledgment submission (within 1-2 seconds) |
| 11 | Verify comment is correctly stored in the log | Comment text 'Spoke with employee - medical emergency, documentation to follow' is displayed exactly as entered |

**Postconditions:**
- Notification status permanently changed to 'Acknowledged'
- Acknowledgment record stored in database with all details
- Audit trail entry created with timestamp and user information
- Comment is permanently associated with the notification
- Notification removed from unacknowledged queue

---

### Test Case: Ensure acknowledgment processing performance
- **ID:** tc-005
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Supervisor is logged into the system
- Unacknowledged attendance anomaly notification is available
- System performance monitoring is enabled
- Network connection is stable
- Database is operational and responsive
- Timer or stopwatch tool is available for measurement

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open the attendance anomaly notification requiring acknowledgment | Notification details displayed with acknowledgment option |
| 2 | Click the 'Acknowledge' button and start timer | Acknowledgment form appears immediately |
| 3 | Enter optional comment: 'Performance test acknowledgment' | Comment text accepted in field |
| 4 | Click 'Submit' button and measure response time until confirmation appears | Success confirmation message displayed within 2 seconds of clicking submit |
| 5 | Record the exact processing time from submission to confirmation | Processing time is 2 seconds or less |
| 6 | Navigate to system audit logs immediately after acknowledgment | Audit logs section loads successfully |
| 7 | Search for the acknowledgment entry just created | Acknowledgment entry is present in logs with correct notification ID |
| 8 | Verify all acknowledgment details in the log entry | Entry contains: supervisor username, accurate timestamp, notification ID, and comment 'Performance test acknowledgment' |
| 9 | Check system performance metrics or logs for processing time | System logs confirm acknowledgment processing completed within 2-second SLA |

**Postconditions:**
- Acknowledgment processed within performance SLA
- System logs contain performance metrics for the transaction
- Acknowledgment data correctly stored in database
- No performance degradation observed
- Response time documented for compliance verification

---

### Test Case: Verify system handles missing acknowledgment gracefully
- **ID:** tc-006
- **Type:** error-case
- **Priority:** Medium
- **Estimated Time:** 7 mins

**Preconditions:**
- Supervisor is logged into the system
- Attendance anomaly notification is available for acknowledgment
- Form validation rules are configured and active
- Error messaging system is functional
- Required field validations are enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open an unacknowledged attendance anomaly notification | Notification details displayed with acknowledgment form |
| 2 | Click the 'Acknowledge' button to open acknowledgment form | Acknowledgment form appears with required and optional fields clearly marked |
| 3 | Leave all required fields empty (if any exist beyond the acknowledge action itself) | Form displays with empty required fields |
| 4 | Attempt to submit the acknowledgment without completing required fields | System displays validation error messages indicating which required fields are missing |
| 5 | Verify error messages are clear and user-friendly | Error messages clearly state: 'Required field must be completed' or similar descriptive text for each missing field |
| 6 | Verify form submission is blocked | Acknowledgment is not submitted and notification status remains 'Unacknowledged' |
| 7 | Check that no partial data was saved to the database | No acknowledgment record created in audit logs or database |
| 8 | Fill in all required fields with valid data | Required fields populated with valid information, validation errors cleared |
| 9 | Add optional comment: 'Resubmitting after validation correction' | Comment accepted in optional field |
| 10 | Click 'Submit' button to resubmit acknowledgment | Form submits successfully without validation errors |
| 11 | Verify success confirmation message is displayed | Success message appears: 'Notification acknowledged successfully' |
| 12 | Check audit logs for acknowledgment entry | Acknowledgment logged with all required details: supervisor name, timestamp, notification ID, and comment |
| 13 | Verify notification status updated to 'Acknowledged' | Notification status changed to 'Acknowledged' in the system |

**Postconditions:**
- Invalid submission attempt blocked and not recorded
- Valid acknowledgment successfully submitted and logged
- No data corruption or partial records in database
- Notification properly acknowledged after correction
- User experience demonstrates clear validation feedback

---

## Story: As Supervisor, I want to customize notification thresholds for attendance anomalies to reduce false alerts
**Story ID:** story-33

### Test Case: Validate updating attendance anomaly thresholds
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Supervisor role credentials
- Supervisor has permission to access attendance anomaly settings
- Configuration database is accessible and operational
- Current threshold values are set to system defaults
- At least one employee record exists in the system for testing anomaly detection

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the attendance anomaly notification settings page from the main dashboard or settings menu | Threshold configuration UI is displayed with all current threshold values visible (late arrival threshold, absence threshold, early departure threshold, etc.) |
| 2 | Review the currently displayed threshold values on the configuration screen | All threshold fields show current values with appropriate labels and units (e.g., minutes for late arrival, number of occurrences for absences) |
| 3 | Enter valid threshold values: Late arrival threshold = 15 minutes, Absence threshold = 2 occurrences, Early departure threshold = 10 minutes | New values are accepted in the input fields without validation errors |
| 4 | Click the 'Save' or 'Apply Changes' button | Success message is displayed confirming changes have been saved and applied immediately. UI shows updated threshold values |
| 5 | Create a test scenario by simulating or recording an attendance event that triggers the newly set late arrival threshold (e.g., employee arrives 16 minutes late) | Anomaly detection system processes the event using the new 15-minute threshold |
| 6 | Check the notifications dashboard or notification center for alerts generated | Notification is generated for the late arrival as it exceeds the new 15-minute threshold, confirming thresholds are applied immediately |
| 7 | Create another test scenario with an attendance event below the threshold (e.g., employee arrives 10 minutes late) | No notification is generated as the event is within the acceptable threshold range |

**Postconditions:**
- New threshold values are saved in the configuration database
- Anomaly detection system is using the updated thresholds for all subsequent checks
- Threshold change is logged in the audit log with supervisor username and timestamp
- System continues to monitor attendance using new thresholds

---

### Test Case: Verify validation of invalid threshold inputs
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in with Supervisor role credentials
- Supervisor has permission to access attendance anomaly settings
- Threshold configuration UI is accessible
- Current threshold values are set and displayed

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the attendance anomaly notification settings page | Threshold configuration UI is displayed with current threshold values |
| 2 | Enter a negative number in the late arrival threshold field (e.g., -5) | Field accepts the input temporarily for validation testing |
| 3 | Click the 'Save' or 'Apply Changes' button | System displays validation error message indicating that negative values are not allowed. Error message appears near the invalid field or in an error summary section. Changes are not saved |
| 4 | Enter a non-numeric value in the absence threshold field (e.g., 'abc' or special characters) | System displays validation error message indicating that only numeric values are accepted. Changes are not saved |
| 5 | Enter an extremely large number that exceeds reasonable bounds (e.g., 99999 minutes for late arrival) | System displays validation error message indicating the value exceeds maximum allowed threshold. Changes are not saved |
| 6 | Leave a required threshold field empty and attempt to save | System displays validation error message indicating that the field is required. Changes are not saved |
| 7 | Correct all invalid inputs with valid threshold values: Late arrival = 20 minutes, Absence = 3 occurrences | Valid values are accepted in the input fields without any validation errors displayed |
| 8 | Click the 'Save' or 'Apply Changes' button | Success message is displayed. Changes are accepted, saved, and applied to the anomaly detection system |

**Postconditions:**
- Invalid threshold values are rejected and not saved to the database
- Valid corrected threshold values are saved in the configuration database
- System continues to use previous valid thresholds until new valid values are saved
- Validation errors are cleared after successful save

---

### Test Case: Ensure reset to default thresholds works
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in with Supervisor role credentials
- Supervisor has permission to access attendance anomaly settings
- Current threshold values have been modified from system defaults
- System default threshold values are defined and accessible
- Audit logging is enabled and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the attendance anomaly notification settings page | Threshold configuration UI is displayed showing currently modified threshold values (non-default values) |
| 2 | Note the current custom threshold values displayed on the screen | Custom values are visible and different from system defaults (e.g., Late arrival = 15 minutes, Absence = 2 occurrences) |
| 3 | Locate and click the 'Reset to Default' or 'Restore Defaults' button | System displays a confirmation dialog asking to confirm the reset action (e.g., 'Are you sure you want to reset all thresholds to default values?') |
| 4 | Click 'Confirm' or 'Yes' in the confirmation dialog | All threshold input fields are immediately populated with default system values (e.g., Late arrival = 30 minutes, Absence = 5 occurrences, Early departure = 20 minutes) |
| 5 | Verify that all threshold fields now display the default values | All fields show default values correctly. Visual indication may show that values have been reset but not yet saved |
| 6 | Click the 'Save' or 'Apply Changes' button to persist the default values | Success message is displayed confirming that default thresholds have been applied. UI confirms the save operation |
| 7 | Navigate to the audit log or change history section | Audit log shows an entry for the threshold reset action with supervisor username, timestamp, action type (reset to defaults), and the default values that were applied |
| 8 | Trigger a test attendance anomaly scenario using the default threshold values | Anomaly detection system uses the default thresholds for evaluation and generates notifications accordingly |

**Postconditions:**
- All threshold values are reset to system defaults in the configuration database
- Anomaly detection system is using default thresholds for all subsequent checks
- Reset action is logged in the audit log with complete details including user, timestamp, and action type
- Previous custom threshold values are overwritten with defaults

---

