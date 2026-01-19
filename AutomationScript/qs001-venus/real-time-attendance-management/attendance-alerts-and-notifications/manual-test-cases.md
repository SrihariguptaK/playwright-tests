# Manual Test Cases

## Story: As Manager, I want to receive alerts for excessive absences to achieve proactive workforce management
**Story ID:** story-17

### Test Case: Validate alert generation on absence threshold breach
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- Manager user is logged in with valid credentials
- Manager has appropriate role-based permissions to configure alerts
- Attendance database is accessible and populated with employee data
- Email and in-app notification services are operational
- At least one department exists in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the alert configuration page from the main dashboard | Alert configuration page loads successfully with all configuration options visible |
| 2 | Select a department from the department dropdown list | Department is selected and displayed in the configuration form |
| 3 | Enter a valid absence threshold value (e.g., 3 absences in 30 days) in the threshold input field | Threshold value is accepted and displayed in the input field without validation errors |
| 4 | Click the 'Save' or 'Submit' button to save the threshold configuration | Success message is displayed confirming 'Threshold saved successfully' and configuration is persisted in the system |
| 5 | Simulate employee absences exceeding the configured threshold by updating attendance records in the system | Attendance records are updated successfully in the database |
| 6 | Wait and monitor the system for alert generation (maximum 5 minutes) | System automatically generates an alert within 5 minutes of threshold breach being detected |
| 7 | Check the manager's email inbox for alert notification | Email notification is received containing alert details including employee information and absence metrics |
| 8 | Check the in-app notification center or dashboard for alert notification | In-app notification is displayed showing the same alert with employee information and absence metrics |
| 9 | Verify that both email and in-app notifications contain consistent information | Both notification channels display identical alert information including employee name, department, absence count, and threshold details |

**Postconditions:**
- Alert threshold configuration is saved in the system
- Alert is generated and logged in the system
- Manager has received notifications via both email and in-app channels
- Attendance records reflect the simulated absences
- Alert is available in alert history for future review

---

### Test Case: Verify alert logging and audit trail
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Manager user is logged in with valid credentials
- Alert configuration is already set up for at least one department
- System has the capability to generate alerts
- Alert history UI is accessible to the manager
- Database logging functionality is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Simulate multiple employee absences exceeding thresholds for different employees or departments | Multiple attendance threshold breaches are created in the system |
| 2 | Wait for the system to generate alerts for each threshold breach (within 5 minutes each) | System generates multiple alerts corresponding to each threshold breach |
| 3 | Verify that all generated alerts are logged in the database with timestamps | All alerts are logged with accurate timestamps, employee IDs, department information, and alert type |
| 4 | Navigate to the alert history UI from the main dashboard or alerts section | Alert history page loads successfully displaying a list or table of alerts |
| 5 | Review the displayed alerts in the alert history UI | All generated alerts are displayed with complete details including employee name, department, absence count, threshold value, timestamp, and alert status |
| 6 | Verify the chronological order of alerts based on timestamps | Alerts are displayed in chronological order (newest first or oldest first based on default sorting) |
| 7 | Click on individual alert entries to view detailed information | Detailed alert view opens showing comprehensive information including full employee details, absence history, and alert generation timestamp |
| 8 | Verify that the audit trail includes all necessary information for compliance and review | Audit trail contains complete information including who was alerted, when the alert was generated, what triggered it, and current status |

**Postconditions:**
- Multiple alerts are logged in the system database
- Alert history is accessible and displays all generated alerts
- Audit trail is complete and available for compliance review
- No alerts are missing from the history log

---

### Test Case: Test alert configuration validation
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Manager user is logged in with valid credentials
- Manager has permissions to access alert configuration
- Alert configuration page is accessible
- Validation rules are implemented in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the alert configuration page | Alert configuration page loads successfully with input fields visible |
| 2 | Enter a negative number (e.g., -5) in the absence threshold field | System displays validation error message such as 'Threshold value must be a positive number' and prevents saving |
| 3 | Clear the threshold field and enter zero (0) as the threshold value | System displays validation error message such as 'Threshold value must be greater than zero' and prevents saving |
| 4 | Enter an excessively large number (e.g., 99999) in the threshold field | System displays validation error message such as 'Threshold value exceeds maximum allowed limit' and prevents saving |
| 5 | Enter non-numeric characters (e.g., 'abc' or special characters) in the threshold field | System displays validation error message such as 'Please enter a valid numeric value' and prevents saving |
| 6 | Leave the threshold field empty and attempt to save the configuration | System displays validation error message such as 'Threshold value is required' and prevents saving |
| 7 | Enter a decimal number (e.g., 3.5) in the threshold field if only integers are allowed | System either rounds to nearest integer or displays validation error message 'Please enter a whole number' based on business rules |
| 8 | Attempt to save configuration without selecting a department | System displays validation error message such as 'Please select a department' and prevents saving |
| 9 | Verify that all validation messages are clear, user-friendly, and displayed near the relevant input fields | All validation messages are displayed in red or highlighted format near the corresponding input fields with clear instructions |

**Postconditions:**
- No invalid threshold configurations are saved in the system
- System maintains data integrity by rejecting invalid inputs
- User is informed of validation errors with clear messages
- Alert configuration page remains in editable state for correction

---

## Story: As Manager, I want to receive notifications for late arrivals to achieve timely corrective actions
**Story ID:** story-18

### Test Case: Validate late arrival detection and notification
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- Manager user is logged in with valid credentials
- Manager has appropriate permissions to configure notifications
- Employee schedules are defined in the system with specific start times
- Attendance monitoring system is operational
- Email and in-app notification services are functional
- At least one employee with a defined schedule exists in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the notification preferences or settings page from the main dashboard | Notification preferences page loads successfully with configuration options displayed |
| 2 | Enable late arrival notifications by toggling the notification switch or checkbox | Late arrival notification option is enabled and visually indicated as active |
| 3 | Configure notification channels by selecting both email and in-app notification options | Both email and in-app notification channels are selected and highlighted |
| 4 | Set the late arrival threshold (e.g., 15 minutes after scheduled start time) if configurable | Late arrival threshold is set and displayed in the configuration |
| 5 | Click 'Save' or 'Apply' button to save the notification preferences | Success message is displayed confirming 'Preferences saved successfully' and settings are persisted |
| 6 | Simulate an employee late arrival by recording attendance after the scheduled start time plus threshold (e.g., employee scheduled for 9:00 AM arrives at 9:20 AM) | Attendance record is created in the system with timestamp indicating late arrival |
| 7 | Wait and monitor the system for late arrival detection and notification generation (maximum 5 minutes) | System detects the late arrival within 5 minutes and generates a notification |
| 8 | Check the manager's email inbox for late arrival notification | Email notification is received containing employee name, scheduled time, actual arrival time, and lateness duration |
| 9 | Check the in-app notification center or dashboard for late arrival notification | In-app notification is displayed showing the same late arrival information with employee details |
| 10 | Verify that both notifications contain consistent and accurate information | Both email and in-app notifications display identical information including employee name, department, scheduled time, actual arrival time, and lateness duration |
| 11 | Verify the timestamp of notification delivery | Notifications are delivered within 5 minutes of late arrival detection as per performance requirements |

**Postconditions:**
- Late arrival notification preferences are saved in the system
- Late arrival is detected and logged in the system
- Manager has received notifications via both email and in-app channels
- Notification is logged in notification history
- Attendance record reflects the late arrival with accurate timestamp

---

### Test Case: Verify notification history accessibility
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 10 mins

**Preconditions:**
- Manager user is logged in with valid credentials
- Late arrival notification preferences are already configured
- System is capable of generating late arrival notifications
- Notification history UI is accessible
- Database logging for notifications is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Simulate multiple employee late arrivals by recording attendance for different employees after their scheduled start times | Multiple late arrival attendance records are created in the system |
| 2 | Wait for the system to detect late arrivals and generate notifications for each instance | System generates multiple late arrival notifications within 5 minutes of each detection |
| 3 | Verify that all notifications are logged in the database with complete information | All notifications are logged with timestamps, employee IDs, scheduled times, actual arrival times, and notification status |
| 4 | Navigate to the notification history page from the main dashboard or notifications section | Notification history page loads successfully displaying a list or table of notifications |
| 5 | Review the displayed notifications in the notification history UI | All generated late arrival notifications are displayed with details including employee name, date, scheduled time, actual arrival time, lateness duration, and timestamp |
| 6 | Verify that notifications are displayed in chronological order | Notifications are sorted by timestamp in descending order (most recent first) or ascending order based on default settings |
| 7 | Use filter or search functionality to find specific notifications by employee name or date | Filter/search functionality works correctly and displays relevant notifications matching the search criteria |
| 8 | Click on individual notification entries to view detailed information | Detailed notification view opens showing comprehensive information including full employee details, schedule information, and notification delivery status |
| 9 | Verify that notification history includes delivery status for both email and in-app channels | Each notification entry shows delivery status indicating whether it was successfully sent via email and in-app channels |

**Postconditions:**
- Multiple late arrival notifications are logged in the system
- Notification history is accessible and displays all notifications
- Notification data is complete and accurate for review purposes
- Manager can access historical notification data for analysis

---

### Test Case: Test notification preference validation
- **ID:** tc-006
- **Type:** error-case
- **Priority:** Medium
- **Estimated Time:** 12 mins

**Preconditions:**
- Manager user is logged in with valid credentials
- Manager has permissions to configure notification preferences
- Notification preferences page is accessible
- Validation rules are implemented for notification settings

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the notification preferences configuration page | Notification preferences page loads successfully with all configuration fields visible |
| 2 | Attempt to save notification preferences without selecting any notification channel (neither email nor in-app) | System displays validation error message such as 'Please select at least one notification channel' and prevents saving |
| 3 | If late arrival threshold is configurable, enter a negative value (e.g., -10 minutes) in the threshold field | System displays validation error message such as 'Threshold must be a positive value' and prevents saving |
| 4 | Enter an excessively large threshold value (e.g., 500 minutes) that exceeds business logic limits | System displays validation error message such as 'Threshold value exceeds maximum allowed limit' and prevents saving |
| 5 | Enter non-numeric characters (e.g., 'abc' or special characters) in the threshold field if applicable | System displays validation error message such as 'Please enter a valid numeric value' and prevents saving |
| 6 | If email notification is selected, enter an invalid email address format in the email field | System displays validation error message such as 'Please enter a valid email address' and prevents saving |
| 7 | Leave required fields empty and attempt to save the configuration | System displays validation error messages for all required fields such as 'This field is required' and prevents saving |
| 8 | Enter a threshold value of zero (0) if not allowed by business rules | System displays validation error message such as 'Threshold must be greater than zero' and prevents saving |
| 9 | Verify that all validation error messages are clear, specific, and displayed near the relevant input fields | All validation messages are displayed in red or highlighted format near the corresponding fields with clear, actionable instructions |
| 10 | Verify that the form does not submit when validation errors are present | Save/Submit button either remains disabled or form submission is prevented until all validation errors are resolved |

**Postconditions:**
- No invalid notification preferences are saved in the system
- System maintains data integrity by rejecting invalid configurations
- User is clearly informed of all validation errors
- Notification preferences page remains in editable state for corrections

---

