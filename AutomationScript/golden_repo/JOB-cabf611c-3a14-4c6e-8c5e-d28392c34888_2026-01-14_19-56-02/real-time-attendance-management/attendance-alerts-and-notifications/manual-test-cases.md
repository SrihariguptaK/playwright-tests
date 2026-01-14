# Manual Test Cases

## Story: As Manager, I want to receive alerts for late arrivals to achieve timely workforce management
**Story ID:** story-15

### Test Case: Validate detection and alerting of late arrivals
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Manager user is logged into the system with appropriate permissions
- Alert configuration module is accessible
- Email and SMS notification services are active and configured
- Test employee account exists in the system
- System time is synchronized and accurate

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to Alert Configuration section and configure late arrival threshold to 9:00 AM | Configuration is saved successfully with confirmation message displayed. Threshold value of 9:00 AM is visible in the configuration settings |
| 2 | Simulate employee check-in at 9:15 AM (15 minutes after threshold) | System detects the late arrival, calculates the delay as 15 minutes, and triggers alert within 1 minute of check-in |
| 3 | Verify alert received via email by checking manager's email inbox | Email alert is received containing employee name, check-in time (9:15 AM), scheduled time (9:00 AM), and delay duration (15 minutes) |
| 4 | Verify alert received via SMS by checking manager's mobile device | SMS alert is received containing employee name, check-in time, and delay information |
| 5 | Verify alert displayed in dashboard by navigating to Alerts/Notifications section | Dashboard displays the late arrival alert with complete employee details, check-in time (9:15 AM), threshold time (9:00 AM), and delay duration (15 minutes) |

**Postconditions:**
- Alert is logged in the system with timestamp
- Alert remains visible in dashboard until acknowledged
- Alert history is updated with the new entry
- All notification channels show consistent information

---

### Test Case: Verify alert configuration UI and validation
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Manager user is logged into the system with configuration permissions
- Alert configuration page is accessible
- No pending configuration changes exist

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to Alert Configuration section | Alert configuration page loads successfully displaying current threshold settings and input fields |
| 2 | Attempt to set invalid threshold time by entering text characters (e.g., 'ABC') in the time field | System displays validation error message 'Invalid time format. Please enter a valid time.' and prevents saving the configuration |
| 3 | Attempt to set threshold time with invalid format (e.g., '25:00' or '9:70') | System displays validation error message 'Invalid time value. Please enter time in HH:MM format (00:00-23:59).' and prevents saving |
| 4 | Leave threshold time field empty and attempt to save | System displays validation error message 'Threshold time is required.' and prevents saving the configuration |
| 5 | Enter valid threshold time (e.g., '09:00') and click Save | Configuration is saved successfully with confirmation message 'Alert threshold updated successfully.' |

**Postconditions:**
- Invalid configurations are not saved to the database
- Valid configuration is persisted and active
- Configuration page displays the current valid threshold
- Validation errors are cleared after successful save

---

### Test Case: Test alert acknowledgment and logging
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 7 mins

**Preconditions:**
- Manager user is logged into the system
- At least one unacknowledged late arrival alert exists in the dashboard
- Alert logging functionality is enabled
- Manager has permission to acknowledge alerts

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the Alerts Dashboard section | Dashboard displays list of alerts including at least one unacknowledged late arrival alert with status 'Pending' |
| 2 | Locate the specific late arrival alert and click on it to view details | Alert details panel opens showing employee name, check-in time, delay duration, and alert timestamp |
| 3 | Click the 'Acknowledge' button on the alert | Alert status changes from 'Pending' to 'Acknowledged' with confirmation message 'Alert acknowledged successfully.' displayed |
| 4 | Verify the alert status is updated in the dashboard list view | Alert shows status as 'Acknowledged' with manager name and acknowledgment timestamp visible |
| 5 | Navigate to Alert History/Logs section | Alert log entry is created containing alert ID, employee details, alert timestamp, manager name, acknowledgment timestamp, and status change from 'Pending' to 'Acknowledged' |
| 6 | Verify the acknowledged alert is moved to appropriate section or filtered view | Alert is no longer displayed in 'Pending Alerts' section and appears in 'Acknowledged Alerts' or 'Alert History' section |

**Postconditions:**
- Alert status is permanently updated to 'Acknowledged' in the database
- Alert acknowledgment is logged with complete audit trail
- Manager's acknowledgment action is recorded with timestamp
- Alert is removed from pending notifications count

---

## Story: As Manager, I want to receive notifications for unexcused absences to achieve proactive attendance management
**Story ID:** story-16

### Test Case: Validate detection and notification of unexcused absences
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Manager user is logged into the system with notification permissions
- Test employee account exists with defined work schedule (e.g., start time 9:00 AM)
- Employee has no approved leave requests for the test date
- Notification services (email, SMS, dashboard) are active and configured
- System time is set to at least 30 minutes after scheduled start time

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Simulate employee absence by ensuring no check-in record exists for the employee and no leave approval is present in the system for the current date | System detects unexcused absence by cross-referencing attendance records and leave approval data. Absence is classified as 'Unexcused' |
| 2 | Wait for system to process absence detection (within 30 minutes of scheduled start time) | System triggers notification workflow within 30 minutes of the scheduled start time (9:00 AM) |
| 3 | Check manager's email inbox for unexcused absence notification | Email notification is received within 30 minutes containing employee name, scheduled start time, absence date, and absence duration. Subject line clearly indicates 'Unexcused Absence Alert' |
| 4 | Check manager's mobile device for SMS notification | SMS notification is received within 30 minutes containing employee name, absence date, and brief absence details |
| 5 | Navigate to Notifications Dashboard in the system | Dashboard displays unexcused absence notification with complete details including employee name, employee ID, scheduled start time, absence date, absence duration, and notification timestamp |
| 6 | Click on the notification in the dashboard to view full details | Notification details panel opens showing comprehensive information and 'Acknowledge' button is available |
| 7 | Click 'Acknowledge' button to acknowledge the notification | Notification status changes to 'Acknowledged' with confirmation message 'Notification acknowledged successfully.' Manager name and acknowledgment timestamp are recorded |
| 8 | Navigate to Notification History/Logs section | Acknowledgment is logged successfully with notification ID, employee details, notification timestamp, manager name, acknowledgment timestamp, and delivery status for all channels (email, SMS, dashboard) |

**Postconditions:**
- Unexcused absence is recorded in the system
- Notification is logged with complete audit trail
- Notification status is updated to 'Acknowledged'
- All notification channels show consistent delivery status
- Manager acknowledgment is permanently recorded

---

### Test Case: Verify notification preference configuration
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 7 mins

**Preconditions:**
- Manager user is logged into the system with configuration permissions
- Notification preferences page is accessible
- Current notification preferences are set to default (all channels enabled)
- Manager profile has valid email and phone number configured

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to Notification Preferences or Settings section | Notification preferences page loads successfully displaying current settings for unexcused absence notifications with options for email, SMS, and dashboard channels |
| 2 | Review current notification delivery preferences | Current preferences are displayed showing enabled/disabled status for each channel (email, SMS, dashboard) and any configured notification timing preferences |
| 3 | Update notification delivery preferences by disabling SMS notifications and keeping email and dashboard enabled | SMS checkbox is unchecked while email and dashboard checkboxes remain checked. Changes are reflected in the UI immediately |
| 4 | Configure notification timing preference (e.g., immediate vs. digest) | Timing preference option is selected and highlighted in the UI |
| 5 | Click 'Save' or 'Update Preferences' button | Preferences are saved successfully with confirmation message 'Notification preferences updated successfully.' displayed |
| 6 | Refresh the page or navigate away and return to verify persistence | Updated preferences are displayed correctly showing SMS disabled, email and dashboard enabled, and selected timing preference |
| 7 | Trigger a test unexcused absence notification to verify preferences are applied | Notification is sent only via email and dashboard. No SMS notification is received, confirming preferences are applied correctly |

**Postconditions:**
- Notification preferences are saved in the database
- Updated preferences are active and applied to future notifications
- Manager receives notifications only through selected channels
- Preference changes are logged in the system audit trail

---

