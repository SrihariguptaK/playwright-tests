# Manual Test Cases

## Story: As Manager, I want to receive alerts for attendance anomalies to achieve timely response to workforce issues
**Story ID:** story-6

### Test Case: Validate alert generation for attendance anomalies
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Manager is logged into the system with appropriate permissions
- Alert configuration module is accessible at /api/alerts
- Email, SMS, and in-app notification channels are configured and operational
- Real-time attendance monitoring system is active
- Test employee account exists in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to Alert Configuration section in the dashboard | Alert Configuration page loads successfully displaying existing rules and option to create new rules |
| 2 | Click on 'Create New Alert Rule' button | Alert rule creation form is displayed with fields for rule type, threshold, and notification channels |
| 3 | Select 'Late Arrival' as the alert type from dropdown | Late Arrival option is selected and relevant configuration fields appear |
| 4 | Set threshold to '15 minutes after scheduled start time' | Threshold value is accepted and displayed in the configuration form |
| 5 | Enable all notification channels: Email, SMS, and In-app notifications | All three notification channels are checked and highlighted as active |
| 6 | Click 'Save Configuration' button | System displays success message 'Alert configuration saved successfully' and rule appears in the active rules list |
| 7 | Verify the saved configuration by checking the alert rules list | New late arrival rule is visible with correct threshold and enabled notification channels |
| 8 | Simulate a late arrival event by marking test employee as checked-in 20 minutes after scheduled start time | Attendance system records the late arrival with timestamp |
| 9 | Wait and monitor alert generation for up to 5 minutes | System detects the anomaly and generates an alert within 5 minutes of the late arrival event |
| 10 | Check in-app notification panel on the dashboard | Alert notification appears in the dashboard showing employee name, late arrival time, and delay duration |
| 11 | Check the configured email inbox for alert notification | Email alert is received containing employee details, late arrival information, and timestamp within 5 minutes |
| 12 | Check the configured mobile device for SMS notification | SMS alert is received with concise message about late arrival including employee name and delay duration |
| 13 | Verify alert details match across all three channels | All notifications contain consistent information about the same late arrival event with matching timestamps |

**Postconditions:**
- Alert rule for late arrivals remains active in the system
- Alert is logged in the system with delivery status for all channels
- Manager has received notifications on all configured channels
- Test employee's late arrival is recorded in attendance history

---

### Test Case: Test alert acknowledgment and dismissal
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Manager is logged into the system with manager role permissions
- At least one active alert exists in the system
- Alert is visible on the manager's dashboard
- Alert has not been previously acknowledged or dismissed

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the Alerts Dashboard section | Alerts Dashboard loads displaying list of active alerts with details |
| 2 | Locate the test alert in the active alerts list | Alert is visible showing employee name, anomaly type, timestamp, and status as 'Unacknowledged' |
| 3 | Click on the alert to view full details | Alert details panel expands showing complete information including acknowledgment and dismissal action buttons |
| 4 | Verify acknowledgment options are available | 'Acknowledge' and 'Dismiss' buttons are visible and enabled in the alert detail view |
| 5 | Click the 'Acknowledge' button | System displays confirmation message 'Alert acknowledged successfully' |
| 6 | Verify alert status update after acknowledgment | Alert status changes from 'Unacknowledged' to 'Acknowledged' with timestamp of acknowledgment and manager's name |
| 7 | Check that acknowledged alert remains in the alerts list | Alert is still visible in the dashboard but marked with 'Acknowledged' status and different visual indicator |
| 8 | Navigate to a different unacknowledged alert or create a new test alert | New alert is visible in the active alerts list with 'Unacknowledged' status |
| 9 | Click on the new alert to view details | Alert details panel opens with full information and action buttons |
| 10 | Click the 'Dismiss' button | System prompts for confirmation with message 'Are you sure you want to dismiss this alert?' |
| 11 | Confirm dismissal by clicking 'Yes' or 'Confirm' | System displays success message 'Alert dismissed successfully' |
| 12 | Verify alert is removed from active alerts list | Dismissed alert is no longer visible in the active alerts dashboard |
| 13 | Check alert history or logs to verify dismissed alert is recorded | Dismissed alert appears in alert history with status 'Dismissed', timestamp, and manager who dismissed it |

**Postconditions:**
- Acknowledged alert remains in system with updated status
- Dismissed alert is removed from active alerts but retained in history
- All alert status changes are logged with timestamps and manager information
- Alert counters on dashboard reflect updated numbers

---

### Test Case: Verify alert delivery failure handling
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- Manager is logged into the system with appropriate permissions
- Alert generation system is operational
- SMS delivery service is accessible for testing failure scenarios
- Alert logging system is active and accessible
- Test alert rule is configured with SMS notification enabled
- Access to system logs and alert delivery logs is available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Configure test environment to simulate SMS delivery failure by disabling SMS gateway or using invalid phone number | SMS delivery service is set to fail for testing purposes while other channels remain operational |
| 2 | Trigger an attendance anomaly event that should generate an alert | System detects the anomaly and initiates alert generation process |
| 3 | Monitor alert delivery attempts in real-time | System attempts to deliver alert via all configured channels including SMS |
| 4 | Verify SMS delivery failure occurs | SMS delivery fails with appropriate error response from SMS gateway |
| 5 | Observe system retry mechanism for SMS delivery | System automatically retries SMS delivery according to configured retry policy (e.g., 3 retry attempts with intervals) |
| 6 | Wait for all retry attempts to complete | System exhausts all retry attempts and marks SMS delivery as failed |
| 7 | Verify other notification channels (email and in-app) are delivered successfully | Email and in-app notifications are delivered successfully despite SMS failure |
| 8 | Navigate to Alert Logs section in the system | Alert Logs page loads displaying list of recent alerts with delivery status |
| 9 | Locate the test alert in the logs | Test alert is visible in the logs with detailed delivery status for each channel |
| 10 | Click on the alert entry to view detailed delivery information | Detailed log view opens showing delivery status breakdown by channel |
| 11 | Verify SMS delivery failure is recorded with timestamp | SMS channel shows 'Failed' status with timestamp of initial attempt and all retry attempts |
| 12 | Check error details for SMS delivery failure | Error details are logged including error code, error message (e.g., 'SMS gateway timeout', 'Invalid recipient'), and number of retry attempts |
| 13 | Verify successful delivery channels are also logged | Email and in-app channels show 'Delivered' status with successful delivery timestamps |
| 14 | Check if system generated any internal alerts or notifications about the delivery failure | System logs the failure appropriately and may generate admin notification about SMS delivery issues if configured |

**Postconditions:**
- SMS delivery failure is fully documented in alert logs
- All retry attempts are recorded with timestamps and error details
- Successful delivery channels are confirmed and logged
- Alert remains in the system with partial delivery status
- System is ready for subsequent alert deliveries
- Test SMS gateway configuration can be restored to normal operation

---

