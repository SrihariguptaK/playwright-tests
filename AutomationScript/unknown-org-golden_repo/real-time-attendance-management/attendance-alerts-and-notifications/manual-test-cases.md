# Manual Test Cases

## Story: As Manager, I want to receive alerts for attendance anomalies to achieve proactive workforce management
**Story ID:** story-14

### Test Case: Validate alert configuration and saving
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Manager is logged into the system with valid credentials
- Manager has appropriate role-based permissions to access alert settings
- Dashboard is accessible and functioning properly
- At least one notification channel (email/SMS/in-app) is available for configuration

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the dashboard and locate the alert settings menu option | Alert settings menu option is visible and clickable |
| 2 | Click on the alert settings menu to access the alert configuration page | Alert configuration UI loads successfully with all configuration options displayed including threshold settings and notification channel selections |
| 3 | Set late arrival threshold to 15 minutes in the threshold configuration field | Threshold value is accepted and displayed correctly in the input field |
| 4 | Set absence alert threshold to trigger immediately upon absence detection | Absence threshold setting is configured and displayed correctly |
| 5 | Select email notification channel by checking the email checkbox | Email checkbox is checked and email notification is enabled |
| 6 | Select SMS notification channel by checking the SMS checkbox | SMS checkbox is checked and SMS notification is enabled |
| 7 | Select in-app notification channel by checking the in-app checkbox | In-app checkbox is checked and in-app notification is enabled |
| 8 | Click the Save button to save the alert configuration settings | Settings are saved successfully and a confirmation message is displayed indicating successful save operation |
| 9 | Navigate away from the alert settings page to another section of the dashboard | Navigation is successful and user is on a different page |
| 10 | Return to the alert settings page by clicking on alert settings menu again | Alert settings page reloads successfully |
| 11 | Verify that the late arrival threshold displays 15 minutes | Late arrival threshold shows the previously saved value of 15 minutes |
| 12 | Verify that the absence threshold displays immediate trigger setting | Absence threshold shows the previously saved immediate trigger configuration |
| 13 | Verify that email, SMS, and in-app notification channels are all checked | All three notification channels (email, SMS, in-app) are displayed as selected with checkboxes checked |

**Postconditions:**
- Alert configuration settings are persisted in the database
- Manager remains logged into the system
- Alert settings page displays the saved configuration
- System is ready to monitor attendance data based on configured thresholds

---

### Test Case: Verify alert delivery for late arrival
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Manager has configured alert settings with late arrival threshold set to 15 minutes
- Email, SMS, and in-app notification channels are enabled in alert settings
- Manager's email address and phone number are registered in the system
- Real-time attendance monitoring system is active and functioning
- Test employee exists in the system with scheduled shift start time
- Current time is within business hours for testing

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Note the current system time and the scheduled shift start time for the test employee | Shift start time is clearly identified and documented |
| 2 | Simulate an employee late arrival event by marking the employee as arrived 20 minutes after their scheduled shift start time | Late arrival event is recorded in the attendance system with timestamp showing 20 minutes late |
| 3 | Wait for the system to process the attendance data and detect the anomaly | System detects the late arrival anomaly as it exceeds the 15-minute threshold and generates an alert |
| 4 | Check the manager's email inbox within 5 minutes of the late arrival event | Alert email is received containing employee name, late arrival time, scheduled time, and delay duration |
| 5 | Check the manager's mobile phone for SMS notification within 5 minutes of the late arrival event | Alert SMS is received containing key information about the late arrival including employee name and delay |
| 6 | Log into the dashboard and check the in-app notifications section | In-app notification is displayed showing the late arrival alert with complete details |
| 7 | Verify that all three notifications were received within 5 minutes of the simulated late arrival event | Timestamps on email, SMS, and in-app notifications confirm delivery within the 5-minute SLA |
| 8 | Click on the late arrival alert in the dashboard notifications panel | Alert details expand showing full information including employee details, scheduled time, actual arrival time, and delay duration |
| 9 | Click the Acknowledge button on the alert | Acknowledge action is processed successfully |
| 10 | Verify the alert status has changed to acknowledged | Alert status is updated to 'Acknowledged' with timestamp and manager name displayed |
| 11 | Refresh the dashboard page | Alert continues to show acknowledged status after page refresh, confirming status persistence |

**Postconditions:**
- Late arrival alert is logged in the system with acknowledged status
- Alert history contains the complete record of the alert and acknowledgment
- Email, SMS, and in-app notifications have been successfully delivered
- Manager can view the acknowledged alert in alert history
- System continues to monitor for new attendance anomalies

---

### Test Case: Test alert acknowledgment and dismissal
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Manager is logged into the dashboard with appropriate permissions
- Multiple active alerts exist in the system (at least 3 alerts for comprehensive testing)
- Alerts include various types such as late arrivals and absences
- Alert history logging functionality is enabled
- Manager has not previously acknowledged or dismissed the test alerts

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the alerts section of the dashboard | Alerts page loads successfully displaying the alerts interface |
| 2 | Locate and click on the active alerts tab or section | Active alerts section is displayed showing all unacknowledged and undismissed alerts |
| 3 | Count and verify the number of active alerts displayed | All active alerts are listed with complete information including employee name, alert type, timestamp, and severity |
| 4 | Review the details of the first alert including alert type, employee information, and timestamp | Alert details are clearly displayed and readable with all relevant information present |
| 5 | Click on the Dismiss button for the first alert in the active alerts list | Dismiss confirmation dialog appears asking for confirmation of the dismissal action |
| 6 | Confirm the dismissal action by clicking Yes or Confirm in the dialog | Alert is dismissed successfully and a confirmation message is displayed |
| 7 | Verify that the dismissed alert is removed from the active alerts list | The dismissed alert no longer appears in the active alerts section and the alert count is reduced by one |
| 8 | Note the exact timestamp when the alert was dismissed | Current system timestamp is recorded for verification purposes |
| 9 | Navigate to the alert history section from the alerts menu | Alert history page loads successfully displaying historical alert records |
| 10 | Search for the recently dismissed alert in the alert history using employee name or alert ID | Dismissed alert is found in the alert history records |
| 11 | Click on the dismissed alert entry in the history to view full details | Alert details expand showing complete information including original alert data |
| 12 | Verify the alert status field shows 'Dismissed' in the alert history record | Alert status is clearly marked as 'Dismissed' in the status field |
| 13 | Verify the dismissal timestamp matches the time when the alert was dismissed | Dismissal timestamp in the history record matches the noted dismissal time with accuracy within seconds |
| 14 | Verify the manager's name or ID is logged as the person who dismissed the alert | Manager's identification information is correctly recorded in the dismissal record for audit purposes |
| 15 | Return to the active alerts section | Active alerts page is displayed again |
| 16 | Select a different alert and click the Acknowledge button instead of Dismiss | Alert is acknowledged and status changes to 'Acknowledged' while remaining visible in the alerts list |
| 17 | Verify the acknowledged alert shows updated status but remains in the alerts view | Alert displays 'Acknowledged' status with timestamp and manager information, distinguishing it from active unacknowledged alerts |

**Postconditions:**
- Dismissed alert is removed from active alerts list
- Dismissed alert is logged in alert history with correct status and timestamp
- Acknowledged alert remains visible with updated status
- Alert history contains complete audit trail of all actions
- Manager remains logged into the system
- All alert actions are properly recorded for compliance and audit purposes

---

