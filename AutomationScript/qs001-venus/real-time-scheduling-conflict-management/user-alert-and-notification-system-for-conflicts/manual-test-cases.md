# Manual Test Cases

## Story: As Scheduler, I want to receive real-time alerts when conflicts occur to promptly resolve scheduling issues
**Story ID:** story-2

### Test Case: Validate real-time alert display on conflict detection
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- Scheduler is logged into the scheduling system
- Scheduler has appropriate permissions to create and modify schedules
- Scheduling interface is loaded and functional
- At least one existing schedule entry is present in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Scheduler creates a new schedule entry that conflicts with an existing schedule (e.g., same resource, overlapping time) | Alert is displayed immediately on the scheduling interface showing conflict notification |
| 2 | Scheduler clicks on the alert to view details | Detailed conflict information is shown including conflicting schedules, resources involved, time overlap, and affected parties |
| 3 | Scheduler clicks the acknowledge button on the alert | Alert is dismissed from the interface and no longer visible in the active alerts list |

**Postconditions:**
- Alert has been acknowledged and removed from active display
- Conflicting schedule entry remains in the system
- Alert acknowledgment is recorded in system logs

---

### Test Case: Verify email notification delivery for conflicts
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Scheduler is logged into the scheduling system
- Scheduler has email notifications enabled in user preferences
- Valid email address is configured in scheduler's profile
- Email service is operational and configured correctly
- Scheduler has access to their email inbox

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Verify that scheduler has email notifications enabled in system preferences | Email notification preference is set to 'enabled' for conflict alerts |
| 2 | Create a scheduling conflict by adding an overlapping schedule entry | System detects the conflict and sends an email notification to the scheduler's registered email address |
| 3 | Scheduler opens their email inbox and locates the conflict notification email | Conflict notification email is received with subject line indicating scheduling conflict, email body contains detailed conflict information including resources, times, and affected schedules |
| 4 | Scheduler clicks the link provided in the email to view the conflict | Browser navigates to the scheduling interface with the specific conflict highlighted and conflict details displayed |

**Postconditions:**
- Email notification has been successfully delivered and opened
- Scheduler is viewing the conflict in the scheduling interface
- Conflict remains unresolved and visible in the system

---

### Test Case: Ensure alert delivery within 1 second
- **ID:** tc-003
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Scheduler is logged into the scheduling system
- System is operating under normal load conditions
- Performance monitoring tools are available and configured
- System logs are accessible for latency verification
- Timer or stopwatch is available to measure alert delivery time

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Note the current time and trigger a scheduling conflict by creating an overlapping schedule entry | Alert is displayed on the scheduling interface within 1 second of conflict creation, measured from submission to alert appearance |
| 2 | Repeat the conflict creation process 10 times, monitoring and recording alert delivery times for each event | All 10 alerts are delivered within 1 second of conflict detection, with consistent performance across all iterations |
| 3 | Access system logs and review alert latency metrics for the test period | System logs show all alert delivery times are within the 1-second SLA, with timestamps confirming conflict detection time and alert delivery time |

**Postconditions:**
- All test alerts have been delivered within performance SLA
- Performance metrics are documented in system logs
- Test conflicts can be cleaned up or remain for further testing

---

## Story: As Scheduler, I want to acknowledge conflict alerts to confirm I have seen and will address scheduling issues
**Story ID:** story-6

### Test Case: Validate alert acknowledgment requirement before dismissal
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- Scheduler is logged into the scheduling system
- A conflict alert has been triggered and is displayed on the interface
- Alert is in unacknowledged state
- Scheduler has permissions to acknowledge alerts

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Scheduler views the conflict alert displayed on the scheduling interface | Alert is displayed with clear acknowledgment button or checkbox option visible, alert shows unacknowledged status |
| 2 | Scheduler attempts to dismiss or close the alert without clicking the acknowledgment button (e.g., clicking X or close button) | System blocks the dismissal action and displays a prompt or message requiring acknowledgment before dismissal, alert remains visible on the interface |
| 3 | Scheduler clicks the acknowledge button on the alert | Alert status updates to 'acknowledged', acknowledgment confirmation is displayed, and alert can now be dismissed successfully |

**Postconditions:**
- Alert status is marked as acknowledged in the system
- Alert can be dismissed by the scheduler
- Acknowledgment is recorded with user identity and timestamp

---

### Test Case: Verify acknowledgment is logged correctly
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Scheduler is logged into the scheduling system with known user credentials
- A conflict alert is displayed and available for acknowledgment
- System logging is enabled and functional
- Access to system logs and audit trail is available
- Database or log query tools are accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Note the current timestamp and scheduler's user ID, then click the acknowledge button on the conflict alert | System displays acknowledgment confirmation and alert status changes to acknowledged |
| 2 | Access the acknowledgment logs through the system admin panel or database query | Acknowledgment log entry is present containing the correct user ID, alert ID, and timestamp within 1 second of the acknowledgment action |
| 3 | Check the audit trail for acknowledgment events related to the specific alert | Audit trail shows complete and accurate event record including user identity, alert identifier, acknowledgment timestamp, and action type as 'alert_acknowledged' |

**Postconditions:**
- Acknowledgment is permanently recorded in system logs
- Audit trail contains complete acknowledgment event details
- Log entries are available for compliance and reporting purposes

---

### Test Case: Ensure acknowledgment processing completes within 1 second
- **ID:** tc-006
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- Scheduler is logged into the scheduling system
- A conflict alert is displayed and ready for acknowledgment
- System is operating under normal load conditions
- Performance monitoring tools are available
- Timer or performance measurement tool is ready

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Note the current time and click the acknowledge button on the conflict alert | Acknowledgment is processed and confirmed within 1 second, alert status updates to acknowledged, and UI reflects the change immediately |
| 2 | Monitor and record system response times during the acknowledgment process using performance tools or browser developer tools | Response time metrics show acknowledgment API call completes within 1 second, network latency and processing time are within acceptable ranges |
| 3 | Review system logs and error logs for any errors or warnings during the acknowledgment process | No errors or exceptions are logged, acknowledgment completes successfully with HTTP 200 status code, and transaction is committed to database |

**Postconditions:**
- Acknowledgment has been processed within performance SLA
- No errors occurred during acknowledgment processing
- Alert status is successfully updated to acknowledged
- Performance metrics are documented for compliance verification

---

## Story: As Scheduler, I want to configure notification preferences for conflict alerts to receive alerts via my preferred channels
**Story ID:** story-7

### Test Case: Validate notification preference configuration UI
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Scheduler user account is created and active
- Scheduler is logged into the system
- User has valid email address in profile
- Notification settings page is accessible
- At least email and in-app notification channels are available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to user profile menu and click on 'Notification Settings' option | Notification settings page loads successfully displaying all available notification channel options (email and in-app) |
| 2 | Review the notification preference options displayed on the page | UI displays checkboxes or toggle switches for email and in-app notification channels with clear labels and current selection status |
| 3 | Select 'Email' notification channel by checking the checkbox | Email checkbox is marked as selected and visual feedback confirms the selection |
| 4 | Select 'In-app' notification channel by checking the checkbox | In-app checkbox is marked as selected and visual feedback confirms the selection |
| 5 | Click 'Save' or 'Update Preferences' button | System displays success message confirming preferences have been saved, and selected channels remain checked |
| 6 | Create a scheduling conflict by attempting to book overlapping appointments | System detects the conflict and triggers a conflict alert |
| 7 | Check email inbox for conflict alert notification | Conflict alert email is received with details of the scheduling conflict |
| 8 | Check in-app notifications panel or bell icon | Conflict alert appears in the in-app notification center with conflict details |

**Postconditions:**
- Notification preferences are saved in the database
- Selected channels (email and in-app) are active for future alerts
- Conflict alert was successfully delivered via both selected channels
- User remains on notification settings page or is redirected to dashboard

---

### Test Case: Verify immediate application of preference changes
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Scheduler user account is created and active
- Scheduler is logged into the system
- Initial notification preferences are already configured (e.g., email only)
- User has access to notification settings
- System has logging capability enabled for preference changes

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to notification settings page | Notification settings page loads showing current preferences (email selected) |
| 2 | Uncheck 'Email' notification channel | Email checkbox is unchecked and visual feedback shows deselection |
| 3 | Check 'In-app' notification channel | In-app checkbox is checked and visual feedback shows selection |
| 4 | Click 'Save' or 'Update Preferences' button | System displays success message 'Preferences updated successfully' and timestamp of update is shown |
| 5 | Note the current time and immediately create a scheduling conflict | System detects the scheduling conflict and triggers a conflict alert |
| 6 | Check email inbox for conflict alert | No conflict alert email is received (email channel was disabled) |
| 7 | Check in-app notifications panel | Conflict alert appears in the in-app notification center according to new preferences |
| 8 | Access system logs or admin panel to review preference change events | System logs show preference update timestamp and immediate application with no delay between save and activation |
| 9 | Verify log entries show alert delivery method matches updated preferences | Logs confirm alert was sent only via in-app channel, matching the updated preferences |

**Postconditions:**
- Updated notification preferences are active in the system
- Email notifications are disabled for the user
- In-app notifications are enabled for the user
- System logs reflect the preference change and immediate application
- No delay observed between preference update and alert delivery

---

### Test Case: Ensure validation of user contact information
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Scheduler user account is created and active
- Scheduler is logged into the system
- Notification settings page is accessible
- Email notification channel is available
- User profile has existing valid email address

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to notification settings page | Notification settings page loads successfully with current contact information displayed |
| 2 | Click on 'Edit Contact Information' or email field to modify email address | Email input field becomes editable and cursor is positioned in the field |
| 3 | Enter invalid email address 'invalidemail@' in the email field | Email field accepts the input temporarily |
| 4 | Select 'Email' notification channel checkbox | Email checkbox is marked as selected |
| 5 | Click 'Save' or 'Update Preferences' button | System displays validation error message 'Please enter a valid email address' in red text near the email field, and preferences are not saved |
| 6 | Verify that the invalid email is highlighted or marked with error indicator | Email field is highlighted with red border or error icon indicating validation failure |
| 7 | Clear the email field and enter valid email address 'scheduler@example.com' | Email field accepts the valid input and error indicators are removed |
| 8 | Ensure 'Email' notification channel remains selected | Email checkbox is still checked |
| 9 | Click 'Save' or 'Update Preferences' button | System displays success message 'Preferences saved successfully' and no validation errors appear |
| 10 | Create a scheduling conflict to trigger an alert | System detects the conflict and triggers a conflict alert |
| 11 | Check the email inbox at 'scheduler@example.com' | Conflict alert email is successfully delivered to the corrected email address with conflict details |

**Postconditions:**
- Valid email address is saved in user profile
- Email notification channel is active with validated contact information
- Notification preferences are successfully saved
- Alert delivery is functional with corrected email address
- System maintains data integrity by rejecting invalid contact information

---

