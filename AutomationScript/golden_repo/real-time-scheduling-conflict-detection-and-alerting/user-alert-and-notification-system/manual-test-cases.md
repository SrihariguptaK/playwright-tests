# Manual Test Cases

## Story: As Scheduler, I want to configure my preferred alert channels to receive scheduling conflict notifications effectively
**Story ID:** story-12

### Test Case: Validate alert channel preference saving
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Scheduler user account exists and is active
- Scheduler is logged into the system
- Alert preferences feature is enabled
- User has valid email address and phone number available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the alert preferences page from the user settings menu | Alert preferences UI is displayed showing available channel options (email, SMS, in-app) and current settings |
| 2 | Select the email checkbox and enter a valid email address in the email field | Email checkbox is checked and email input field accepts the valid email format without validation errors |
| 3 | Select the SMS checkbox and enter a valid phone number in the SMS field | SMS checkbox is checked and phone number input field accepts the valid phone format without validation errors |
| 4 | Click the 'Save Preferences' button | System displays a success confirmation message indicating preferences have been saved successfully |
| 5 | Refresh the alert preferences page | Previously saved preferences (email and SMS channels with contact information) are displayed correctly |

**Postconditions:**
- Alert preferences are persisted in the user preferences database
- Email and SMS channels are active for the scheduler
- Future alerts will be sent via configured channels

---

### Test Case: Verify alerts sent via configured channels
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Scheduler has configured alert preferences with email and SMS channels enabled
- Valid email address and phone number are saved in preferences
- Email and SMS notification services are operational
- Test scheduling conflict scenario is available to trigger

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Create a scheduling conflict by double-booking a resource or creating overlapping schedules | System detects the scheduling conflict and triggers the alert mechanism |
| 2 | Wait for alert delivery (maximum 2 seconds as per success metrics) | Alert is sent to both email and SMS channels within 2 seconds |
| 3 | Check the configured email inbox for the alert notification | Email alert is received containing scheduling conflict details with timestamp and conflict information |
| 4 | Check the configured phone number for SMS alert notification | SMS alert is received containing scheduling conflict summary with relevant details |
| 5 | Verify that in-app notification was NOT received (since it was not configured) | No in-app notification is displayed, confirming alerts are sent only via configured channels |

**Postconditions:**
- Scheduler has received alerts on both configured channels
- Alert delivery is logged in the system
- Scheduling conflict remains active until resolved

---

### Test Case: Test validation of invalid contact info
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Scheduler user is logged into the system
- Alert preferences page is accessible
- Email and SMS channels are available for configuration

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the alert preferences page | Alert preferences UI is displayed with input fields for contact information |
| 2 | Select the email checkbox and enter an invalid email format (e.g., 'invalidemail@') | Email input field accepts the text entry |
| 3 | Click the 'Save Preferences' button | Validation error is displayed indicating invalid email format, and preferences are not saved |
| 4 | Correct the email address to a valid format (e.g., 'scheduler@example.com') | Email input field accepts the valid email and validation error is cleared |
| 5 | Select the SMS checkbox and enter an invalid phone number format (e.g., '123') | Phone number input field accepts the text entry |
| 6 | Click the 'Save Preferences' button | Validation error is displayed indicating invalid phone number format, and preferences are not saved |
| 7 | Correct the phone number to a valid format (e.g., '+1234567890') | Phone number input field accepts the valid number and validation error is cleared |
| 8 | Click the 'Save Preferences' button | System displays success confirmation message and preferences are saved successfully |

**Postconditions:**
- Valid contact information is saved in user preferences
- Invalid data was rejected and not persisted
- User received clear validation feedback

---

## Story: As Scheduler, I want to receive escalation alerts for unresolved scheduling conflicts to ensure timely resolution
**Story ID:** story-14

### Test Case: Verify escalation alert after unresolved conflict threshold
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 35 mins

**Preconditions:**
- Scheduler user account exists and is active
- Escalation feature is enabled in the system
- Escalation threshold is configured (e.g., 30 minutes)
- Designated higher-level users are configured for escalation
- Alert channels are configured for both scheduler and escalation recipients
- System time can be manipulated or waited for testing purposes

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Create a scheduling conflict by double-booking a resource | System detects the scheduling conflict and records the conflict creation timestamp |
| 2 | Verify that initial alert is sent to the scheduler | Initial conflict alert is received by the scheduler via configured channels with conflict details |
| 3 | Leave the conflict unresolved and wait until the escalation threshold time passes (or advance system time) | Escalation threshold is reached without conflict resolution |
| 4 | Monitor for escalation alert delivery within 1 minute of threshold | Escalation alert is sent to designated higher-level users within 1 minute of threshold being reached |
| 5 | Verify escalation alert content received by higher-level users | Escalation alert contains detailed conflict information including original alert time, duration unresolved, and conflict details |
| 6 | Resolve the scheduling conflict by removing the double-booking | System marks the conflict as resolved and records resolution timestamp |
| 7 | Monitor for any additional escalation alerts after conflict resolution | No further escalation alerts are sent after the conflict is resolved |

**Postconditions:**
- Conflict is resolved in the system
- Escalation alerts have ceased
- Escalation event is logged in audit trail
- Conflict duration is recorded accurately

---

### Test Case: Check audit logging of escalation events
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 10 mins

**Preconditions:**
- Audit logging feature is enabled
- User has permissions to view audit logs
- Escalation feature is configured and operational
- At least one unresolved conflict exists that can trigger escalation

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Create a scheduling conflict and wait for escalation threshold to pass | Scheduling conflict is created and escalation threshold is reached |
| 2 | Verify that escalation alert is triggered and sent to designated users | Escalation alert is sent successfully to higher-level users |
| 3 | Navigate to the audit logs section of the system | Audit logs interface is displayed with search and filter options |
| 4 | Filter audit logs for escalation events related to the triggered conflict | Audit log entries for the escalation event are displayed |
| 5 | Review the escalation event log entry details | Log entry contains accurate timestamp of escalation, conflict ID, scheduler user details, escalated-to user details, and escalation reason |
| 6 | Verify the timestamp accuracy in the audit log | Timestamp in audit log matches the actual time when escalation alert was triggered (within acceptable margin) |
| 7 | Check that all required fields are populated in the audit log entry | Audit log contains complete information including event type, user IDs, conflict details, and escalation level |
| 8 | Resolve the conflict and verify resolution is also logged | Conflict resolution event is logged with timestamp and user who resolved it |

**Postconditions:**
- Complete audit trail exists for the escalation event
- Audit logs accurately reflect escalation history
- Logs are available for compliance and reporting purposes

---

## Story: As Scheduler, I want to receive detailed conflict information in alerts to understand and resolve issues effectively
**Story ID:** story-20

### Test Case: Verify detailed conflict information in alerts
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Scheduler user is logged into the system
- Scheduler has valid email address configured for notifications
- In-app notification system is enabled
- At least two bookings exist that create a scheduling conflict
- Notification service is operational
- User has appropriate permissions to view booking details

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Create or identify a scheduling conflict by attempting to book the same resource for overlapping time slots | System detects the scheduling conflict and triggers conflict detection mechanism |
| 2 | Wait for conflict alert to be generated | Alert is generated within 2 seconds of conflict detection |
| 3 | Review the alert content received via in-app notification | Alert contains all required details: booking IDs of conflicting bookings, resource names involved in conflict, conflicting time slots with start and end times, and suggested resolution steps |
| 4 | Verify the booking IDs displayed in the alert | Both conflicting booking IDs are clearly displayed and match the actual conflicting bookings in the system |
| 5 | Verify the resource names displayed in the alert | Resource names are accurate and match the resources involved in the conflict |
| 6 | Verify the time slots displayed in the alert | Time slots show exact start and end times for both conflicting bookings in a clear, readable format |
| 7 | Check email inbox for the same conflict alert | Email notification is received with identical conflict information |
| 8 | Review the email alert formatting and content structure | Email alert content is clear, well-formatted, and easy to read with proper spacing, headers, and organized sections for booking IDs, resources, times, and suggested actions |
| 9 | Compare in-app notification format with email notification format | Both notification channels display the same information with appropriate formatting for each medium |
| 10 | Locate and identify the clickable link to the first conflicting booking in the alert | Link is clearly visible and properly labeled with the booking ID or descriptive text |
| 11 | Click on the link to the first conflicting booking | System navigates to the booking details page for the first conflicting booking in the UI |
| 12 | Verify the booking details page displays correct information matching the alert | Booking details page shows the same booking ID, resource name, and time slot as mentioned in the alert |
| 13 | Navigate back to the alert and click on the link to the second conflicting booking | System navigates to the booking details page for the second conflicting booking in the UI |
| 14 | Verify the second booking details page displays correct information | Booking details page shows accurate information for the second conflicting booking matching the alert details |
| 15 | Review the suggested resolution steps provided in the alert | Alert contains clear, actionable suggested resolution steps such as 'Reschedule one of the bookings', 'Select alternative resource', or 'Contact booking owner' |

**Postconditions:**
- Scheduler has received and reviewed detailed conflict information
- Scheduler has successfully accessed both conflicting booking details via provided links
- Alert remains in notification history for future reference
- No system errors or performance issues occurred during alert generation and delivery
- Conflict remains unresolved and available for scheduler action

---

