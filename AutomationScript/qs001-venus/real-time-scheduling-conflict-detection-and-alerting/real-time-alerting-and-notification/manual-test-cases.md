# Manual Test Cases

## Story: As Scheduler, I want to receive real-time alerts for scheduling conflicts to enable immediate resolution
**Story ID:** story-12

### Test Case: Validate real-time alert delivery upon conflict detection
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged into the scheduling system with valid credentials
- User has configured at least one alert notification channel (in-app, email, or SMS)
- Conflict detection engine is active and operational
- System time synchronization is accurate
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Create a scheduling conflict by assigning the same resource to two overlapping time slots | Conflict is detected by the system immediately and logged in the conflict detection engine |
| 2 | Start a timer and observe the alert dispatch mechanism | Alert is generated and sent within 2 seconds of conflict detection via all configured notification channels |
| 3 | Check the received alert notification in the configured channel(s) | Alert is received and contains detailed conflict information including resource name, conflicting time slots, affected schedules, and suggested resolution actions |
| 4 | Verify the alert timestamp against the conflict creation time | Alert delivery latency is confirmed to be under 2 seconds from conflict detection |

**Postconditions:**
- Alert is successfully delivered to user via configured channels
- Alert delivery is logged in the system with timestamp and delivery status
- Conflict remains in pending state awaiting resolution
- Alert appears in user's notification center

---

### Test Case: Verify user alert preference configuration
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged into the scheduling system with scheduler role privileges
- User has access to alert settings and preferences
- Multiple notification channels are available (in-app, email, SMS)
- User profile is complete with valid contact information
- System has POST /api/alerts endpoint accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to user profile settings and click on 'Alert Preferences' or 'Notification Settings' | Alert settings page is displayed showing all available notification channel options and current preferences |
| 2 | Select preferred notification channels by checking in-app, email, and/or SMS options | Selected channels are highlighted and marked as active |
| 3 | Configure additional settings such as alert frequency, quiet hours, and priority levels, then click 'Save' or 'Update Preferences' | Success message is displayed confirming preferences are saved successfully, and settings are persisted in the database |
| 4 | Trigger a test conflict alert by creating a scheduling conflict | Alert is generated and sent only via the user-selected notification channels within 2 seconds |
| 5 | Verify alert receipt in each selected channel | Alert is received in all configured channels (in-app notification, email inbox, SMS message) with consistent conflict information |

**Postconditions:**
- User alert preferences are saved and active in the system
- Future alerts will be delivered according to configured preferences
- Alert preference settings are retrievable and editable
- Test conflict alert is logged in alert delivery logs

---

### Test Case: Ensure alert delivery logging and acknowledgment tracking
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged into the scheduling system
- Alert delivery logging mechanism is enabled
- Database has alert_logs table with proper schema
- User has permissions to acknowledge alerts
- Reporting module is accessible and functional

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Trigger a scheduling conflict to generate an alert and send it to the user via configured channels | Alert is sent successfully to the user |
| 2 | Query the alert delivery logs in the database or access the alert log viewer in the admin panel | Alert delivery is logged in the system with details including alert ID, timestamp, recipient, delivery channel, delivery status (sent/failed), and conflict details |
| 3 | User opens the alert notification and clicks 'Acknowledge' or 'Mark as Read' button | Acknowledgment action is processed and recorded in the system with user ID and acknowledgment timestamp |
| 4 | Refresh the alert log viewer and locate the acknowledged alert | Alert status is updated to 'Acknowledged' with user details and timestamp visible in the log |
| 5 | Navigate to the reporting module and generate an alert delivery and acknowledgment report for the current date/time period | Report is generated successfully showing all alerts with their delivery status, acknowledgment status, delivery timestamps, acknowledgment timestamps, and user details |
| 6 | Verify the accuracy of the report by cross-referencing with the alert logs | Report accurately reflects all alert statuses including sent, delivered, failed, acknowledged, and unacknowledged alerts with correct timestamps and user information |

**Postconditions:**
- All alert deliveries are logged with complete metadata
- User acknowledgments are tracked and associated with correct alerts
- Alert status is updated to acknowledged in the system
- Reports accurately reflect current alert delivery and acknowledgment metrics
- Audit trail is maintained for compliance and accountability

---

## Story: As Scheduler, I want to acknowledge and track alerts for scheduling conflicts to ensure accountability and follow-up
**Story ID:** story-15

### Test Case: Validate alert acknowledgment process
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged into the scheduling system with valid scheduler credentials
- A conflict alert has been generated and delivered to the user
- Alert is visible in user's notification interface
- POST /api/alerts/{id}/acknowledge endpoint is functional
- User has authorization to acknowledge alerts
- System clock is synchronized for accurate timestamp recording

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the notification center or alert inbox where conflict alerts are displayed | Alert is displayed to user with conflict details, timestamp, and unacknowledged status indicator |
| 2 | Click on the alert to view full details including conflict information, affected resources, and time slots | Alert details panel opens showing comprehensive conflict information and an 'Acknowledge' button or checkbox |
| 3 | Click the 'Acknowledge' button to acknowledge the alert | Acknowledgment request is sent to the server via POST /api/alerts/{id}/acknowledge endpoint and processed within 1 second |
| 4 | Observe the UI response after acknowledgment | Success confirmation message is displayed, alert status changes to 'Acknowledged', and acknowledgment is recorded with current timestamp and user ID |
| 5 | Navigate to the alert logs or audit trail section and search for the acknowledged alert by alert ID | Alert log entry shows status as 'Acknowledged' with correct user name/ID and accurate acknowledgment timestamp |
| 6 | Verify the acknowledgment timestamp matches the time when the acknowledge action was performed | Timestamp in the log accurately reflects the acknowledgment time within 1 second accuracy |

**Postconditions:**
- Alert status is permanently updated to 'Acknowledged' in the database
- Acknowledgment record includes user ID, username, and precise timestamp
- Alert is marked as acknowledged in user's notification interface
- Acknowledgment data is available for reporting and analytics
- No further reminders will be sent for this acknowledged alert

---

### Test Case: Verify reminder notifications for unacknowledged alerts
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 35 mins

**Preconditions:**
- User is logged into the scheduling system
- Reminder notification feature is enabled in system configuration
- Reminder interval is configured (e.g., 30 minutes for unacknowledged alerts)
- User has valid notification channels configured
- System scheduler/cron job for reminder notifications is running
- At least one conflict alert exists in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Generate a new conflict alert by creating a scheduling conflict and ensure it is delivered to the user | Alert is generated and delivered successfully to user via configured channels with unacknowledged status |
| 2 | Verify the alert appears in the notification interface and note the delivery timestamp | Alert is visible in user's notification center with 'Unacknowledged' status and initial delivery timestamp |
| 3 | Do not acknowledge the alert and wait for the configured reminder interval to elapse (e.g., wait 30 minutes) | Alert remains in unacknowledged state throughout the waiting period |
| 4 | After the reminder interval has elapsed, check for reminder notification in configured channels | System automatically sends a reminder notification via the same channels as the original alert, indicating the alert is still unacknowledged and requires attention |
| 5 | Verify the reminder notification content and metadata | Reminder notification includes original conflict details, time elapsed since first alert, and clear indication that this is a reminder for an unacknowledged alert |
| 6 | Open the alert from the reminder notification and click 'Acknowledge' | Acknowledgment is processed successfully and recorded with user ID and timestamp |
| 7 | Wait for another reminder interval period to verify reminders have stopped | No additional reminder notifications are sent after the alert has been acknowledged, confirming reminders stop upon acknowledgment |
| 8 | Check the alert logs to verify reminder delivery and acknowledgment sequence | Logs show initial alert delivery, reminder notification delivery, and final acknowledgment with all timestamps and status transitions accurately recorded |

**Postconditions:**
- Alert is acknowledged and status is updated in the system
- Reminder notifications are stopped for the acknowledged alert
- All reminder attempts are logged with timestamps
- Alert acknowledgment is recorded with final user and timestamp
- System continues to monitor other unacknowledged alerts for reminder triggers

---

