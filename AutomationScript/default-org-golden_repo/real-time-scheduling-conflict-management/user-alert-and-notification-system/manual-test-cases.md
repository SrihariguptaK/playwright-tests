# Manual Test Cases

## Story: As Scheduler, I want to receive notifications via email for scheduling conflicts to stay informed when away from the system
**Story ID:** story-3

### Test Case: Verify email notification is sent upon conflict detection
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User account exists in the system with valid email address
- User has scheduler role permissions
- Email notification preferences are enabled in user settings
- SMTP service is configured and operational
- Test email inbox is accessible for verification

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into the system with scheduler credentials | User successfully logs in and dashboard is displayed |
| 2 | Navigate to user profile settings and locate email notification preferences section | Email notification preferences page is displayed with available options |
| 3 | Enable email notifications for scheduling conflicts and enter valid email address | Email notification preference is enabled and email address is saved |
| 4 | Click Save or Update button to save preferences | Success message is displayed confirming preferences saved successfully |
| 5 | Navigate to scheduling module and create a new schedule entry for a specific resource and time slot | First schedule entry is created successfully |
| 6 | Create a second schedule entry that conflicts with the first entry (same resource and overlapping time) | Scheduling conflict is detected by the system and conflict detection process is triggered |
| 7 | Wait for email notification to be sent and check the configured email inbox | Email notification is received in the inbox with subject line indicating scheduling conflict |
| 8 | Open the email and review the content for conflict details | Email contains accurate conflict details including resource name, conflicting time slots, schedule IDs, and timestamp of conflict detection |

**Postconditions:**
- Email notification is successfully delivered to user inbox
- Email delivery status is logged in system
- User preferences remain enabled for future conflicts
- Scheduling conflict remains in the system for resolution

---

### Test Case: Validate email delivery status tracking
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User account exists with valid email address configured
- Email notification preferences are enabled
- SMTP service is operational
- System has access to email delivery logs
- User has permissions to view delivery status logs

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into the system with administrator or scheduler credentials | User successfully logs in to the system |
| 2 | Navigate to scheduling module and trigger a scheduling conflict by creating overlapping schedule entries | Scheduling conflict is detected and email notification process is initiated |
| 3 | Navigate to system administration or notification logs section | Notification logs page is displayed with list of sent notifications |
| 4 | Locate the test email notification entry in the logs by timestamp or recipient email | Email notification entry is found in the logs |
| 5 | Review the delivery status field for the email notification | Delivery status is logged with one of the following states: Sent, Delivered, Failed, or Pending |
| 6 | Verify that timestamp of email send attempt is recorded | Timestamp is logged showing when email was sent |
| 7 | Check for additional tracking information such as recipient email, subject, and delivery confirmation | All relevant delivery information is logged including recipient, subject line, and delivery confirmation status |

**Postconditions:**
- Email delivery status is accurately logged in system database
- Delivery logs are accessible for audit purposes
- System maintains complete tracking history of email notifications

---

### Test Case: Ensure email is sent within 5 minutes of conflict detection
- **ID:** tc-003
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User account exists with valid email address
- Email notification preferences are enabled
- SMTP service is operational with normal latency
- System clock is synchronized and accurate
- Test environment has access to timestamp logs

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into the system and navigate to scheduling module | User is logged in and scheduling module is displayed |
| 2 | Note the current system time before triggering conflict | Current timestamp is recorded for reference |
| 3 | Create a scheduling conflict by adding overlapping schedule entries for the same resource | Scheduling conflict is detected and conflict detection timestamp is logged |
| 4 | Record the exact timestamp when conflict detection occurs from system logs | Conflict detection timestamp is captured (T1) |
| 5 | Monitor email inbox for incoming notification | Email notification arrives in inbox |
| 6 | Check the received timestamp of the email in inbox | Email received timestamp is captured (T2) |
| 7 | Calculate the time difference between conflict detection (T1) and email received time (T2) | Time difference is calculated in minutes |
| 8 | Verify that the time difference is less than or equal to 5 minutes | Email is received within 5 minutes of conflict detection, meeting the performance requirement |

**Postconditions:**
- Email delivery time is within acceptable performance threshold
- Timestamps are logged for performance monitoring
- System meets the 5-minute SLA requirement for email notifications

---

## Story: As Scheduler, I want to acknowledge or dismiss conflict alerts to manage my scheduling workflow effectively
**Story ID:** story-4

### Test Case: Verify user can acknowledge conflict alerts
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User has scheduler role with appropriate permissions
- User is logged into the system
- At least one active conflict alert exists in the system
- Alert acknowledgment feature is enabled
- Database is accessible for persistence verification

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into the system with scheduler credentials | User successfully logs in and dashboard is displayed |
| 2 | Navigate to the alerts or notifications section of the application | Alerts page is displayed showing list of active conflict alerts |
| 3 | Verify that a conflict alert is displayed in the UI with details about the scheduling conflict | Conflict alert is visible showing resource name, time slot, and conflict details |
| 4 | Locate the acknowledge button or action associated with the conflict alert | Acknowledge button is visible and enabled for the alert |
| 5 | Click the acknowledge button for the conflict alert | System processes the acknowledgment request immediately |
| 6 | Observe the UI update after clicking acknowledge | Alert status updates to 'Acknowledged' and UI reflects the change with visual indicator (e.g., different color, icon, or label) |
| 7 | Verify that the acknowledged alert remains visible but is marked as acknowledged | Alert is still displayed in the list but clearly marked with acknowledged status |
| 8 | Refresh the browser or reload the alert list page | Page reloads successfully |
| 9 | Locate the previously acknowledged alert in the refreshed list | Acknowledged alert status is persisted and still shows as 'Acknowledged' after page reload |

**Postconditions:**
- Alert status is updated to 'Acknowledged' in the database
- Alert acknowledgment is persisted across sessions
- Alert remains in the system for audit trail purposes
- User action is logged with timestamp and user ID

---

### Test Case: Verify user can dismiss conflict alerts
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User has scheduler role with appropriate permissions
- User is logged into the system
- At least one active conflict alert exists in the system
- Alert dismissal feature is enabled
- Database is accessible for persistence verification

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into the system with scheduler credentials | User successfully logs in and dashboard is displayed |
| 2 | Navigate to the alerts or notifications section of the application | Alerts page is displayed showing list of active conflict alerts |
| 3 | Verify that a conflict alert is displayed in the UI with full conflict details | Conflict alert is visible in the active alerts list |
| 4 | Locate the dismiss button or action associated with the conflict alert | Dismiss button is visible and enabled for the alert |
| 5 | Click the dismiss button for the conflict alert | System processes the dismissal request immediately |
| 6 | Observe the UI update after clicking dismiss | Alert is removed from the active alerts view with smooth transition or animation |
| 7 | Verify that the dismissed alert is no longer visible in the active alerts list | Alert is completely removed from active alerts display |
| 8 | Refresh the browser or reload the alert list page | Page reloads successfully |
| 9 | Check the active alerts list for the previously dismissed alert | Dismissed alert is not shown in active alerts list, confirming dismissal is persisted |
| 10 | Navigate to alert history or archived alerts section if available | Dismissed alert can be found in history/archive with 'Dismissed' status for audit purposes |

**Postconditions:**
- Alert is removed from active alerts view
- Alert status is updated to 'Dismissed' in the database
- Dismissal action is persisted across sessions
- Alert is moved to history or archived state
- User action is logged with timestamp and user ID

---

### Test Case: Ensure only authorized users can change alert status
- **ID:** tc-006
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- System has role-based access control configured
- At least one active conflict alert exists in the system
- Test user account exists without scheduler permissions
- Authorization rules are properly configured for alert actions
- Error handling is implemented for unauthorized access

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into the system with a user account that does not have scheduler or alert management permissions (e.g., read-only user or viewer role) | User successfully logs in with limited permissions |
| 2 | Navigate to the alerts or notifications section of the application | Alerts page is displayed, but action buttons may be disabled or hidden |
| 3 | Locate a conflict alert in the list and check for acknowledge or dismiss buttons | Acknowledge and dismiss buttons are either not visible or appear disabled for unauthorized user |
| 4 | Attempt to click the acknowledge button if visible | Action is blocked and error message is displayed indicating insufficient permissions |
| 5 | Verify the error message content | Error message clearly states 'You do not have permission to acknowledge alerts' or similar authorization error |
| 6 | Attempt to click the dismiss button if visible | Action is blocked and error message is displayed indicating insufficient permissions |
| 7 | Verify the error message content for dismiss action | Error message clearly states 'You do not have permission to dismiss alerts' or similar authorization error |
| 8 | Check the alert status in the system | Alert status remains unchanged and no modifications were made |
| 9 | Attempt to make direct API call to PATCH /alerts/{id}/status endpoint using unauthorized user credentials | API returns 403 Forbidden or 401 Unauthorized status code with appropriate error message |
| 10 | Verify that the unauthorized action attempt is logged in security audit logs | Security log contains entry showing unauthorized access attempt with user ID, timestamp, and action attempted |

**Postconditions:**
- Alert status remains unchanged
- No unauthorized modifications are made to the database
- Security audit log contains record of unauthorized attempt
- System maintains data integrity and security
- User receives clear feedback about permission denial

---

## Story: As Scheduler, I want to receive SMS notifications for critical scheduling conflicts to ensure timely awareness
**Story ID:** story-7

### Test Case: Verify SMS notification is sent for critical conflicts
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User account is active and has Scheduler role
- User has a valid phone number registered in the system
- SMS gateway integration is configured and operational
- User is logged into the scheduling system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to user profile settings and access SMS notification preferences section | SMS notification preferences page is displayed with options to enable/disable SMS alerts for critical conflicts |
| 2 | Enable SMS notifications for critical scheduling conflicts and enter valid phone number in international format | Phone number is validated and accepted, SMS preferences are saved successfully with confirmation message displayed |
| 3 | Create a scheduling entry that triggers a critical conflict (e.g., double-booking a resource, overlapping time slots for same personnel) | System detects the critical scheduling conflict and initiates SMS notification process |
| 4 | Check the registered mobile phone SMS inbox within 3 minutes of conflict creation | SMS notification is received containing conflict type, affected resources/personnel, date/time of conflict, and brief description of the issue |
| 5 | Verify SMS message content includes all critical conflict details: conflict ID, schedule names, time overlap, and severity level | SMS contains accurate and complete conflict information matching the detected conflict in the system |

**Postconditions:**
- SMS notification is successfully delivered to user's phone
- Delivery status is logged in the system
- User is aware of the critical conflict
- Conflict remains active in the system until resolved

---

### Test Case: Validate SMS delivery tracking
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User account has SMS notifications enabled
- Valid phone number is configured in user preferences
- SMS gateway is operational and connected
- System has logging mechanism enabled for SMS delivery tracking
- User has appropriate permissions to view delivery logs

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to SMS notification settings and initiate a test SMS notification for critical conflict scenario | Test SMS notification is queued for sending and system generates a unique tracking ID |
| 2 | Monitor the SMS gateway response and capture the delivery status callback | SMS gateway returns delivery status (sent, delivered, or failed) with timestamp |
| 3 | Access the SMS delivery logs section in the admin or user dashboard | Delivery logs page displays with search and filter options |
| 4 | Search for the test SMS notification using tracking ID or phone number | Log entry is found showing SMS details including: recipient phone number, timestamp, delivery status, gateway response code, and message content summary |
| 5 | Verify that delivery status is accurately logged with complete metadata (sent time, delivered time, status code) | All delivery information is correctly logged and matches the actual SMS delivery status from the gateway |

**Postconditions:**
- SMS delivery status is permanently logged in the system database
- Delivery tracking information is accessible for audit purposes
- System maintains complete delivery history
- Delivery metrics are updated for reporting

---

### Test Case: Ensure SMS sent within 3 minutes of conflict detection
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User has SMS notifications enabled with valid phone number
- SMS gateway is operational with normal response times
- System clock is synchronized with accurate time source
- Conflict detection engine is running and monitoring schedules
- Test environment has timing measurement tools available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Record the current system timestamp before creating the conflict scenario | Baseline timestamp is captured for performance measurement |
| 2 | Create a critical scheduling conflict by double-booking a resource or creating overlapping schedule entries | Conflict is detected by the system and conflict detection timestamp is logged |
| 3 | Monitor the SMS gateway logs and system notification queue for SMS processing | SMS notification is queued and sent to the gateway within seconds of conflict detection |
| 4 | Check mobile phone SMS inbox and note the time when SMS is received | SMS notification is received on the mobile device |
| 5 | Calculate the total elapsed time from conflict detection timestamp to SMS receipt timestamp | Total time elapsed is less than or equal to 3 minutes (180 seconds), meeting the performance requirement |
| 6 | Review system logs to verify each stage timing: detection time, queue time, gateway submission time, and delivery time | All timing logs confirm that SMS was processed and delivered within the 3-minute SLA |

**Postconditions:**
- SMS delivery time is logged and meets performance criteria
- Performance metrics are updated in the system
- User received timely notification of critical conflict
- System demonstrates compliance with 3-minute delivery requirement

---

## Story: As Scheduler, I want to receive in-app notifications for scheduling conflicts to get immediate feedback while working
**Story ID:** story-9

### Test Case: Validate real-time in-app notification delivery
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged into the scheduling application with active session
- User has Scheduler role with appropriate permissions
- WebSocket or push notification service is active and connected
- Browser/application has notification permissions enabled
- Conflict detection engine is running

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Verify user is logged in and the application dashboard is displayed with active connection indicator | User session is active, dashboard is loaded, and real-time connection status shows as connected |
| 2 | Create a scheduling conflict by adding an overlapping appointment or double-booking a resource while remaining on the current page | Scheduling conflict is created and saved in the system, triggering the conflict detection engine |
| 3 | Observe the application interface for in-app notification appearance without refreshing the page | In-app notification appears immediately (within 1 second) in the notification area, displaying conflict alert with visual indicator (badge, popup, or banner) |
| 4 | Click on the in-app notification to expand and read the full conflict details | Notification expands showing complete conflict information including: conflict type, affected schedules, resources involved, time overlap details, and severity level |
| 5 | Click the 'Acknowledge' button or action within the notification | Notification status updates to 'Acknowledged', visual indicator changes (e.g., color or icon), and notification smoothly disappears from the active notification list |
| 6 | Verify the notification is moved to notification history or acknowledged items section | Acknowledged notification is accessible in history with timestamp and acknowledgment status recorded |

**Postconditions:**
- User is aware of the scheduling conflict
- Notification status is updated to acknowledged in the database
- Notification is removed from active notifications list
- User action is logged for audit trail
- Conflict remains in the system until resolved

---

### Test Case: Verify notification persistence until addressed
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 9 mins

**Preconditions:**
- User is logged into the scheduling application
- In-app notification system is operational
- User has at least one active scheduling conflict that triggers notification
- Notification persistence mechanism is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Trigger a scheduling conflict to generate an in-app notification | In-app notification appears displaying the conflict details with actionable buttons |
| 2 | View the notification but do not click any action buttons (acknowledge or resolve), then navigate to a different page within the application | Notification remains visible in the notification center or panel, showing unread/unacknowledged status with visual indicator (e.g., red badge, bold text) |
| 3 | Log out of the application and then log back in with the same user credentials | After successful login, the unacknowledged notification reappears in the notification center, maintaining its unread status |
| 4 | Verify notification counter shows the correct number of pending notifications and notification remains accessible | Notification counter displays accurate count, notification is visible and accessible with all original details intact |
| 5 | Click the 'Acknowledge' button on the persistent notification | Notification status changes to acknowledged, visual indicators update (badge count decreases, notification styling changes) |
| 6 | Verify the notification is removed from the active notifications list | Notification disappears from the main notification area and is moved to acknowledged/history section, notification counter decrements by one |
| 7 | Refresh the page or navigate to another section and return to verify notification does not reappear | Acknowledged notification does not reappear in active notifications, remains only in history section |

**Postconditions:**
- Notification persistence is verified across sessions and page navigation
- Acknowledged notification is permanently removed from active list
- Notification status is correctly maintained in the database
- User cannot miss important conflict notifications

---

### Test Case: Ensure only authenticated users receive relevant notifications
- **ID:** tc-006
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Multiple user accounts exist with different roles and schedule assignments
- At least two test users: User A (authorized for Schedule X) and User B (not authorized for Schedule X)
- Scheduling conflicts exist or can be created for specific schedules
- Authentication and authorization system is properly configured
- In-app notification system is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in to the application as User A who is assigned to and has permissions for Schedule X | User A successfully logs in and dashboard displays with schedules they are authorized to access |
| 2 | Create a scheduling conflict in Schedule X that User A is responsible for or has access to | Scheduling conflict is created successfully in Schedule X |
| 3 | Observe the in-app notification area for User A | User A receives an in-app notification about the conflict in Schedule X, notification contains relevant conflict details specific to their schedule |
| 4 | Verify notification details match User A's schedule assignments and permissions | Notification content is relevant to User A's responsibilities, showing only schedules and resources they have access to |
| 5 | Log out as User A and log in as User B who does not have access to Schedule X | User B successfully logs in and dashboard displays only their authorized schedules (not including Schedule X) |
| 6 | Check the in-app notification center for User B | User B does not receive any notification about the conflict in Schedule X, notification center shows zero notifications or only notifications relevant to User B's schedules |
| 7 | Create a new conflict in a schedule that User B is authorized to access | User B receives an in-app notification for the conflict in their authorized schedule, confirming they receive only relevant notifications |
| 8 | Verify that User B's notification does not contain any information about Schedule X or other unauthorized schedules | User B's notification contains only information about schedules they are authorized to access, no data leakage from unauthorized schedules |

**Postconditions:**
- Authentication and authorization rules are properly enforced for notifications
- Users receive only notifications relevant to their assigned schedules
- No unauthorized access to schedule information through notifications
- System maintains data privacy and security compliance
- Notification filtering by user permissions is verified

---

