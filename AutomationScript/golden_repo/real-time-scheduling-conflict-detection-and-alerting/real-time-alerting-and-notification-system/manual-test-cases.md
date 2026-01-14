# Manual Test Cases

## Story: As Scheduler, I want to receive real-time alerts for scheduling conflicts to avoid double bookings
**Story ID:** story-11

### Test Case: Validate alert sent within 5 seconds of conflict detection
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Scheduler user account is active and logged into the system
- At least one existing booking is present in the system
- Alert notification system is operational
- Scheduler has valid notification channels configured (email/SMS/in-app)
- System clock is synchronized for accurate timing measurements

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Create a new booking that conflicts with an existing booking by selecting the same resource and overlapping time slot | System detects the scheduling conflict and triggers the conflict detection engine within 2 seconds |
| 2 | Start timer and monitor the configured notification channel (email/SMS/in-app) for alert delivery | Alert notification is received by the scheduler within 5 seconds of conflict detection |
| 3 | Open and review the received alert notification content | Alert contains complete conflict information including: conflicting booking IDs, resource names, overlapping time slots, affected parties, and conflict severity level |

**Postconditions:**
- Alert delivery is logged in the system with timestamp
- Conflict status remains active until resolved
- Scheduler is aware of the conflict and can take corrective action

---

### Test Case: Verify alert preference configuration and delivery
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Scheduler user account is active and logged into the system
- Scheduler has access to alert preference settings
- Multiple notification channels are available (email, SMS, in-app)
- Valid email address and phone number are registered for the scheduler
- Test booking data exists to trigger conflicts

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to alert preferences settings and select 'Email only' as the notification channel, then save the configuration | System displays confirmation message 'Preferences saved successfully' and email is set as the sole notification channel |
| 2 | Create a conflicting booking to trigger the conflict detection system | Alert is sent exclusively via email channel; no SMS or in-app notifications are generated |
| 3 | Return to alert preferences settings, deselect email, and select both 'SMS' and 'In-app' notification channels, then save | System saves the updated preferences and confirms the change; subsequent alerts are delivered via both SMS and in-app notification channels only |
| 4 | Create another conflicting booking to verify the updated preferences | Alert notifications are received via SMS and in-app channels; no email notification is sent |

**Postconditions:**
- Alert preferences are persisted in the user profile
- All future alerts respect the updated channel preferences
- Preference change history is logged in the system

---

### Test Case: Ensure system retries failed alert deliveries
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Scheduler user account is active with email notification enabled
- System has retry mechanism configured for failed notifications
- Ability to simulate email delivery failure in test environment
- Alert delivery logging is enabled
- Test booking data exists to trigger conflicts

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Configure test environment to simulate email server failure or network timeout for the scheduler's email address | Email delivery service is set to fail on first attempt |
| 2 | Create a conflicting booking to trigger alert generation and monitor the initial delivery attempt | System attempts to send alert via email and receives delivery failure response; alert status is marked as 'Failed' in logs |
| 3 | Restore email delivery service to normal operation and wait for the system's automatic retry mechanism to execute | System automatically retries sending the alert according to retry policy; alert is successfully delivered on retry attempt |
| 4 | Access the alert delivery logs and review the complete delivery history for this alert | Logs show initial failed attempt with timestamp and error details, followed by successful retry attempt with delivery confirmation and timestamps for both attempts |

**Postconditions:**
- Alert is successfully delivered to scheduler
- Complete delivery history including failures and retries is logged
- System retry mechanism is confirmed operational
- Scheduler receives the conflict notification despite initial failure

---

## Story: As Scheduler, I want to receive alerts only for conflicts relevant to my assigned resources to reduce noise
**Story ID:** story-16

### Test Case: Verify alert filtering by assigned resources
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Scheduler user account is active and logged into the system
- Multiple resources exist in the system (both assigned and unassigned to the scheduler)
- Scheduler has permission to view and update resource assignments
- Alert notification system is operational
- Test booking data exists for multiple resources

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to resource assignment settings and assign specific resources (e.g., Conference Room A, Projector 1) to the scheduler, then save the assignments | System displays confirmation message 'Assignments saved successfully' and the assigned resources are visible in the scheduler's resource list |
| 2 | Create multiple conflicting bookings: one involving an assigned resource (Conference Room A) and another involving an unassigned resource (Conference Room B) | Scheduler receives alert notification only for the conflict involving Conference Room A (assigned resource); no alert is received for Conference Room B conflict |
| 3 | Verify the received alert content to confirm it relates only to assigned resources | Alert details show only conflicts for Conference Room A and contains no information about Conference Room B |
| 4 | Update resource assignments by adding Conference Room B and removing Conference Room A from the scheduler's assigned resources, then save | System confirms 'Assignments updated successfully' and the resource list reflects the changes immediately |
| 5 | Create new conflicting bookings for both Conference Room A and Conference Room B | Scheduler now receives alerts only for Conference Room B conflicts and does not receive alerts for Conference Room A conflicts, confirming alert filtering updates accordingly |

**Postconditions:**
- Resource assignments are updated and persisted in the system
- Alert filtering reflects current resource assignments
- Scheduler receives only relevant alerts based on updated assignments
- Assignment change history is logged

---

### Test Case: Test override of filtering for critical alerts
- **ID:** tc-005
- **Type:** edge-case
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Scheduler user account is active with specific resource assignments configured
- Critical alert override functionality is enabled in the system
- Scheduler has resources assigned that do not include all system resources
- System can identify and flag critical conflicts
- Alert notification channels are operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Verify scheduler's current resource assignments and identify a resource not assigned to the scheduler (e.g., Emergency Equipment) | Scheduler's assignment list is confirmed and does not include Emergency Equipment |
| 2 | Create a critical conflict involving the unassigned resource (Emergency Equipment) by marking it as high priority or critical severity in the system | System detects the critical conflict and triggers alert generation with override flag, bypassing normal filtering rules |
| 3 | Monitor notification channels for alert delivery | Scheduler receives the alert notification despite Emergency Equipment not being in their assigned resources list, confirming override functionality |
| 4 | Open and review the alert notification content and metadata | Alert is clearly marked with 'CRITICAL' or 'OVERRIDE' indicator and includes explanation text such as 'This alert was sent due to critical priority, overriding your resource filter settings' |

**Postconditions:**
- Critical alert is successfully delivered despite filtering
- Override event is logged in the system
- Scheduler is aware of the critical conflict and the reason for receiving the alert
- Normal filtering rules remain active for non-critical alerts

---

## Story: As Scheduler, I want the system to support multiple alert channels including email, SMS, and in-app notifications to ensure timely awareness
**Story ID:** story-18

### Test Case: Validate multi-channel alert delivery
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User has a valid scheduler account with active status
- User has verified email address and phone number registered in the system
- Alert preferences page is accessible
- Email, SMS, and in-app notification services are operational
- Test conflict scenario is prepared in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to user profile settings and access alert preferences section | Alert preferences page loads successfully displaying all available notification channels (email, SMS, in-app) |
| 2 | Select email checkbox and enter/verify email address | Email channel is enabled and email address is validated and saved |
| 3 | Select SMS checkbox and enter/verify phone number | SMS channel is enabled and phone number is validated and saved |
| 4 | Select in-app notification checkbox | In-app notification channel is enabled and preference is saved |
| 5 | Click 'Save Preferences' button | Success message displayed confirming preferences saved successfully for all three channels |
| 6 | Trigger conflict detection by creating a scheduling conflict in the system | System detects the conflict and initiates alert generation process |
| 7 | Check email inbox for alert notification | Email alert received within 5 seconds containing conflict details with proper formatting |
| 8 | Check mobile device for SMS notification | SMS alert received within 5 seconds containing conflict summary with proper formatting |
| 9 | Check in-app notification center within the application | In-app notification appears within 5 seconds displaying conflict information with actionable links |
| 10 | Verify timestamp consistency across all three channels | All alerts show consistent timestamp and conflict information across email, SMS, and in-app channels |

**Postconditions:**
- User preferences remain saved in the system
- All three alert channels show successful delivery status in logs
- Conflict alert is marked as delivered in the system
- User can view alert history for all channels

---

### Test Case: Test alert delivery retry on failure
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User has valid scheduler account with SMS alert preference enabled
- User has verified phone number registered in the system
- SMS service is accessible for testing
- Test environment allows simulation of SMS delivery failures
- Delivery logs are accessible for verification
- Retry policy is configured in the system (e.g., 3 retry attempts with 30-second intervals)

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Configure test environment to simulate SMS delivery failure for the next alert | SMS service mock/simulator is set to return failure status for initial delivery attempt |
| 2 | Trigger conflict detection to generate an alert | System detects conflict and initiates alert sending process |
| 3 | Monitor initial SMS delivery attempt | Initial SMS delivery fails with error status recorded in system logs |
| 4 | Access delivery logs and verify failure is recorded | Delivery log shows failed attempt with timestamp, error code, and channel (SMS) clearly documented |
| 5 | Remove SMS delivery failure simulation to allow successful delivery | SMS service is restored to normal operational state |
| 6 | Wait for system to automatically retry SMS delivery according to retry policy | System initiates retry attempt within configured interval (e.g., 30 seconds) |
| 7 | Verify SMS alert is received on mobile device | SMS alert delivered successfully on retry attempt with correct conflict information |
| 8 | Access delivery logs and check retry attempts | Delivery logs show initial failure followed by successful retry with timestamps, attempt numbers, and final success status |
| 9 | Verify delivery status in alert dashboard | Alert dashboard displays final status as 'Delivered' with retry count and delivery timeline visible |

**Postconditions:**
- SMS alert successfully delivered to user
- Complete delivery history logged including failure and retry
- Alert marked as delivered in the system
- SMS service restored to normal operation
- Retry mechanism validated as functional

---

## Story: As Scheduler, I want the system to track alert delivery status and retry failed notifications to ensure reliable communication
**Story ID:** story-20

### Test Case: Verify delivery status tracking and retry mechanism
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- User has valid scheduler account with multiple alert channels configured
- Alert delivery dashboard is accessible
- Test environment supports simulation of delivery failures
- Delivery logging system is operational
- Retry policy is configured with specific intervals and maximum attempts
- Administrator or scheduler has appropriate permissions to view delivery logs

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Configure test environment to simulate delivery failures for specific channels (e.g., email and SMS) | Test environment is set to return failure status for designated alert channels |
| 2 | Trigger conflict detection to generate alerts across multiple channels | System generates alerts and attempts delivery via email, SMS, and in-app channels |
| 3 | Monitor initial delivery attempts for all channels | Email and SMS deliveries fail as simulated; in-app notification succeeds |
| 4 | Access delivery logs via GET /api/alert-delivery-status endpoint | Delivery logs display all attempts with status: email (failed), SMS (failed), in-app (success) with timestamps and error details |
| 5 | Verify failure details are recorded accurately in logs | Each failed delivery shows channel name, timestamp, error code, alert ID, and user ID |
| 6 | Remove delivery failure simulation to allow successful retries | Email and SMS services restored to operational state |
| 7 | Wait for automatic retry according to configured retry policy | System initiates retry attempts for failed email and SMS deliveries within configured interval |
| 8 | Verify alerts are delivered successfully on retry | Email and SMS alerts delivered successfully; user receives notifications on both channels |
| 9 | Access delivery logs again to verify retry attempts | Logs show complete history: initial failures, retry attempts with timestamps, and final success status for each channel |
| 10 | Navigate to delivery status dashboard | Dashboard loads successfully displaying alert delivery statistics and status |
| 11 | Locate the specific alert in the dashboard | Alert is displayed with complete delivery information for all channels |
| 12 | Verify accuracy of status and retry attempts displayed | Dashboard shows accurate status (Delivered), retry count per channel, delivery timeline, and success rate matching the logs |
| 13 | Check dashboard filters and sorting options | Dashboard allows filtering by status, channel, date range, and sorting by various parameters |

**Postconditions:**
- All alerts successfully delivered after retries
- Complete delivery history logged for audit purposes
- Dashboard reflects accurate delivery status
- Test environment restored to normal state
- Retry mechanism validated as functional across all channels

---

### Test Case: Test administrator notifications on persistent failures
- **ID:** tc-004
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- Administrator account is configured with valid contact information
- Administrator notification preferences are enabled
- Test environment supports simulation of persistent delivery failures
- Retry policy is configured with maximum retry attempts (e.g., 3 attempts)
- Alert system is operational
- Administrator has access to notification channels (email/in-app)

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Configure test environment to simulate persistent SMS delivery failures that exceed retry limit | SMS service mock is set to continuously return failure status for all retry attempts |
| 2 | Trigger conflict detection to generate an alert for a scheduler user | System generates alert and attempts delivery via configured channels including SMS |
| 3 | Monitor initial SMS delivery attempt | Initial SMS delivery fails and is logged with failure status |
| 4 | Wait for first automatic retry attempt | System retries SMS delivery after configured interval; retry fails and is logged |
| 5 | Wait for second automatic retry attempt | System retries SMS delivery again; retry fails and is logged |
| 6 | Wait for third automatic retry attempt (final retry per policy) | System performs final retry; retry fails and maximum retry limit is reached |
| 7 | Verify system flags the alert as persistently failed | Alert status updated to 'Persistent Failure' in delivery logs with all retry attempts documented |
| 8 | Check if administrator notification is triggered | System generates and sends notification to administrators about persistent delivery failure |
| 9 | Access administrator email inbox | Administrator receives email notification within 5 seconds containing failure details: alert ID, user affected, channel failed (SMS), retry attempts, and timestamp |
| 10 | Check administrator in-app notification center | Administrator receives in-app notification with persistent failure alert including actionable information and links to delivery dashboard |
| 11 | Verify notification content includes all necessary details | Notification contains: affected user ID, alert type, failed channel, number of retry attempts, error codes, and recommended actions |
| 12 | Access delivery status dashboard as administrator | Dashboard displays the persistent failure prominently with visual indicator (e.g., red flag or alert icon) |
| 13 | Verify persistent failure is logged comprehensively | Complete log entry shows all delivery attempts, timestamps, error codes, retry history, and final persistent failure status |

**Postconditions:**
- Persistent failure is flagged in the system
- Administrator is notified via all configured channels
- Complete failure history is logged for investigation
- Alert remains in failed state pending administrator action
- Test environment can be restored to normal operation

---

