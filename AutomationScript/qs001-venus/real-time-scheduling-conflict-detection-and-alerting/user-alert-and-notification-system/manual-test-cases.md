# Manual Test Cases

## Story: As Scheduler, I want to receive real-time pop-up alerts for scheduling conflicts to act immediately
**Story ID:** story-3

### Test Case: Verify pop-up alert displays on conflict detection
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- User is logged into the scheduling system with Scheduler role
- Pop-up alerts are enabled in user preferences
- Conflict detection engine is active and running
- At least one existing schedule entry exists in the system
- User has necessary permissions to create/modify schedules

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the scheduling interface | Scheduling interface loads successfully with input fields visible |
| 2 | Enter scheduling data that causes a conflict with an existing schedule (e.g., same resource, overlapping time) | Pop-up alert appears on screen within 1 second of entering the conflicting data |
| 3 | Read the alert details displayed in the pop-up | Alert shows accurate conflict information including conflicting items, times, resources, and clear description of the conflict |
| 4 | Click the acknowledge button on the pop-up alert | Alert is dismissed from the screen and acknowledgment is recorded in the system |
| 5 | Verify acknowledgment was recorded by checking system logs or audit trail | System logs show the alert acknowledgment with timestamp and user information |

**Postconditions:**
- Pop-up alert is no longer visible on screen
- Alert acknowledgment is recorded in system database
- User remains on the scheduling interface
- Conflicting schedule data is not saved until resolved

---

### Test Case: Test alert preference configuration
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged into the scheduling system with Scheduler role
- User has access to settings/preferences page
- Pop-up alerts are currently enabled by default
- At least one existing schedule entry exists to create conflicts
- User preferences are stored and retrievable from database

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to user settings or preferences page | Settings page loads successfully with alert preferences section visible |
| 2 | Locate the pop-up alert configuration option | Pop-up alert toggle or checkbox is visible and currently enabled |
| 3 | Disable pop-up alerts by toggling off or unchecking the option | Setting is updated and confirmation message appears indicating pop-up alerts are disabled |
| 4 | Save the preference changes | Settings are saved successfully with confirmation message |
| 5 | Navigate to scheduling interface and enter scheduling data causing a conflict | No pop-up alert appears on screen despite the conflict being detected |
| 6 | Return to user settings and enable pop-up alerts by toggling on or checking the option | Setting is updated and confirmation message appears indicating pop-up alerts are enabled |
| 7 | Save the preference changes | Settings are saved successfully with confirmation message |
| 8 | Navigate to scheduling interface and enter scheduling data causing a conflict | Pop-up alert appears on screen within 1 second displaying conflict details |

**Postconditions:**
- Pop-up alerts are enabled in user preferences
- User preference settings are persisted in database
- Alert behavior matches the configured preference
- User remains logged into the system

---

## Story: As Scheduler, I want to receive email notifications for scheduling conflicts to stay informed when away from system
**Story ID:** story-4

### Test Case: Verify email notification sent on conflict detection
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is registered in the system with valid email address
- Email notifications are enabled in user preferences
- SMTP or email service is configured and operational
- Conflict detection engine is active and running
- At least one existing schedule entry exists in the system
- Email delivery logging is enabled
- Test email inbox is accessible for verification

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Note the current timestamp before triggering the conflict | Timestamp is recorded for measuring email delivery time |
| 2 | Trigger a scheduling conflict in the system by creating or modifying a schedule that conflicts with an existing entry | Conflict is detected by the system and conflict detection logs show the event |
| 3 | Wait and monitor for email notification delivery | Email notification is sent within 30 seconds of conflict detection |
| 4 | Check the recipient's email inbox for the notification | Email is received in inbox with subject line indicating scheduling conflict |
| 5 | Open and read the email content | Email contains accurate conflict details including conflicting items, times, resources, and affected schedules |
| 6 | Review email delivery logs in the system | Delivery status is logged as successful with timestamp, recipient email, and delivery confirmation |
| 7 | Verify the email delivery time from logs | Email was sent within 30 seconds of the conflict detection timestamp |

**Postconditions:**
- Email notification is successfully delivered to recipient
- Email delivery is logged with successful status
- Conflict remains in system until resolved
- Email service remains operational for future notifications

---

### Test Case: Test email notification preference settings
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged into the scheduling system with Scheduler role
- User has access to settings/preferences page
- Email notifications are currently enabled by default
- User has valid email address registered in system
- At least one existing schedule entry exists to create conflicts
- Email service is configured and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to user settings or preferences page | Settings page loads successfully with notification preferences section visible |
| 2 | Locate the email notification configuration option | Email notification toggle or checkbox is visible and currently enabled |
| 3 | Disable email notifications by toggling off or unchecking the option | Setting is updated and confirmation message appears indicating email notifications are disabled |
| 4 | Save the preference changes | Settings are saved successfully with confirmation message |
| 5 | Trigger a scheduling conflict in the system | Conflict is detected by the system |
| 6 | Wait 60 seconds and check email inbox | No email notification is received in the inbox |
| 7 | Verify email delivery logs | No email delivery attempt is logged for this conflict |
| 8 | Return to user settings and enable email notifications by toggling on or checking the option | Setting is updated and confirmation message appears indicating email notifications are enabled |
| 9 | Save the preference changes | Settings are saved successfully with confirmation message |
| 10 | Trigger another scheduling conflict in the system | Conflict is detected by the system |
| 11 | Wait up to 30 seconds and check email inbox | Email notification is received in inbox with conflict details |
| 12 | Verify email delivery logs | Email delivery is logged as successful for this conflict |

**Postconditions:**
- Email notifications are enabled in user preferences
- User preference settings are persisted in database
- Email notification behavior matches the configured preference
- User remains logged into the system
- Email service continues to function normally

---

## Story: As Scheduler, I want the system to log all scheduling conflicts and alerts for audit and analysis
**Story ID:** story-7

### Test Case: Verify logging of scheduling conflicts
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Scheduler role
- Logging system is operational and accessible
- Database has sufficient storage for logs
- At least two appointments exist that can create a conflict
- User has permissions to query system logs

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Create or trigger a scheduling conflict by attempting to book overlapping appointments for the same resource | System detects the scheduling conflict and prevents the double booking |
| 2 | Verify conflict details are logged with complete metadata including conflict type, timestamp, user ID, affected resources, and appointment IDs | Conflict is logged within 500 milliseconds with all required metadata fields populated accurately |
| 3 | Navigate to the system log query interface and search for the conflict entry using the timestamp or conflict ID | Log query returns results within 2 seconds |
| 4 | Review the retrieved log entry and verify all metadata fields match the triggered conflict details | Log entry is present, complete, and accurate with correct conflict type, time, user information, and affected resource details |

**Postconditions:**
- Conflict log entry is permanently stored in the database
- Log entry is retrievable for future audit purposes
- System remains in operational state
- No data loss occurred during logging operation

---

### Test Case: Verify logging of alerts and acknowledgments
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- User is logged in with Scheduler role
- Alert system is configured and operational
- Logging system is functional
- Test user account exists to receive alerts
- Unauthorized test account exists for access control testing
- A scheduling conflict scenario is ready to trigger

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Trigger a scheduling conflict that generates an alert to the designated user | System detects conflict and generates an alert notification |
| 2 | Verify the alert is sent to the user through the configured notification channel | Alert is successfully delivered to the user and alert delivery is logged with timestamp, recipient, and alert content |
| 3 | As the recipient user, acknowledge the received alert through the system interface | System registers the acknowledgment and displays confirmation to the user |
| 4 | Verify the user acknowledgment is logged with timestamp, user ID, and alert reference | Acknowledgment is logged within 500 milliseconds with complete metadata including acknowledgment time and user details |
| 5 | Query the logs to retrieve both the alert delivery and acknowledgment entries | Both log entries are present, accurate, and linked to the same alert event |
| 6 | Log out and log in as an unauthorized user without log access permissions | Unauthorized user successfully logs into the system |
| 7 | Attempt to access the system logs or query log entries as the unauthorized user | Access is denied with appropriate error message indicating insufficient permissions, and the access attempt is logged as a security event |

**Postconditions:**
- Alert delivery and acknowledgment are permanently logged
- Logs are securely stored with proper access controls enforced
- Unauthorized access attempt is logged for security audit
- System maintains log integrity and security
- All logging operations completed within performance requirements

---

## Story: As Scheduler, I want the system to provide detailed conflict information in alerts to understand and resolve issues quickly
**Story ID:** story-10

### Test Case: Verify detailed conflict information in alerts
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- User is logged in with Scheduler role
- Alert system is configured and operational
- Multiple appointments exist in the system that can create conflicts
- Resources are properly configured with names and availability
- System performance monitoring tools are available to measure alert generation time
- User has access to view scheduling details and navigate to conflicting schedules

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Create a scheduling scenario with multiple simultaneous conflicts by attempting to book three overlapping appointments for the same resource at the same time | System detects multiple scheduling conflicts simultaneously |
| 2 | Trigger the conflict detection and wait for the alert to be generated | Alert is generated and displayed to the user |
| 3 | Review the alert content and verify it includes full details of all conflicting appointments including appointment IDs, titles, times, and durations | Alert displays complete information for all three conflicting appointments with accurate details |
| 4 | Verify the alert includes resource names and time slots for each conflict | Alert shows the resource name and specific time slots for each conflicting appointment clearly |
| 5 | Identify and verify the presence of clickable links to each conflicting schedule in the alert | Alert contains distinct clickable links or buttons for each of the conflicting appointments |
| 6 | Click on the first link in the alert to navigate to the first conflicting schedule | System navigates to the correct schedule page showing the first conflicting appointment details |
| 7 | Return to the alert and click on the second link to navigate to the second conflicting schedule | System navigates to the correct schedule page showing the second conflicting appointment details |
| 8 | Return to the alert and click on the third link to navigate to the third conflicting schedule | System navigates to the correct schedule page showing the third conflicting appointment details |
| 9 | Using performance monitoring tools, measure the time elapsed between conflict detection and alert display | Alert generation and display completes within 1 second of conflict detection, meeting the performance requirement |
| 10 | Verify the alert remains accessible and all information is readable and properly formatted | Alert displays all conflict information in a clear, organized, and user-friendly format with no truncation or formatting errors |

**Postconditions:**
- Alert with detailed conflict information is logged in the system
- User has successfully navigated to all conflicting schedules
- Conflicts remain unresolved and available for user action
- System performance metrics confirm alert generation within 1 second
- Alert can be dismissed or remains available for future reference per system design

---

## Story: As Scheduler, I want to configure my alert preferences to receive notifications via preferred channels
**Story ID:** story-11

### Test Case: Verify alert preference configuration and application
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as Scheduler with valid credentials
- User has access to alert preference settings
- User profile database is accessible and operational
- At least one alert-triggering event is available for testing
- Default alert preferences are set (all channels enabled)

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the alert preference settings page from the main dashboard or user profile menu | Alert preference settings UI is displayed showing all available alert channels (pop-ups, emails, dashboard notifications) with current configuration status |
| 2 | Verify that all alert channel options are visible and accessible | Pop-up notifications, email notifications, and dashboard notifications options are displayed with toggle switches or checkboxes in their current state |
| 3 | Enable the email alert channel by clicking the toggle switch or checkbox | Email alert channel toggle changes to enabled state with visual confirmation (e.g., green color, checkmark) |
| 4 | Enable the dashboard notifications channel by clicking the toggle switch or checkbox | Dashboard notifications channel toggle changes to enabled state with visual confirmation |
| 5 | Disable the pop-up alert channel by clicking the toggle switch or checkbox | Pop-up alert channel toggle changes to disabled state with visual confirmation (e.g., gray color, unchecked) |
| 6 | Click the 'Save' or 'Apply' button to save the alert preferences | Success message is displayed confirming preferences are saved successfully, and the save operation completes within 1 second |
| 7 | Refresh the alert preference settings page or navigate away and return to the settings | Previously saved preferences are displayed correctly: email enabled, dashboard notifications enabled, pop-ups disabled |
| 8 | Trigger an alert event that would normally generate notifications across all channels | Alert is delivered only through enabled channels: email notification is received and dashboard notification appears |
| 9 | Verify that no pop-up alert is displayed on the screen | No pop-up notification appears, confirming that disabled channel preferences are respected |
| 10 | Check the email inbox for the alert notification | Email alert is received in the inbox with correct alert content and timestamp |
| 11 | Check the dashboard notifications section | Dashboard notification is visible in the notifications panel with correct alert content and timestamp |
| 12 | Measure and verify the response time for preference retrieval | Preference retrieval operation completes in under 1 second as per performance requirements |

**Postconditions:**
- User alert preferences are saved in the user profile database
- Email and dashboard notification channels remain enabled
- Pop-up notification channel remains disabled
- Future alerts will be delivered according to the saved preferences
- User session remains active and authenticated

---

