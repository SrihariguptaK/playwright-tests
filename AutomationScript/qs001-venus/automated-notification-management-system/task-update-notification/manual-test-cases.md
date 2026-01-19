# Manual Test Cases

## Story: As Task Assignee, I want to receive notifications for task updates to stay informed about my responsibilities
**Story ID:** story-27

### Test Case: Validate notification sent on task status update
- **ID:** tc-027-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged into the system as a task assignee
- Task exists in the system with assignee assigned
- User has valid email address, phone number, and in-app notification enabled
- Notification service is running and operational
- User notification preferences are set to default (all channels enabled)

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the task management module and select an existing task assigned to the test user | Task details are displayed with current status visible |
| 2 | Update the task status from 'In Progress' to 'Completed' and save the changes | System detects the status update, saves the changes successfully, and triggers the notification generation process |
| 3 | Check the user's email inbox for the task update notification | Email notification is received within 1 minute containing correct task name, previous status, new status, update timestamp, and task assignee information |
| 4 | Check the user's mobile device for SMS notification | SMS notification is received within 1 minute containing task name and new status information |
| 5 | Check the in-app notification center within the application | In-app notification appears in the notification center with complete task details, status change information, and timestamp |
| 6 | Navigate to user profile settings and access notification preferences section | Notification preferences page is displayed showing options for email, SMS, and in-app notifications |
| 7 | Disable SMS notifications for task updates and save the preferences | Preferences are saved successfully with confirmation message displayed |
| 8 | Update the same task status from 'Completed' to 'In Review' | System detects the status update and triggers notification generation |
| 9 | Check email, SMS, and in-app notifications for the second update | Email and in-app notifications are received with correct details, but no SMS notification is received, respecting the updated preferences |

**Postconditions:**
- Task status is updated to 'In Review' in the system
- All notifications are logged in the notification history
- User notification preferences remain as customized (SMS disabled)
- Notification delivery records are stored in the database

---

### Test Case: Verify retry mechanism on notification failure
- **ID:** tc-027-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- User is logged into the system with admin or test privileges
- Task exists in the system with assignee assigned
- Notification service is operational
- Test environment allows simulation of notification delivery failures
- Access to notification logs and monitoring dashboard is available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Configure the test environment to simulate email notification delivery failure for the next notification attempt | Email service mock is configured to return failure response on first attempt |
| 2 | Update a task status from 'New' to 'In Progress' to trigger notification | System detects status change and attempts to send notification via all configured channels |
| 3 | Monitor the notification service logs in real-time during the retry attempts | System logs the initial failure and automatically initiates retry attempt #1 within 30 seconds |
| 4 | Continue monitoring as the system performs subsequent retry attempts | System performs retry attempt #2 and retry attempt #3, with each retry logged with timestamp and failure reason |
| 5 | Access the notification logs dashboard and filter for the specific task update notification | Notification log entry displays initial attempt timestamp, 3 retry attempt timestamps, failure reasons, and total of 4 delivery attempts |
| 6 | Verify the log entry details including task ID, notification type, delivery channel, and retry count | All retry attempts are logged with accurate timestamps (showing intervals between retries), error codes, and delivery status marked as 'Failed after 3 retries' |
| 7 | Remove the failure simulation and update the task status again from 'In Progress' to 'Blocked' | System triggers notification and successfully delivers on first attempt |
| 8 | Check the notification logs for the successful delivery | Log entry shows successful delivery on first attempt with no retry attempts needed, marked as 'Delivered' with delivery timestamp |

**Postconditions:**
- All notification delivery attempts are logged in the system
- Failed notification is marked as permanently failed after 3 retries
- Subsequent notifications are delivered successfully
- Test environment is restored to normal operation
- Notification failure alerts are generated for monitoring team

---

### Test Case: Ensure immediate notification delivery
- **ID:** tc-027-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- User is logged into the system with task assignee role
- Multiple tasks exist in the system assigned to the test user
- Notification service is running with optimal performance
- System monitoring and logging tools are active
- Timestamp synchronization is enabled across all services

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Record the current system timestamp as the test start time | Baseline timestamp is captured for performance measurement |
| 2 | Update the status of Task #1 from 'New' to 'In Progress' and record the exact update timestamp | Task status is updated successfully and update timestamp is recorded |
| 3 | Monitor notification delivery and record the timestamp when notification is received in the in-app notification center | Notification is received within 5 seconds of the task update, delivery timestamp is recorded |
| 4 | Calculate the time difference between task update and notification delivery for Task #1 | Time difference is less than or equal to 5 seconds, meeting immediate delivery requirement |
| 5 | Update the status of Task #2 from 'In Progress' to 'Completed' and record the update timestamp | Task status is updated successfully and timestamp is recorded |
| 6 | Monitor and record the notification delivery timestamp for Task #2 | Notification is received within 5 seconds and delivery timestamp is recorded |
| 7 | Update the status of Task #3 from 'Completed' to 'Archived' and record the update timestamp | Task status is updated successfully and timestamp is recorded |
| 8 | Monitor and record the notification delivery timestamp for Task #3 | Notification is received within 5 seconds and delivery timestamp is recorded |
| 9 | Access the system logs and filter for notification delivery events for all three task updates | System logs display all three notification events with trigger timestamps, processing times, and delivery timestamps |
| 10 | Review the logs for any errors, warnings, or delays in the notification processing pipeline | No errors or warnings are recorded; all notifications show successful immediate delivery with processing time under 5 seconds |
| 11 | Generate a performance report showing average delivery time across all three notifications | Average delivery time is calculated and confirms all notifications met the immediate delivery requirement (≤5 seconds) |

**Postconditions:**
- All three task status updates are saved in the system
- All notifications are delivered successfully within required timeframe
- Performance metrics are logged and available for reporting
- No errors or delays are recorded in system logs
- Notification delivery times are documented for compliance verification

---

## Story: As Task Manager, I want to receive notifications for task delays to proactively manage project timelines
**Story ID:** story-30

### Test Case: Validate notification sent on task delay detection
- **ID:** tc-030-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- User is logged into the system with task manager role
- Task exists in the system with defined deadline and assigned to a team member
- Task deadline monitoring service is active and running
- User has valid email address, phone number, and in-app notification enabled
- System clock is synchronized and accurate

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Create or select a task with a deadline set to the current date and time minus 1 hour (simulating a missed deadline) | Task is displayed with status showing 'Overdue' or 'Delayed' and deadline has passed |
| 2 | Trigger the system's delay detection process manually or wait for the scheduled delay check cycle to run | System detects that the task deadline has passed without completion and triggers the delay notification generation process |
| 3 | Check the task manager's email inbox for the delay notification | Email notification is received within 2 minutes containing task name, original deadline, current delay duration, assigned team member, and task priority |
| 4 | Verify the email content includes delay reason if available in the task details | Email displays delay reason field (populated if available, or marked as 'Not specified' if unavailable) |
| 5 | Check the task manager's mobile device for SMS notification | SMS notification is received within 2 minutes containing task name, delay status, and deadline information |
| 6 | Check the in-app notification center for the delay alert | In-app notification appears with complete delay details including task name, deadline, delay duration, assignee, and actionable links to the task |
| 7 | Click on the in-app notification to open the task details page | Task details page opens showing full task information with delay highlighted and acknowledgment option available |
| 8 | Click the 'Acknowledge' button on the notification or task details page | Acknowledgment dialog appears prompting for optional comments |
| 9 | Enter comment 'Reviewing resource allocation to address delay' and submit the acknowledgment | Acknowledgment is saved successfully with confirmation message displayed, and notification status changes to 'Acknowledged' |
| 10 | Navigate to the notification logs or history section | Notification log entry displays the delay notification with acknowledgment timestamp, manager name, and comment text |

**Postconditions:**
- Delay notification is marked as acknowledged in the system
- Manager's comment is stored and associated with the task
- Notification delivery and acknowledgment are logged with timestamps
- Task remains in delayed status until completion or deadline adjustment
- Audit trail is created for the notification and acknowledgment

---

### Test Case: Verify retry mechanism on notification failure
- **ID:** tc-030-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- User is logged into the system with admin or test privileges
- Task exists with passed deadline to trigger delay notification
- Notification service is operational
- Test environment allows simulation of notification delivery failures
- Access to notification logs and system monitoring tools is available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Configure the test environment to simulate SMS notification delivery failure for the next notification attempt | SMS service mock is configured to return failure response on initial attempts |
| 2 | Set a task deadline to current time minus 30 minutes and ensure task is incomplete to trigger delay detection | Task is marked as delayed in the system |
| 3 | Trigger the delay detection process to generate and send delay notification | System detects the delay and attempts to send notification via email, SMS, and in-app channels |
| 4 | Monitor the notification service logs in real-time to observe the initial SMS delivery failure | System logs the SMS delivery failure with error code and automatically initiates retry attempt #1 within 30 seconds |
| 5 | Continue monitoring the logs as the system performs the second retry attempt | System performs retry attempt #2 after the configured retry interval, logs the attempt with timestamp and failure status |
| 6 | Observe the third and final retry attempt in the logs | System performs retry attempt #3, logs the attempt with timestamp, and marks the notification as 'Failed after maximum retries' |
| 7 | Access the notification logs dashboard and search for the specific delay notification by task ID | Notification log entry is displayed showing initial attempt timestamp, all 3 retry attempt timestamps with intervals, failure reasons, and final status as 'Delivery Failed' |
| 8 | Verify that each retry attempt log entry includes task ID, notification type, delivery channel (SMS), retry count, timestamp, and error details | All log entries contain complete information with accurate timestamps showing progression of retry attempts (initial + 3 retries = 4 total attempts) |
| 9 | Check if email and in-app notifications were delivered successfully despite SMS failure | Email and in-app notifications show successful delivery status, confirming that failure in one channel does not affect others |
| 10 | Remove the failure simulation and create another delayed task to trigger a new notification | New delay notification is triggered for the second task |
| 11 | Verify that the new notification is delivered successfully via all channels including SMS | Notification log shows successful delivery on first attempt for all channels with no retry attempts needed |

**Postconditions:**
- All notification delivery attempts are logged with complete details
- Failed notification is marked as permanently failed after 3 retries
- System administrator is alerted about the notification delivery failure
- Subsequent notifications are delivered successfully after removing failure simulation
- Test environment is restored to normal configuration
- Failure metrics are recorded for monitoring and reporting

---

### Test Case: Ensure immediate notification delivery upon delay detection
- **ID:** tc-030-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 18 mins

**Preconditions:**
- User is logged into the system with task manager role
- Multiple tasks exist in the system with different deadlines
- Delay detection service is running and configured for immediate processing
- System monitoring and performance logging tools are active
- All notification channels are operational and responsive

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Record the current system timestamp as the test baseline | Baseline timestamp is captured for performance measurement |
| 2 | Create Task #1 with deadline set to current time minus 15 minutes and status as 'In Progress' (incomplete) | Task #1 is created and saved in the system with overdue status |
| 3 | Trigger the delay detection process and record the exact timestamp when delay is detected | System detects Task #1 delay and records detection timestamp |
| 4 | Monitor the in-app notification center and record the timestamp when the delay notification appears | Delay notification for Task #1 is received within 5 seconds of delay detection |
| 5 | Calculate and document the time difference between delay detection and notification delivery for Task #1 | Time difference is less than or equal to 5 seconds, meeting immediate delivery requirement |
| 6 | Create Task #2 with deadline set to current time minus 45 minutes and status as 'Not Started' | Task #2 is created and saved with overdue status |
| 7 | Trigger delay detection for Task #2 and record detection timestamp | System detects Task #2 delay and records detection timestamp |
| 8 | Monitor and record the notification delivery timestamp for Task #2 | Delay notification for Task #2 is received within 5 seconds of detection |
| 9 | Create Task #3 with deadline set to current time minus 2 hours and status as 'In Progress' | Task #3 is created and saved with significantly overdue status |
| 10 | Trigger delay detection for Task #3 and record detection timestamp | System detects Task #3 delay and records detection timestamp |
| 11 | Monitor and record the notification delivery timestamp for Task #3 | Delay notification for Task #3 is received within 5 seconds of detection |
| 12 | Access the system logs and filter for all three delay notification events | System logs display all three delay detection and notification delivery events with complete timestamps and processing details |
| 13 | Review the logs for any errors, warnings, delays, or performance issues in the notification pipeline | No errors, warnings, or delays are recorded; all notifications show successful immediate delivery with processing time under 5 seconds |
| 14 | Generate a performance summary report calculating average delivery time across all three delay notifications | Performance report shows average delivery time of ≤5 seconds, confirming all notifications met immediate delivery requirement |
| 15 | Verify that notification delivery metrics are recorded in the system dashboard | Dashboard displays delivery metrics showing 100% success rate and average delivery time within acceptable threshold |

**Postconditions:**
- All three tasks remain in delayed status in the system
- All delay notifications are delivered successfully within required timeframe
- Performance metrics are logged and available in monitoring dashboard
- No errors or delays are recorded in system logs
- Notification delivery times are documented for compliance and SLA verification
- System continues to monitor tasks for further delays or status changes

---

## Story: As Task Assignee, I want to acknowledge task update notifications to confirm receipt and understanding
**Story ID:** story-32

### Test Case: Validate task assignee acknowledgment of task update
- **ID:** tc-032-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as a task assignee
- Task update notification has been generated and sent to the assignee
- User has appropriate permissions to acknowledge notifications
- Notification system is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the notifications section in the application | Notifications page loads successfully and displays the task update notification |
| 2 | Locate and click on the task update notification | Notification details are displayed with an acknowledge button visible |
| 3 | Click the acknowledge button | Acknowledgment form appears with optional comment field |
| 4 | Enter optional comment in the comment field (e.g., 'Understood, will complete by deadline') | Comment text is accepted and displayed in the input field |
| 5 | Submit the acknowledgment | System displays confirmation message indicating successful acknowledgment |
| 6 | Navigate to system logs or acknowledgment history section | Acknowledgment entry is visible with timestamp, user details, and the entered comment |
| 7 | Verify the acknowledgment record contains correct information | Record shows correct assignee name, accurate timestamp, task update reference, and the optional comment entered |

**Postconditions:**
- Acknowledgment is permanently recorded in the system
- Notification status is updated to 'Acknowledged'
- Audit log contains the acknowledgment entry with all required details
- Assignee can view their acknowledgment history

---

### Test Case: Ensure acknowledgment processing performance
- **ID:** tc-032-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in as a task assignee
- Task update notification is available for acknowledgment
- System performance monitoring tools are accessible
- Network connection is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open the task update notification in the application | Notification details are displayed with acknowledge button |
| 2 | Note the current time and click the acknowledge button | Acknowledgment form is displayed immediately |
| 3 | Submit the acknowledgment via the UI | Acknowledgment is processed and confirmation message appears within 2 seconds |
| 4 | Record the time taken from submission to confirmation | Processing time is within acceptable performance threshold (under 3 seconds) |
| 5 | Access system logs or admin panel to view acknowledgment entries | System logs are accessible and display recent acknowledgment entries |
| 6 | Locate the acknowledgment entry just submitted | Entry is present in the logs with correct timestamp matching submission time |
| 7 | Verify all details in the log entry | Log entry contains correct user ID, notification ID, timestamp, and acknowledgment status |

**Postconditions:**
- Acknowledgment is recorded in system logs
- Performance metrics confirm prompt processing
- No system delays or errors occurred
- Notification status reflects acknowledgment

---

### Test Case: Verify system handles missing acknowledgment gracefully
- **ID:** tc-032-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in as a task assignee
- Critical task update notification requiring acknowledgment is available
- System validation rules are configured for required fields
- User has permissions to acknowledge notifications

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open a critical task update notification that requires acknowledgment | Notification details are displayed with required field indicators |
| 2 | Click the acknowledge button without completing any required fields | System displays validation error messages indicating which fields are required |
| 3 | Attempt to submit the acknowledgment form with missing required fields | System blocks submission and displays clear error messages (e.g., 'Acknowledgment confirmation is required') |
| 4 | Verify that the notification status remains unchanged | Notification status is still 'Pending Acknowledgment' and not marked as acknowledged |
| 5 | Complete all required fields in the acknowledgment form | Required field indicators are cleared and form appears valid |
| 6 | Resubmit the acknowledgment with all required fields completed | System accepts the acknowledgment and displays success confirmation message |
| 7 | Verify the acknowledgment is logged in the system | Acknowledgment entry is present in logs with timestamp, user details, and all required information |
| 8 | Check the notification status after successful acknowledgment | Notification status is updated to 'Acknowledged' and removed from pending list |

**Postconditions:**
- System validation prevented incomplete acknowledgment submission
- Valid acknowledgment was successfully recorded after correction
- Audit trail shows both the failed attempt and successful submission
- Notification status accurately reflects acknowledgment state

---

## Story: As Task Assignee, I want to customize notification preferences for task updates to control alert frequency and channels
**Story ID:** story-34

### Test Case: Validate saving and updating task notification preferences
- **ID:** tc-034-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- User is logged in as a task assignee
- User has access to notification preferences settings
- Default notification preferences are already configured
- At least one task is assigned to the user for testing notifications

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to user settings or profile section | Settings page loads successfully with navigation menu visible |
| 2 | Click on 'Notification Preferences' or 'Task Notification Settings' option | Task notification preferences UI is displayed showing current preference settings |
| 3 | Review the current notification frequency setting | Current frequency preference is displayed (e.g., 'Immediate', 'Daily Digest', 'Weekly Summary') |
| 4 | Select a different notification frequency from the dropdown or radio buttons (e.g., change from 'Immediate' to 'Daily Digest') | New frequency option is selected and highlighted in the UI |
| 5 | Review available notification channels (e.g., Email, In-App, SMS, Push) | All available notification channels are displayed with checkboxes or toggle switches |
| 6 | Select preferred notification channels by checking/unchecking options (e.g., enable Email and In-App, disable SMS) | Selected channels are visually indicated as active, unselected channels are inactive |
| 7 | Click the 'Save' or 'Update Preferences' button | System displays success confirmation message (e.g., 'Notification preferences saved successfully') |
| 8 | Refresh the preferences page or navigate away and return | Saved preferences are retained and displayed correctly |
| 9 | Trigger a task update notification by having another user update an assigned task | Task update event is generated in the system |
| 10 | Check the selected notification channels for the notification | Notification is received only through the selected channels (Email and In-App) according to the chosen frequency (Daily Digest) |
| 11 | Verify that disabled channels did not receive the notification | No notification is received via SMS or other disabled channels |

**Postconditions:**
- Notification preferences are saved in the user preferences database
- Future notifications are delivered according to saved preferences
- Preference changes are logged in the audit trail
- User can modify preferences again at any time

---

### Test Case: Verify validation of invalid inputs
- **ID:** tc-034-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in as a task assignee
- User has access to notification preferences settings
- System validation rules are configured for frequency and channel inputs
- Browser developer tools are available for testing edge cases

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to task notification preferences UI | Notification preferences page is displayed with all input fields |
| 2 | Attempt to enter an invalid frequency value (e.g., manually enter 'InvalidFrequency' via browser console or by manipulating the form) | System detects invalid input and displays validation error message |
| 3 | Try to select an unsupported or invalid channel value (e.g., manipulate form data to include 'FakeChannel') | System displays validation error indicating the channel is not valid |
| 4 | Attempt to save preferences with invalid frequency or channel values | System rejects the input, displays clear error messages (e.g., 'Please select a valid notification frequency', 'Invalid channel selected'), and prevents saving |
| 5 | Verify that the previous valid preferences remain unchanged | Original preferences are still active and no changes were saved |
| 6 | Correct the frequency input by selecting a valid option from the dropdown (e.g., 'Immediate') | Valid frequency is selected and error message for frequency is cleared |
| 7 | Correct the channel selection by choosing valid channels (e.g., Email, In-App) | Valid channels are selected and error message for channels is cleared |
| 8 | Click 'Save' button with corrected valid inputs | System accepts the preferences, displays success confirmation, and saves the settings |
| 9 | Verify the saved preferences in the UI | Corrected preferences are displayed accurately in the settings page |

**Postconditions:**
- Invalid inputs were rejected and not saved to the database
- Valid preferences were successfully saved after correction
- System validation prevented data corruption
- Error messages provided clear guidance for correction

---

### Test Case: Ensure immediate effect of preference changes
- **ID:** tc-034-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in as a task assignee
- User has existing notification preferences configured
- Test environment allows triggering of notification events
- Multiple notification channels are available for testing

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to task notification preferences UI | Current notification preferences are displayed |
| 2 | Note the current preference settings (e.g., Frequency: 'Daily Digest', Channels: 'Email only') | Current settings are clearly visible and documented |
| 3 | Change the notification frequency to 'Immediate' | Frequency is updated to 'Immediate' in the UI |
| 4 | Add additional notification channels (e.g., enable 'In-App' and 'Push' notifications) | New channels are selected and visually indicated as active |
| 5 | Click 'Save' to update preferences | System displays confirmation message 'Preferences updated successfully' and saves changes immediately |
| 6 | Note the timestamp of the preference update | Current time is recorded for comparison with notification delivery |
| 7 | Immediately trigger a task update notification event (e.g., have another user update a task assigned to the test user) | Task update event is generated in the system |
| 8 | Check for notification delivery across all newly enabled channels within 1-2 minutes | Notification is received immediately via Email, In-App, and Push channels according to the updated 'Immediate' frequency setting |
| 9 | Verify the notification was not sent according to the old preferences | Notification delivery reflects the new preferences, not the old 'Daily Digest' setting |
| 10 | Check system logs or audit trail for preference change record | Preference change is logged with timestamp, user ID, old values, and new values |

**Postconditions:**
- Notification preferences are updated in real-time
- Subsequent notifications are delivered according to new preferences
- No delay in applying preference changes
- Preference change is logged in audit trail for compliance

---

