# Manual Test Cases

## Story: As Employee, I want to perform task status updates to achieve accurate progress tracking
**Story ID:** story-1

### Test Case: Validate successful status update with valid input
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- User is authenticated with valid OAuth2 credentials
- User has employee role with task update permissions
- At least one task is assigned to the logged-in employee
- Task has a current status that allows valid transitions
- System is accessible via desktop browser
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the task detail page by clicking on an assigned task from the task list | Task detail page loads successfully displaying task name, description, current status, and status update dropdown. Current status is clearly visible and highlighted. |
| 2 | Click on the status dropdown menu to view available status options | Dropdown expands showing all valid status options for the current task state. Invalid status transitions are either not displayed or are disabled/grayed out. |
| 3 | Select a valid new status from the dropdown menu (e.g., change from 'In Progress' to 'Completed') | Selected status is highlighted in the dropdown. The dropdown closes and the new status value is displayed in the status field. Submit button becomes enabled if previously disabled. |
| 4 | Click the 'Submit' or 'Update Status' button to save the status change | System processes the request and displays a success confirmation message (e.g., 'Status updated successfully'). The update completes within 2 seconds. The new status is reflected in the task detail view. |
| 5 | Navigate back to the task list view | Task list displays the updated status for the modified task, confirming the change has been persisted in the system. |

**Postconditions:**
- Task status is updated in the TaskStatus table
- Status change is recorded with timestamp in the database
- Task list reflects the new status
- User remains on the task detail page or is redirected to task list
- No error messages are displayed

---

### Test Case: Verify rejection of invalid status transition
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is authenticated with valid OAuth2 credentials
- User has employee role with task update permissions
- At least one task is assigned to the logged-in employee
- Task has a current status with defined invalid transition rules (e.g., cannot move from 'Completed' to 'Not Started')
- System is accessible via desktop browser
- Business rules for status transitions are configured in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the task detail page by selecting a task with a status that has restricted transitions | Task detail page loads successfully displaying task details and current status (e.g., 'Completed'). Status dropdown is visible and accessible. |
| 2 | Click on the status dropdown to view available options and attempt to select an invalid status transition (e.g., from 'Completed' to 'Not Started') | Invalid status options are either not displayed in the dropdown, or are displayed but disabled/grayed out with a visual indicator. If selectable, a validation warning appears immediately upon selection. |
| 3 | If the invalid status was selectable, click the 'Submit' or 'Update Status' button | System blocks the submission and displays a clear error message such as 'Invalid status transition: Cannot change from Completed to Not Started' or 'This status change is not allowed'. The original status remains unchanged. |
| 4 | Verify that the task status has not changed by checking the current status display | Task detail page continues to show the original status. No success confirmation message is displayed. The status field reverts to the original value if it was temporarily changed. |
| 5 | Navigate to the task list and verify the task status | Task list shows the original status for the task, confirming no unauthorized status change occurred. |

**Postconditions:**
- Task status remains unchanged in the database
- Error message is displayed to the user
- No status change is recorded in the audit log
- User remains on the task detail page
- System maintains data integrity

---

### Test Case: Ensure status update works on mobile devices
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is authenticated with valid OAuth2 credentials on mobile device
- User has employee role with task update permissions
- At least one task is assigned to the logged-in employee
- Mobile device (iOS or Android) with supported browser or native app
- Mobile device has stable internet connection
- Task has a current status that allows valid transitions

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open the task management application on a mobile device (smartphone or tablet) and navigate to the task list | Application loads with responsive mobile interface. Task list is displayed in a mobile-optimized layout with touch-friendly elements. All tasks are visible and scrollable. |
| 2 | Tap on a task to access the task update interface | Task detail page opens with mobile-responsive design. All elements (task name, description, status dropdown, submit button) are properly sized and accessible. Interface adapts to screen orientation (portrait/landscape). |
| 3 | Tap on the status dropdown to view available status options | Dropdown menu expands with touch-optimized selection options. Status options are clearly readable and have adequate touch target size (minimum 44x44 pixels). Valid status options are displayed. |
| 4 | Select a valid new status from the dropdown by tapping on it | Selected status is highlighted and the dropdown closes. New status value is displayed in the status field. No UI elements overlap or become inaccessible. |
| 5 | Tap the 'Submit' or 'Update Status' button to save the change | System processes the update within 2 seconds. Success confirmation message appears in a mobile-friendly format (toast notification or modal). The message is clearly visible and does not obstruct other UI elements. |
| 6 | Navigate back to the task list view by using the back button or navigation menu | Task list reloads and displays the updated status for the modified task. The status change is immediately visible in the mobile task list view. |
| 7 | Verify the status change persists by closing and reopening the application | Upon reopening, the task list shows the updated status, confirming the change was successfully saved to the server and persisted. |

**Postconditions:**
- Task status is updated in the database
- Status change is visible on both mobile and desktop platforms
- Mobile interface remains responsive and functional
- User can continue to perform other actions on mobile device
- No layout or rendering issues occur on mobile view

---

## Story: As Employee, I want to perform editing task status updates to achieve correction of mistakes
**Story ID:** story-3

### Test Case: Validate successful status edit within allowed time window
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is authenticated with valid credentials and has edit permissions
- User has employee role with status edit authorization
- At least one task has a status update submitted less than 30 minutes ago
- TaskStatusHistory table contains recent status update records
- Audit trail logging is enabled and functional
- System time is synchronized and accurate

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the task detail page and locate the 'Status History' or 'View History' section | Task status history section is displayed showing a chronological list of all status updates with timestamps, previous status, new status, and user who made the change. Most recent updates appear at the top. |
| 2 | Identify a status update that was submitted less than 30 minutes ago (timestamp should be within the allowed edit window) | Recent status update is visible with a timestamp showing it is within the 30-minute window. An 'Edit' button or icon is displayed next to the status update entry, indicating it is editable. |
| 3 | Click the 'Edit' button next to the recent status update | Edit interface opens, either as a modal dialog or inline form. The current status value is pre-populated in an editable dropdown or field. A status dropdown shows all valid status options based on transition rules. |
| 4 | Select a different valid status from the dropdown menu (e.g., change from 'In Progress' to 'On Hold') | New status is selected and highlighted in the dropdown. The interface shows the change clearly, possibly with a visual indicator showing 'Original: In Progress' and 'New: On Hold'. |
| 5 | Click the 'Save' or 'Update' button to submit the edited status change | System processes the edit within 2 seconds. A success confirmation message appears (e.g., 'Status update edited successfully'). The edit interface closes and returns to the status history view. |
| 6 | Verify the status history now reflects the edited status | Status history shows the updated status value with an indicator that it was edited (e.g., 'Edited' badge or icon). The timestamp of the original update is preserved, but an 'Edited at' timestamp is also displayed. |
| 7 | Navigate to the audit trail or system logs to verify the edit was logged | Audit trail contains a new entry recording the status edit with details including: original status, new status, user who made the edit, timestamp of edit, and task ID. All required audit information is complete and accurate. |
| 8 | Check the current task status on the task detail page | Task detail page displays the newly edited status as the current status. The change is reflected throughout the system consistently. |

**Postconditions:**
- Status update is modified in TaskStatusHistory table
- Audit trail entry is created with complete edit details
- Current task status reflects the edited value
- Original timestamp is preserved with additional edit timestamp
- Manager notification is queued or sent
- User remains on task detail or history page

---

### Test Case: Verify rejection of status edit after time window
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is authenticated with valid credentials and has edit permissions
- User has employee role with status edit authorization
- At least one task has a status update submitted more than 30 minutes ago
- TaskStatusHistory table contains status update records older than 30 minutes
- System time is synchronized and accurate
- 30-minute edit window validation is configured and active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the task detail page and access the 'Status History' section | Task status history is displayed showing all status updates with timestamps. Status updates older than 30 minutes are visible in the list. |
| 2 | Locate a status update that was submitted more than 30 minutes ago (check timestamp to confirm it is outside the edit window) | Status update with timestamp older than 30 minutes is visible. The 'Edit' button is either not displayed, is disabled/grayed out, or shows a visual indicator that editing is not allowed (e.g., lock icon). |
| 3 | Attempt to click the 'Edit' button or option for the expired status update (if visible) | If the button is disabled, no action occurs and a tooltip may appear stating 'Edit window expired'. If the button is clickable, the system prevents the edit interface from opening or immediately shows an error message. |
| 4 | If edit interface opens, attempt to modify the status and click 'Save' or 'Update' | System blocks the submission and displays a clear error message such as 'Edit window expired - status updates can only be edited within 30 minutes of submission' or 'Cannot edit status: time limit exceeded'. |
| 5 | Verify the error message is displayed prominently and provides clear guidance | Error message is displayed in a visible location (modal, banner, or inline message) with appropriate styling (red color, error icon). Message clearly explains why the edit was rejected and the time constraint. |
| 6 | Close the error message and return to the status history view | Status history view is displayed without any changes. The expired status update remains in its original state. |
| 7 | Verify that no changes were made to the status history by checking the status update details | The status update older than 30 minutes shows the original status value with no modifications. No 'Edited' indicator is present. The timestamp remains unchanged. |
| 8 | Check the audit trail to confirm no edit attempt was logged as successful | Audit trail does not contain any successful edit entry for this status update. Optionally, a failed edit attempt may be logged for security purposes, but the status itself remains unchanged. |
| 9 | Verify the current task status has not changed | Task detail page shows the same status as before the edit attempt. No unauthorized changes occurred in the system. |

**Postconditions:**
- Status update remains unchanged in TaskStatusHistory table
- No audit trail entry for successful edit is created
- Error message is displayed to user
- Current task status remains the same
- System maintains data integrity and time-based validation
- User remains on task detail or history page

---

### Test Case: Ensure notifications are sent to managers on status edits
- **ID:** tc-006
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 6 mins

**Preconditions:**
- User is authenticated with valid credentials and has edit permissions
- User has employee role with status edit authorization
- At least one task has a status update submitted less than 30 minutes ago
- Task has an assigned manager with valid notification settings
- Manager notification system is configured and operational
- Notification service is running and accessible
- Manager has a valid email address or notification channel configured

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the task status history and select a recent status update (less than 30 minutes old) to edit | Status history is displayed with recent updates. Edit option is available for the selected status update within the time window. |
| 2 | Click the 'Edit' button to open the edit interface | Edit interface opens with the current status pre-populated and a dropdown showing valid status options. |
| 3 | Modify the status by selecting a different valid status from the dropdown | New status is selected and displayed in the edit interface. The change is clearly visible to the user. |
| 4 | Click 'Save' or 'Update' to submit the edited status change | System processes the edit successfully within 2 seconds. Success confirmation message appears (e.g., 'Status updated and manager notified'). The edit is saved to the database and audit trail. |
| 5 | Access the manager notification system or inbox (log in as the assigned manager or check notification logs) | Manager notification system shows a new notification related to the status edit. Notification appears in the manager's notification center, email inbox, or configured notification channel. |
| 6 | Open and review the notification content | Notification contains accurate and complete information including: task name/ID, employee who made the edit, original status, new edited status, timestamp of edit, and a link to view the task details. |
| 7 | Verify the notification includes all required details: task identifier, original status, new status, employee name, and edit timestamp | All required information is present and accurate in the notification. The notification is formatted clearly and professionally. Links (if any) are functional and direct to the correct task. |
| 8 | Check the notification timestamp to ensure it was sent immediately after the edit | Notification timestamp is within seconds of the status edit submission time, confirming real-time or near-real-time notification delivery. |
| 9 | Verify in the system logs or notification service that the notification was successfully delivered | System logs or notification service dashboard shows successful delivery status for the manager notification. No delivery errors or failures are recorded. |

**Postconditions:**
- Status edit is successfully saved in the database
- Manager receives notification via configured channel
- Notification contains accurate task and edit details
- Notification delivery is logged in the system
- Audit trail includes both the status edit and notification event
- Manager can access task details from notification link

---

## Story: As Employee, I want to perform receiving notifications for task status updates to achieve timely awareness
**Story ID:** story-7

### Test Case: Validate notification delivery on status update
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged into the system as an employee
- User has at least one task assigned to them
- User has both in-app and email notifications enabled in settings
- User has valid email address configured in profile
- Notification service is running and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the task details page for an assigned task | Task details page loads successfully showing current task status |
| 2 | Update the task status from current status to a different status (e.g., from 'Pending' to 'In Progress') | Status update is processed successfully and task status is changed in the system |
| 3 | Click on the notifications icon in the application header to view in-app notifications | Notification appears in the in-app notification panel with task name, new status ('In Progress'), and timestamp of the status change |
| 4 | Open the email inbox associated with the user account | Email notification is received within 5 seconds containing task name, new status, timestamp, and link to the task |
| 5 | Verify the content accuracy of both in-app and email notifications | Both notifications display identical and accurate information matching the task status update |

**Postconditions:**
- Task status remains updated in the system
- Notification is marked as delivered in the notification service logs
- User can access the task from notification links

---

### Test Case: Verify notification preference settings
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged into the system as an employee
- User has at least one task assigned to them
- User currently has both in-app and email notifications enabled
- User has access to notification settings page

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to user profile settings and click on 'Notification Settings' or 'Preferences' | Notification settings page is displayed showing all available notification channels (in-app and email) with current preferences |
| 2 | Locate the email notification toggle/checkbox for task status updates and disable it | Email notification option is unchecked/toggled off while in-app notification remains enabled |
| 3 | Click the 'Save' or 'Update Preferences' button | Success message is displayed confirming 'Notification preferences saved successfully' and settings page reflects the updated preference |
| 4 | Navigate to a task assigned to the user and update its status to trigger a notification | Task status is updated successfully in the system |
| 5 | Check the in-app notification panel for the status update notification | In-app notification is displayed with correct task details, new status, and timestamp |
| 6 | Check the email inbox for any notification related to the status update | No email notification is received, confirming that email notifications are disabled |
| 7 | Verify notification delivery logs in the system | Logs show notification sent only via in-app channel, email channel skipped based on user preference |

**Postconditions:**
- User notification preferences remain saved as in-app only
- Future task status updates will only trigger in-app notifications
- Email notification channel remains disabled until user re-enables it

---

### Test Case: Ensure unauthorized users do not receive notifications
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Two user accounts exist: User A (authorized) and User B (unauthorized)
- User A is logged in and has a task assigned to them
- User B is logged in in a separate browser/session and is NOT assigned to User A's task
- Both users have notifications enabled
- Admin/tester has access to audit logs and notification service logs

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | As User A, navigate to the task details page for a task assigned only to User A | Task details page loads successfully showing User A as the assignee |
| 2 | Update the task status from current status to a different status (e.g., from 'Pending' to 'In Progress') | Status update is processed successfully and task status changes in the system |
| 3 | As User A, check the in-app notifications panel | User A receives notification about the task status update with correct details |
| 4 | Switch to User B's session and check the in-app notifications panel | User B does not see any notification related to User A's task status update |
| 5 | Check User B's email inbox for any notifications about User A's task | No email notification is received by User B regarding the task status update |
| 6 | Access the notification service audit logs and filter by the task status update event | Audit logs show notifications were sent only to User A (authorized user) and no notification records exist for User B |
| 7 | Verify the notification recipient list in the logs matches only authorized users | Logs confirm that the system correctly identified only User A as an affected employee and excluded User B from notification distribution |

**Postconditions:**
- Only authorized users have received notifications
- Audit logs accurately reflect notification distribution to authorized users only
- System security controls prevented unauthorized notification delivery

---

## Story: As Employee, I want to perform filtering tasks by status to achieve focused task management
**Story ID:** story-8

### Test Case: Validate filtering tasks by single status
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged into the system as an employee
- User has multiple tasks assigned with different statuses (e.g., In Progress, Pending, Completed)
- Task list page is accessible and functional
- At least 3 tasks exist with 'In Progress' status and 3 tasks with other statuses

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the task list page from the main navigation menu | Full task list page is displayed showing all tasks assigned to the user across all statuses with task count visible |
| 2 | Locate the status filter dropdown or filter panel on the task list page | Status filter UI component is visible showing all available status options (e.g., In Progress, Pending, Completed, etc.) |
| 3 | Select a single status filter option 'In Progress' from the filter dropdown/panel | Task list updates dynamically to display only tasks with 'In Progress' status, and task count reflects the filtered number |
| 4 | Verify that all displayed tasks show 'In Progress' as their status | All visible tasks in the list have 'In Progress' status and no tasks with other statuses are displayed |
| 5 | Note the number of tasks displayed and verify it matches the expected count of 'In Progress' tasks | Task count matches the number of tasks with 'In Progress' status |
| 6 | Click the 'Clear filter' button or deselect the 'In Progress' status filter | Full task list is restored showing all tasks across all statuses, and task count returns to the original total |
| 7 | Verify that tasks with all statuses are now visible again | Task list displays tasks with various statuses including In Progress, Pending, Completed, etc. |

**Postconditions:**
- Task list displays all tasks without any filters applied
- Filter controls are reset to default state
- No filter selections are active

---

### Test Case: Validate filtering tasks by multiple statuses
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged into the system as an employee
- User has tasks assigned with multiple different statuses
- At least 2 tasks exist with 'In Progress' status, 2 with 'Pending' status, and 2 with 'Completed' status
- Task list page supports multi-select filtering
- Browser session persistence is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the task list page | Full task list is displayed showing all tasks with various statuses |
| 2 | Open the status filter control and select multiple status options: 'In Progress' and 'Pending' | Both 'In Progress' and 'Pending' status filters are selected/checked in the filter UI |
| 3 | Apply the multi-select filter or wait for automatic filtering | Task list updates to show only tasks with either 'In Progress' OR 'Pending' status, excluding tasks with 'Completed' or other statuses |
| 4 | Verify that all displayed tasks have either 'In Progress' or 'Pending' status | All visible tasks match one of the selected statuses and no tasks with unselected statuses are shown |
| 5 | Modify the filter selection by deselecting 'Pending' and adding 'Completed' to the selection | Filter selection updates to show 'In Progress' and 'Completed' as selected statuses |
| 6 | Observe the task list update | Task list updates dynamically to show only tasks with 'In Progress' or 'Completed' status, excluding 'Pending' tasks |
| 7 | Note the current filter selections ('In Progress' and 'Completed') | Filter UI clearly indicates that 'In Progress' and 'Completed' are the active filters |
| 8 | Reload the page by pressing F5 or clicking the browser refresh button | Page reloads successfully and task list page is displayed |
| 9 | Check the status filter selections after page reload | Previously selected filters ('In Progress' and 'Completed') are persisted and still active, showing the same filtered task list |
| 10 | Verify the task list content matches the persisted filter selections | Task list displays only tasks with 'In Progress' or 'Completed' status, confirming filter persistence across page reload |

**Postconditions:**
- Filter selections remain persisted in the user session
- Task list continues to show filtered results based on saved preferences
- User can continue working with the same filter context

---

### Test Case: Ensure filtered task list loads within performance SLA
- **ID:** tc-006
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged into the system as an employee
- Test environment has 1000+ tasks loaded in the database assigned to the user
- Tasks have various statuses distributed across the dataset
- Network conditions are normal (not throttled)
- Performance monitoring tools are available to measure load times
- User has appropriate authorization to view all assigned tasks

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the task list page and wait for the full unfiltered list to load | Task list page loads showing all 1000+ tasks with pagination or infinite scroll, and total task count is displayed |
| 2 | Open browser developer tools and navigate to the Network tab to monitor API calls | Network monitoring is active and ready to capture API request/response times |
| 3 | Select one or more status filters (e.g., 'In Progress') and start a timer or note the timestamp | Filter selection is applied and API request is initiated to fetch filtered results |
| 4 | Monitor the time taken for the filtered task list to fully load and display results | Filtered task list loads and displays within 2 seconds, meeting the performance SLA requirement |
| 5 | Verify the API response time in the Network tab for the GET /api/tasks?status=... request | API response time is under 2 seconds and HTTP status code is 200 OK |
| 6 | Clear the filter to return to the full unfiltered task list view | Full task list loads successfully without errors or performance degradation |
| 7 | Apply a different status filter and measure the load time again | Filtered results load within 2 seconds consistently |
| 8 | Navigate between filtered and unfiltered views multiple times (at least 3 iterations) | UI remains responsive throughout all navigation actions with no lag, freezing, or JavaScript errors |
| 9 | Check browser console for any errors or warnings during filter operations | No errors or warnings are displayed in the browser console |
| 10 | Verify that only tasks authorized for the current user are displayed in both filtered and unfiltered views | All displayed tasks are assigned to or accessible by the current user, and no unauthorized tasks are visible in the list |
| 11 | Randomly select several tasks from the filtered list and verify their status matches the applied filter | All sampled tasks have the correct status matching the filter criteria, confirming data accuracy |

**Postconditions:**
- Task list performance meets the 2-second SLA requirement
- System handles large datasets without performance degradation
- Security controls ensure only authorized tasks are displayed
- UI remains stable and responsive under load

---

## Story: As Employee, I want to perform validating task status updates to achieve data integrity
**Story ID:** story-10

### Test Case: Validate acceptance of valid status update
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Employee is logged into the system with valid credentials
- Employee has permission to update task status
- At least one task exists in the system with current status 'In Progress'
- Business rules engine is configured with valid status transition flows
- API endpoint PUT /api/tasks/{taskId}/status is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the task management page and select a task with status 'In Progress' | Task details are displayed with current status showing 'In Progress' |
| 2 | Click on the status dropdown and select a valid next status (e.g., 'Completed') | Status dropdown displays available valid status options |
| 3 | Fill in all mandatory fields required for the status update (e.g., completion notes, actual hours) | All mandatory fields are populated with valid data |
| 4 | Click the 'Update Status' button to submit the status change | System processes the request and update is accepted and saved to the database |
| 5 | Verify confirmation message is displayed on the screen | Success confirmation message appears stating 'Task status updated successfully' or similar |
| 6 | Refresh the task details page and verify the status has been updated | Task now displays the new status 'Completed' with timestamp of update |
| 7 | Navigate to the audit logs section and search for the task update record | Audit log entry is found showing task ID, old status, new status, timestamp, and employee who made the change |
| 8 | Verify all details in the audit log are correct and complete | Update is logged correctly with 100% accuracy of all fields |

**Postconditions:**
- Task status is updated to 'Completed' in the database
- Audit log contains complete record of the status change
- Employee can view the updated task status
- System remains in stable state ready for next operation

---

### Test Case: Verify rejection of invalid status update
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Employee is logged into the system with valid credentials
- Employee has permission to update task status
- At least one task exists with current status 'Completed'
- Business rules define that 'Completed' tasks cannot transition to 'In Progress'
- Validation rules are properly configured in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the task management page and select a task with status 'Completed' | Task details are displayed showing current status as 'Completed' |
| 2 | Attempt to change the status to an invalid transition state (e.g., 'In Progress') | Status dropdown allows selection but validation will occur on submission |
| 3 | Fill in any required fields and click 'Update Status' button to submit the invalid status update | System validates the status transition and rejects the update |
| 4 | Verify that an error message is displayed on the screen | Descriptive error message appears stating 'Invalid status transition: Cannot change from Completed to In Progress' or similar clear explanation |
| 5 | Verify that the task status remains unchanged in the system | Task status remains 'Completed' and no update is saved to the database |
| 6 | Review the error message details to understand the validation failure reason | Error message clearly explains why the transition is invalid and what valid options are available |
| 7 | Correct the status by selecting a valid transition (e.g., 'Archived' if allowed from 'Completed') | Valid status option is selected |
| 8 | Resubmit the status update with the corrected valid status | System validates and accepts the update, displaying success confirmation |
| 9 | Verify the task now shows the new valid status | Task status is successfully updated to the valid status with confirmation message displayed |

**Postconditions:**
- Invalid status update was rejected and not saved
- Task eventually updated to valid status after correction
- Validation error was logged in system logs
- Employee understands the valid status transition rules

---

### Test Case: Ensure validation completes within performance SLA
- **ID:** tc-003
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- Employee is logged into the system with valid credentials
- Multiple tasks (at least 10) exist in the system with various statuses
- System is under normal operational load
- Performance monitoring tools are configured and accessible
- System logs are enabled and capturing validation events
- Network latency is within normal parameters

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open performance monitoring dashboard or prepare timing measurement tool | Monitoring tools are ready to capture response times |
| 2 | Navigate to the first task and initiate a valid status update | Task update form is displayed |
| 3 | Submit the status update and measure the validation processing time from submission to response | Validation completes and response is received within 1 second (1000ms) |
| 4 | Record the validation time and verify it meets the SLA requirement | Validation time is logged and is less than or equal to 1 second |
| 5 | Repeat steps 2-4 for at least 9 more tasks with different status transitions under normal load | Each validation completes within 1 second for all submissions |
| 6 | Submit a status update with invalid data to trigger a validation error | Validation error occurs and is processed within 1 second |
| 7 | Navigate to system logs and search for validation error entries | System logs display all validation errors that occurred during testing |
| 8 | Verify each validation error log entry contains complete information (timestamp, task ID, error type, error message, employee ID) | All validation errors are logged with 100% accuracy and completeness of required fields |
| 9 | Cross-reference the number of validation errors triggered with the number of log entries | Count matches exactly - all errors are logged without any missing entries |
| 10 | Monitor system resource utilization (CPU, memory, response times) during the validation tests | System resources remain within normal operating parameters |
| 11 | Verify system responsiveness by navigating to different pages and performing other operations | No performance degradation occurs - system remains responsive with normal page load times |
| 12 | Review overall performance metrics and confirm all validations met the 1-second SLA | 100% of status update validations completed within the 1-second performance requirement |

**Postconditions:**
- All validation operations completed within 1 second SLA
- All validation errors are logged in system logs with complete accuracy
- System performance remains stable with no degradation
- Performance metrics are documented for future reference
- Test tasks are in their final updated states

---

