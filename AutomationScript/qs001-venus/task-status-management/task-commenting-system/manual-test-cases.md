# Manual Test Cases

## Story: As Employee, I want to perform adding comments to tasks to achieve improved communication
**Story ID:** story-2

### Test Case: Validate successful comment submission
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as an employee with valid credentials
- User has access to at least one task in the system
- Task detail page is accessible
- Network connectivity is stable
- Browser supports JavaScript and has cookies enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to task detail page by clicking on a task from the task list | Task detail page loads successfully within 2 seconds. Task details are displayed including title, description, status, and assignee. Comment input box is visible at the bottom of the page with a submit button |
| 2 | Click on the comment input box and enter a valid comment text (e.g., 'This is a test comment for validation'). Click the submit button | Comment is submitted successfully. The comment appears immediately in the comment list below the input box. Comment displays with the current user's name as author, current timestamp in format 'MMM DD, YYYY HH:MM AM/PM', and the exact comment text entered |
| 3 | Check the notification system or ask relevant stakeholders (task assignee, task creator, project manager) to verify notification receipt | Notification is successfully sent to all relevant stakeholders. Notification contains task name, commenter name, and comment preview. Notification appears in the notification center within 5 seconds of comment submission |

**Postconditions:**
- Comment is permanently saved in TaskComments table
- Comment is visible to all users with access to the task
- Notifications have been delivered to stakeholders
- Comment count for the task is incremented by 1
- User remains on the task detail page

---

### Test Case: Verify editing and deleting own comments within time limit
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in as an employee
- User has previously added at least one comment to a task
- The comment was posted less than 15 minutes ago
- User is on the task detail page where the comment exists
- System time is synchronized correctly

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Locate own comment in the comment list that was posted less than 15 minutes ago. Hover over or click on the comment | Edit and delete icons/buttons are visible and enabled for the user's own comment. The options appear as clickable elements (e.g., pencil icon for edit, trash icon for delete). Comments posted by other users do not show these options |
| 2 | Click the edit button/icon. Modify the comment text (e.g., change 'This is a test comment' to 'This is an updated test comment'). Click save or submit button | Comment editing interface appears with the current comment text pre-populated in an editable text box. After saving, the updated comment text is displayed in the comment list. An 'edited' indicator appears next to the timestamp. The timestamp shows when the comment was last edited |
| 3 | Click the delete button/icon on the same comment. Confirm deletion if a confirmation dialog appears | A confirmation dialog appears asking 'Are you sure you want to delete this comment?'. After confirming, the comment is immediately removed from the comment list. The comment no longer appears on the page. A success message 'Comment deleted successfully' is displayed briefly |

**Postconditions:**
- Edited comment is saved with updated timestamp in database
- Deleted comment is removed from TaskComments table or marked as deleted
- Comment count for the task is decremented by 1 after deletion
- User remains on the task detail page
- No orphaned data remains in the system

---

### Test Case: Ensure comment input sanitization prevents XSS
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as an employee
- User is on a task detail page with comment functionality
- Browser developer console is open to monitor for errors
- Security testing is approved for the test environment
- Test data includes various XSS attack vectors

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | In the comment input box, enter a comment containing script tags such as '<script>alert("XSS")</script>' or other malicious code like '<img src=x onerror=alert("XSS")>' | Input is accepted in the text box without immediate errors. No script execution occurs during input. The input field displays the text as entered |
| 2 | Click the submit button to save the comment | Comment is successfully submitted and saved. The comment appears in the comment list with the script tags displayed as plain text (e.g., visible as '&lt;script&gt;alert("XSS")&lt;/script&gt;'). No JavaScript alert boxes or script execution occurs. The malicious code is rendered as harmless text |
| 3 | Check browser developer console for JavaScript errors, security warnings, or XSS alerts. Refresh the page and verify the comment still displays safely. Check application security logs | No JavaScript errors appear in the console. No security warnings or XSS alerts are triggered. After page refresh, the comment still displays as sanitized plain text without executing scripts. Security logs show no injection attempts succeeded. System remains stable and fully functional |

**Postconditions:**
- Malicious input is stored safely in sanitized form
- No security vulnerabilities are exploited
- System security logs record the sanitization event
- Application remains stable and secure
- Comment is visible as plain text to all users

---

## Story: As Employee, I want to perform adding comments with mentions to achieve targeted communication
**Story ID:** story-4

### Test Case: Validate autocomplete suggestions for mentions
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in as an employee
- User is on a task detail page with comment functionality
- Multiple users exist in the system directory
- User has permission to mention other users
- Network latency is within normal parameters

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Click in the comment input box. Type the '@' symbol followed by characters matching a user's name (e.g., '@joh' for user 'John Smith'). Measure the response time | Autocomplete dropdown appears below the cursor position within 1 second. The dropdown displays a list of users whose names match the entered characters. Each entry shows user's full name and optionally their avatar or role. The list is filtered in real-time as more characters are typed |
| 2 | Use arrow keys or mouse to navigate the autocomplete list. Click on or press Enter to select a user from the list (e.g., select 'John Smith') | The selected user's mention is inserted into the comment input at the cursor position in the format '@John Smith' or '@johnsmith' depending on system configuration. The autocomplete dropdown closes automatically. The mention text is visually distinguished (e.g., highlighted in blue or with different background color). Cursor is positioned after the mention ready for continued typing |
| 3 | Complete the comment text if needed (e.g., '@John Smith please review this task'). Click the submit button | Comment is saved successfully to the database. The comment appears in the comment list immediately. The mention '@John Smith' is displayed with special formatting (e.g., highlighted, clickable, or in a different color). Hovering over the mention may show user details. The comment structure preserves the mention metadata |

**Postconditions:**
- Comment with mention is saved in TaskComments table
- Mention metadata is stored linking to the mentioned user
- Comment is visible with highlighted mention to all users
- System is ready to process notification for mentioned user
- User remains on task detail page

---

### Test Case: Verify notifications sent to mentioned users
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as an employee
- At least one other user exists in the system to be mentioned
- User is on a task detail page
- Notification system is enabled and functioning
- Mentioned user has notification permissions enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | In the comment input box, type '@' and select a specific user from the autocomplete list (e.g., '@Jane Doe'). Complete the comment (e.g., '@Jane Doe can you help with this?'). Click submit button | Comment is submitted successfully. Success message appears (e.g., 'Comment posted successfully'). The comment appears in the comment list with the mention highlighted. No error messages are displayed. The system confirms the comment was saved with HTTP 200/201 status |
| 2 | Log in as the mentioned user (Jane Doe) or check the notification center/inbox for the mentioned user account. Navigate to notifications section | A new notification appears in the mentioned user's notification center. The notification is marked as unread. Notification appears within 10 seconds of comment submission. The notification icon shows an updated count badge |
| 3 | Click on the notification to view its details. Verify the notification content includes task name, commenter name, comment text, and timestamp | Notification displays complete and accurate information including: task title/ID, name of user who mentioned them, full or truncated comment text with the mention visible, timestamp of when comment was posted, and a link to navigate directly to the task. Clicking the notification navigates to the specific task detail page with the comment visible |

**Postconditions:**
- Notification is marked as delivered in the system
- Mentioned user has received and can access the notification
- Notification remains in user's notification history
- Clicking notification navigates to correct task
- Original commenter remains on task detail page

---

### Test Case: Ensure input sanitization prevents injection via mentions
- **ID:** tc-006
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in as an employee
- User is on a task detail page with mention functionality
- Browser developer console is open for monitoring
- Security testing is authorized in test environment
- Test includes various injection attack vectors

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | In the comment input box, attempt to enter mention input with special characters or malicious scripts such as '@<script>alert("XSS")</script>' or '@user"><script>alert("XSS")</script>' or SQL injection patterns like '@user'; DROP TABLE users;--' | System accepts the input without crashing. Input sanitization occurs in real-time or upon submission. Special characters are escaped or encoded. No script execution occurs during input. Autocomplete may not trigger for invalid mention patterns. The input field remains functional |
| 2 | Click the submit button to save the comment with the malicious mention input | Comment is submitted and processed by the server. The comment is saved successfully. Malicious code is sanitized and stored as plain text. The comment appears in the comment list with special characters escaped (e.g., displayed as '&lt;script&gt;' instead of executing). No JavaScript alerts or SQL errors occur. The mention is either treated as plain text or rejected gracefully |
| 3 | Check browser developer console for errors. Review application security logs for injection attempts. Refresh the page and verify the comment displays safely. Check database integrity | No JavaScript errors or security warnings appear in console. Security logs show the sanitization event and blocked injection attempt. After page refresh, comment still displays as safe, sanitized text. No script execution occurs. Database tables remain intact with no corruption. System remains stable and fully operational. No unauthorized database queries were executed |

**Postconditions:**
- Malicious input is neutralized and stored safely
- No security vulnerabilities are exploited
- Security incident is logged for audit purposes
- Database integrity is maintained
- System remains secure and functional
- Comment is visible as sanitized text to all users

---

## Story: As Employee, I want to perform deleting my own comments within allowed time to achieve control over my input
**Story ID:** story-6

### Test Case: Validate successful deletion of own comment within time window
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee is logged into the system
- Employee has access to a task with commenting enabled
- Employee has posted at least one comment less than 15 minutes ago
- Database connection is active and TaskComments table is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the task details page containing the employee's own comment | Task details page loads successfully with all comments displayed |
| 2 | Locate the comment posted by the logged-in employee that is less than 15 minutes old | Comment is visible with delete option/icon displayed next to it |
| 3 | Click the delete button/icon on the eligible comment | Confirmation dialog appears asking 'Are you sure you want to delete this comment?' |
| 4 | Click the 'Confirm' or 'Yes' button in the confirmation dialog | Comment is immediately removed from the UI and success message is displayed |
| 5 | Refresh the page to verify comment removal from database | Deleted comment does not reappear, confirming database deletion |
| 6 | Access the audit log system and search for deletion events by the employee's user ID and timestamp | Audit log contains a deletion record with correct user ID, comment ID, task ID, and timestamp within 2 seconds of deletion action |

**Postconditions:**
- Comment is permanently removed from TaskComments table
- UI no longer displays the deleted comment
- Audit log contains complete deletion record
- Other comments on the task remain unaffected

---

### Test Case: Verify rejection of deletion after time window
- **ID:** tc-002
- **Type:** edge-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- Employee is logged into the system
- Employee has access to a task with commenting enabled
- Employee has posted at least one comment more than 15 minutes ago
- System time is accurately synchronized

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the task details page containing the employee's own comment posted more than 15 minutes ago | Task details page loads successfully with all comments displayed |
| 2 | Locate the comment posted by the logged-in employee that is older than 15 minutes | Comment is visible but delete option is either disabled, grayed out, or not displayed |
| 3 | Attempt to access the delete functionality (if visible) or try to submit a DELETE request via API endpoint | System blocks the action and displays error message 'Deletion window expired' or similar notification |
| 4 | Verify the error message content and clarity | Error message clearly states that comments can only be deleted within 15 minutes of posting |
| 5 | Refresh the page and verify the comment status | Comment remains visible and unchanged in both UI and database |
| 6 | Check audit logs for any deletion attempt records | Audit log may contain failed deletion attempt with appropriate rejection reason |

**Postconditions:**
- Comment remains in TaskComments table unchanged
- UI continues to display the comment
- No deletion record is created in audit log
- Employee receives clear feedback about time window expiration

---

### Test Case: Ensure confirmation prompt appears before deletion
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Employee is logged into the system
- Employee has access to a task with commenting enabled
- Employee has posted at least one comment less than 15 minutes ago
- Confirmation dialog functionality is enabled in system settings

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the task details page containing the employee's own eligible comment | Task details page loads successfully with comments displayed |
| 2 | Locate an eligible comment (posted less than 15 minutes ago) and click the delete button | Confirmation dialog immediately appears with message asking for deletion confirmation, containing 'Cancel' and 'Confirm' buttons |
| 3 | Click the 'Cancel' or 'No' button in the confirmation dialog | Confirmation dialog closes and returns to task details page without any changes |
| 4 | Verify the comment is still present in the UI | Comment remains visible and unchanged with all original content intact |
| 5 | Click the delete button again on the same comment | Confirmation dialog appears again as expected |
| 6 | Click the 'Confirm' or 'Yes' button in the confirmation dialog | Comment is successfully deleted and removed from UI within 2 seconds |
| 7 | Verify the deletion was processed in the database | Comment no longer exists in TaskComments table and audit log contains deletion record |

**Postconditions:**
- When cancelled: Comment remains in database and UI unchanged
- When confirmed: Comment is permanently deleted from database and UI
- Audit log reflects only confirmed deletion action
- User experience includes proper confirmation safeguard

---

## Story: As Employee, I want to perform receiving notifications for new comments to achieve prompt awareness
**Story ID:** story-9

### Test Case: Validate notification delivery on new comment
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Two employee accounts are active and logged in (commenter and recipient)
- Recipient employee is assigned to or associated with a task
- Notification service is running and operational
- Email service is configured and functional
- Recipient has default notification settings enabled for both in-app and email

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | As the commenter employee, navigate to the task details page | Task details page loads successfully with comment section visible |
| 2 | Enter a new comment in the comment text field (e.g., 'This is a test comment for notification') | Comment text is entered successfully in the input field |
| 3 | Click the 'Submit' or 'Add Comment' button to post the comment | Comment is saved successfully, appears in the comment list with timestamp and author name |
| 4 | As the recipient employee, check the in-app notification center within 5 seconds | New notification appears showing comment excerpt, author name (commenter), task title, and timestamp |
| 5 | Verify the notification content includes all required details | Notification displays: comment excerpt (first 50-100 characters), full author name, task ID/title, and link to task |
| 6 | Check the recipient employee's email inbox within 5 seconds | Email notification is received with subject line containing task reference |
| 7 | Open and review the email notification content | Email contains comment excerpt, author name, task details, direct link to task, and is formatted correctly |
| 8 | Click the notification link in either in-app or email notification | User is redirected to the correct task details page with the new comment visible |

**Postconditions:**
- Comment is stored in TaskComments table
- In-app notification is marked as delivered in notification logs
- Email notification is sent and logged
- Notification delivery time is recorded and within 5 seconds threshold
- Recipient can access the task directly from notification

---

### Test Case: Verify notification preference settings for comments
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 8 mins

**Preconditions:**
- Employee is logged into the system
- Notification preferences page is accessible
- Employee has default notification settings enabled
- At least one task is assigned to the employee for testing
- Another employee account exists to add comments

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to user profile or settings menu and select 'Notification Settings' or 'Preferences' | Notification settings page loads displaying all notification preference options |
| 2 | Locate the comment notification settings section | Comment notification options are visible with separate toggles for in-app and email channels |
| 3 | Disable the email notification toggle for comments while keeping in-app notifications enabled | Email toggle switches to 'Off' state while in-app toggle remains 'On' |
| 4 | Click the 'Save' or 'Update Preferences' button | Success message appears confirming 'Notification preferences saved successfully' |
| 5 | Refresh the notification settings page to verify persistence | Email notifications for comments remain disabled, in-app notifications remain enabled |
| 6 | As another employee, add a new comment to a task assigned to the test employee | Comment is posted successfully to the task |
| 7 | As the test employee, check the in-app notification center within 5 seconds | In-app notification appears with comment details as expected |
| 8 | Check the test employee's email inbox after 10 seconds | No email notification is received for the new comment |
| 9 | Verify notification logs in the system | Logs show in-app notification sent, email notification skipped due to user preference |

**Postconditions:**
- User notification preferences are saved in database
- Email notifications for comments are disabled for the user
- In-app notifications continue to function normally
- System respects user preferences for future comment notifications
- Preference changes are reflected in notification delivery logs

---

### Test Case: Ensure unauthorized users do not receive comment notifications
- **ID:** tc-006
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Three employee accounts exist: Employee A (task owner), Employee B (authorized), Employee C (unauthorized)
- A task exists assigned to Employee A and Employee B only
- Employee C has no association with the task
- Notification service is operational
- All employees have notifications enabled by default

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Verify task assignment and permissions showing Employee A and B are assigned, Employee C is not | Task permissions confirm only Employee A and B have access |
| 2 | As Employee A, navigate to the task and add a new comment | Comment is posted successfully and saved to TaskComments table |
| 3 | As Employee C (unauthorized user), check in-app notification center immediately | No notification appears for the newly added comment |
| 4 | Wait 10 seconds and check Employee C's email inbox | No email notification is received regarding the comment |
| 5 | As Employee B (authorized user), check in-app notification center | Notification appears with correct comment details |
| 6 | Access the system audit logs and filter for notification events related to the comment | Audit logs show notifications sent only to Employee B (authorized), no notification record for Employee C |
| 7 | Review notification service logs for authorization checks | Logs confirm authorization check was performed and Employee C was excluded from notification recipients |
| 8 | Verify Employee C cannot access the task directly via URL | Employee C receives 'Access Denied' or '403 Forbidden' error when attempting to view the task |

**Postconditions:**
- Only authorized users (Employee A and B) received notifications
- Unauthorized user (Employee C) received no notifications
- Audit logs accurately reflect notification recipients
- Security authorization checks are logged and verifiable
- System maintains data privacy and access control

---

## Story: As Employee, I want to perform viewing comments on tasks to achieve context understanding
**Story ID:** story-11

### Test Case: Validate display of comments with pagination
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as an authorized employee
- Task exists with more than 20 comments in the system
- User has permission to view the task and its comments
- Browser is open and network connection is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the task detail page by clicking on a task from the task list | Task detail page loads successfully and displays task information |
| 2 | Scroll down to the comments section on the task detail page | Comments section is visible and first 20 comments are displayed within 1 second |
| 3 | Verify that comments are displayed in chronological order (oldest to newest or newest to oldest based on design) | Comments are arranged in proper chronological sequence with consistent ordering |
| 4 | Check each comment for the presence of author name and timestamp | All 20 comments display the author's name and timestamp in the correct format (e.g., 'John Doe - Jan 15, 2024 10:30 AM') |
| 5 | Scroll down to the bottom of the loaded comments to trigger pagination or lazy loading | Loading indicator appears briefly and additional comments (next batch) load smoothly without page refresh |
| 6 | Continue scrolling through multiple pages of comments | Each subsequent batch of comments loads smoothly with proper author and timestamp metadata displayed |
| 7 | Verify the total number of comments matches the expected count for the task | All comments are eventually loaded and the count matches the total number of comments associated with the task |

**Postconditions:**
- All comments remain visible on the page
- User can scroll back through previously loaded comments
- No errors are logged in the browser console
- Page performance remains stable

---

### Test Case: Verify highlighting of new comments
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in as an authorized employee
- Task exists with existing comments
- User has previously viewed the task comments section
- New comments have been added to the task since the user's last visit
- System tracks last visit timestamp for the user

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the task detail page that has new comments added since last visit | Task detail page loads successfully |
| 2 | Scroll to the comments section and observe the display of comments | Comments section loads and new comments added since last visit are visually highlighted (e.g., with different background color, border, or badge) |
| 3 | Verify that only comments added after the last visit timestamp are highlighted | Only new unseen comments show the highlighting visual indicator; previously viewed comments do not have highlighting |
| 4 | Count the number of highlighted comments and cross-reference with the actual new comments added | The number of highlighted comments matches exactly with the number of new comments added since last visit (no false positives) |
| 5 | Scroll through all comments to view the highlighted new comments | All new comments remain highlighted as user scrolls through the comments section |
| 6 | Navigate away from the task detail page to another page in the application | User successfully navigates to a different page |
| 7 | Return to the same task detail page and navigate to the comments section | Comments section loads and previously highlighted comments are no longer highlighted, indicating they have been viewed |
| 8 | Refresh the browser page and check the comments section again | After page refresh, the highlighting has reset and no comments are highlighted since all have been viewed |

**Postconditions:**
- New comment highlighting state is updated in the system
- User's last visit timestamp is updated
- No comments are incorrectly highlighted on subsequent visits
- System maintains accurate tracking of viewed comments

---

### Test Case: Ensure access control for comments
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- User is logged in as an authorized employee
- Multiple tasks exist in the system with different access permissions
- At least one task exists that the user is NOT authorized to view
- At least one task exists that the user IS authorized to view
- Access control rules are properly configured in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Identify a task ID that the logged-in user is not authorized to access | Task ID is identified and confirmed to be outside user's authorization scope |
| 2 | Attempt to navigate to the unauthorized task detail page by entering the URL directly or clicking a link | System denies access and displays an appropriate error message (e.g., '403 Forbidden' or 'You do not have permission to view this task') |
| 3 | Attempt to access the comments section of the unauthorized task via direct API call (if applicable) using browser developer tools | API request returns 403 Forbidden status code and no comment data is returned |
| 4 | Verify that no comment data or metadata is visible or leaked in the error response | Error response contains no sensitive information about comments, authors, or timestamps |
| 5 | Navigate to a task that the user IS authorized to view | Task detail page loads successfully without any access restrictions |
| 6 | Scroll to the comments section of the authorized task | Comments section loads and displays all comments with author names, timestamps, and content correctly |
| 7 | Verify that all displayed comments belong to the current task and no comments from other tasks are visible | All comments displayed are associated only with the current authorized task; no data leakage from other tasks occurs |
| 8 | Check browser console and network tab for any unauthorized data requests or errors | No unauthorized API calls are made and no errors related to data leakage are present |
| 9 | Verify audit logs (if accessible) to confirm access attempts are properly logged | Audit logs show the denied access attempt for unauthorized task and successful access for authorized task |

**Postconditions:**
- User remains on an authorized page or error page
- No unauthorized data has been accessed or displayed
- Security logs reflect the access attempts accurately
- System maintains data integrity and access control

---

## Story: As Employee, I want to perform receiving notifications for comment edits to achieve awareness of changes
**Story ID:** story-12

### Test Case: Validate notification delivery on comment edit
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in as an authorized employee
- Task exists with at least one comment
- User is assigned to or has access to the task
- User has notifications enabled for comment edits (default settings)
- Email service is configured and operational
- In-app notification system is functional
- User has a valid email address registered in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the task detail page containing the comment to be edited | Task detail page loads successfully with comments section visible |
| 2 | Locate an existing comment and click on the edit button/icon for that comment | Comment edit interface opens with the current comment text displayed in an editable field |
| 3 | Modify the comment text by adding or changing content (e.g., change 'Initial comment' to 'Updated comment with new information') | Text is successfully modified in the edit field |
| 4 | Click the Save or Update button to save the edited comment | Comment is updated successfully and the new text is displayed in the comments section with an 'edited' indicator or timestamp |
| 5 | Wait for up to 5 seconds and check the in-app notification icon/bell in the application header | In-app notification appears within 5 seconds showing the comment edit notification with notification badge count incremented |
| 6 | Click on the in-app notification to view details | Notification displays correct details including: edited comment excerpt, editor's name, task name/ID, and timestamp of the edit |
| 7 | Verify the content of the notification matches the actual edit made | Notification content accurately reflects the edited comment text (excerpt) and shows who made the edit |
| 8 | Open the email client associated with the user's registered email address | Email client opens successfully |
| 9 | Check the inbox for a notification email regarding the comment edit (wait up to 5 seconds if not immediately visible) | Email notification is received within 5 seconds with subject line indicating comment edit (e.g., 'Comment Edited on Task: [Task Name]') |
| 10 | Open the email notification and review its content | Email contains accurate information including: edited comment excerpt, editor's name and details, task name/link, timestamp, and a link to view the task |
| 11 | Click on the task link in the email notification | Browser opens and navigates directly to the task detail page with the edited comment visible |

**Postconditions:**
- Comment remains in edited state with updated content
- Notification is marked as delivered in the system
- Email is successfully sent and logged
- User can access the task from notification links
- Notification delivery metrics are updated

---

### Test Case: Verify notification preference settings for comment edits
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 12 mins

**Preconditions:**
- User is logged in as an authorized employee
- User has access to notification settings page
- Task exists with at least one comment that can be edited
- Notification preferences are set to default (both in-app and email enabled)
- User has permission to modify their own notification settings

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the user profile or settings menu by clicking on the user avatar or settings icon | User menu or profile dropdown is displayed with options |
| 2 | Click on 'Notification Settings' or 'Preferences' option from the menu | Notification settings page loads successfully displaying all notification preference options |
| 3 | Locate the notification preferences section specifically for 'Comment Edits' or 'Comment Updates' | Comment edit notification preferences are visible with toggle switches or checkboxes for different notification channels (in-app, email) |
| 4 | Verify the current state of notification preferences (both in-app and email should be enabled by default) | Both in-app and email notification toggles are in the 'enabled' or 'on' state |
| 5 | Click on the email notification toggle to disable email notifications for comment edits | Email notification toggle switches to 'disabled' or 'off' state while in-app notification remains enabled |
| 6 | Click the Save or Update button to save the notification preferences | Success message appears confirming 'Notification preferences saved successfully' and the page reflects the updated settings |
| 7 | Navigate away from the settings page and then return to verify persistence | Upon returning to notification settings, email notifications for comment edits remain disabled while in-app remains enabled |
| 8 | Navigate to a task detail page with an existing comment | Task detail page loads with comments section visible |
| 9 | Edit an existing comment by modifying its text and saving the changes | Comment is successfully updated and saved with the new content displayed |
| 10 | Wait for up to 5 seconds and check the in-app notification icon | In-app notification appears within 5 seconds showing the comment edit notification |
| 11 | Verify the in-app notification contains correct details about the comment edit | In-app notification displays accurate information including edited comment excerpt and editor details |
| 12 | Check the email inbox for any notification email regarding the comment edit (wait up to 1 minute) | No email notification is received in the inbox, confirming that email notifications are disabled as per user preference |
| 13 | Verify spam/junk folder to ensure email was not misdirected | No email notification is found in spam or junk folders either |

**Postconditions:**
- User notification preferences remain saved as configured
- Only in-app notifications are sent for comment edits
- Email notifications are suppressed for comment edits
- User can re-enable email notifications at any time
- System respects user preferences for future comment edits

---

### Test Case: Ensure unauthorized users do not receive comment edit notifications
- **ID:** tc-006
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- Two users are logged into the system: User A (authorized) and User B (unauthorized)
- Task exists that is assigned to or accessible by User A only
- User B does not have access or assignment to the task
- Task contains at least one comment that can be edited
- Both users have notifications enabled for comment edits
- Audit logging is enabled in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in as User A (authorized user) and navigate to the task detail page | User A successfully accesses the task detail page with comments visible |
| 2 | As User A, locate an existing comment and click the edit button | Comment edit interface opens for User A |
| 3 | Modify the comment text with new content (e.g., 'This is an updated comment for testing') | Comment text is modified in the edit field |
| 4 | Save the edited comment by clicking the Save or Update button | Comment is successfully updated and the new text is displayed in the comments section with updated timestamp |
| 5 | Note the exact timestamp of the comment edit for audit verification | Timestamp is recorded for later verification |
| 6 | Switch to User B's session (unauthorized user) or log in as User B in a different browser/incognito window | User B is successfully logged into the system |
| 7 | As User B, check the in-app notification icon/bell for any new notifications | No notification appears for User B regarding the comment edit on the unauthorized task |
| 8 | As User B, navigate to the notifications page or notification center to view all notifications | Notification list does not contain any notification about the comment edit from the task User B is not authorized to access |
| 9 | Check User B's email inbox for any notification emails about the comment edit | No email notification is received by User B regarding the comment edit |
| 10 | Wait for up to 1 minute to ensure no delayed notifications are delivered to User B | After waiting, User B still has not received any notifications (in-app or email) about the comment edit |
| 11 | As User A or system administrator, access the audit logs or notification logs for the comment edit event | Audit logs are accessible and display notification events for the comment edit |
| 12 | Review the audit logs to verify which users received notifications for the comment edit | Audit logs show that notifications were sent only to User A (authorized user) and not to User B (unauthorized user) |
| 13 | Verify the audit log entry contains details such as: task ID, comment ID, editor name, timestamp, and list of notified users | Audit log contains complete information and confirms User B is not in the list of notified users |
| 14 | As User B, attempt to directly access the task URL to verify access control | User B is denied access to the task with appropriate error message (403 Forbidden or similar) |

**Postconditions:**
- Comment remains in edited state
- Only authorized users received notifications
- No data leakage occurred to unauthorized users
- Audit logs accurately reflect notification distribution
- System maintains security and access control integrity
- User B remains unaware of the task and comment edit

---

