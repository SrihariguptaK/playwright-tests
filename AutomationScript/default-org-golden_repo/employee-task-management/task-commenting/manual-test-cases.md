# Manual Test Cases

## Story: As Employee, I want to add comments to tasks to achieve effective communication
**Story ID:** story-12

### Test Case: Validate successful comment addition with valid input
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- Employee is logged into the system with valid credentials
- Employee has authorization to view and comment on tasks
- At least one task exists in the system that the employee can access
- Network connectivity is stable
- Comments table is accessible and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Employee navigates to task details page by selecting a task from the task list | Task details page loads successfully within 2 seconds, displaying task information and comments section at the bottom or designated area |
| 2 | Employee locates the comment input field in the comments section and enters valid comment text (e.g., 'This task is progressing well. Expected completion by Friday.') | Comment text is accepted and displayed in the input field without any validation errors. Character count indicator (if present) shows text is within allowed limit |
| 3 | Employee clicks the 'Submit' or 'Add Comment' button to post the comment | Comment is saved successfully to the database. The new comment appears immediately in the comments section with the employee's name, timestamp, and comment text. Success confirmation message is displayed. Notifications are sent to relevant stakeholders |

**Postconditions:**
- Comment is persisted in the Comments table with correct taskId association
- Comment is visible to all authorized users who can view the task
- Comment displays correct user attribution and timestamp
- Comment input field is cleared and ready for new input
- Relevant team members receive notifications about the new comment

---

### Test Case: Reject comment submission with empty or too long text
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- Employee is logged into the system with valid credentials
- Employee has authorization to comment on tasks
- Employee is on a task details page with comments section visible
- System has defined maximum comment length limit (e.g., 1000 characters)
- Validation rules are configured and active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Employee leaves the comment input field empty (no text entered) and clicks the 'Submit' or 'Add Comment' button | System displays a validation error message (e.g., 'Comment text is required' or 'Please enter a comment before submitting'). Comment is not saved to the database. Submit button may be disabled or form submission is blocked |
| 2 | Employee enters comment text that exceeds the maximum allowed length (e.g., enters 1500 characters when limit is 1000) and attempts to submit | System displays a validation error message (e.g., 'Comment exceeds maximum length of 1000 characters' or 'Please shorten your comment'). Character count indicator shows text is over limit in red. Comment is not saved to the database. Submission is blocked until text is within limit |

**Postconditions:**
- No invalid comment is saved to the database
- Comment input field retains the invalid text for user to correct
- Error messages are clearly visible to the user
- System remains in stable state ready for valid input
- No notifications are sent for failed submissions

---

### Test Case: Prevent unauthorized user from adding comments
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- Unauthorized user has access to the system (either not logged in, or logged in without proper permissions)
- Task exists in the system
- Authorization and authentication checks are properly configured
- Security middleware is active and enforcing access controls

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Unauthorized user attempts to navigate to task details page or directly access the comments API endpoint POST /api/tasks/{taskId}/comments with a comment payload | System performs authentication and authorization checks. Access is denied with HTTP 401 (Unauthorized) or 403 (Forbidden) status code. Authorization error message is displayed (e.g., 'You do not have permission to add comments to this task' or 'Access denied'). Comment input field is either hidden or disabled. No comment is saved to the database |

**Postconditions:**
- No unauthorized comment is created in the database
- Security event is logged in the system audit trail
- User is redirected to login page (if not authenticated) or shown access denied message (if authenticated but unauthorized)
- Task data remains unchanged
- System security integrity is maintained

---

## Story: As Employee, I want to edit my recent comments to correct mistakes and clarify information
**Story ID:** story-13

### Test Case: Validate successful comment edit within allowed time
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- Employee is logged into the system with valid credentials
- Employee has previously posted a comment on a task
- The comment was posted less than 15 minutes ago
- Employee has authorization to edit their own comments
- Edit history table is accessible and operational
- System time is accurately synchronized

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Employee navigates to the task details page containing their recent comment posted within the last 15 minutes | Task details page loads successfully. Employee's comment is displayed with an 'Edit' button or icon visible next to it, indicating the comment is eligible for editing |
| 2 | Employee clicks the 'Edit' button on their comment | Comment text becomes editable in an input field or text area. Original comment text is pre-populated. 'Save' and 'Cancel' buttons appear. Edit mode is clearly indicated |
| 3 | Employee modifies the comment text (e.g., corrects a typo or adds clarifying information) and clicks 'Save' or 'Submit' button | System validates the edit request (ownership and time window check pass). Comment is updated in the database within 2 seconds. Updated comment text is displayed immediately. Edit indicator (e.g., 'Edited' label or timestamp) is shown next to the comment. Edit history is logged with timestamp and user details. Success confirmation message appears |

**Postconditions:**
- Comment text is updated in the Comments table
- Edit history record is created in the edit history table with original text, new text, timestamp, and user ID
- Updated comment displays 'Edited' indicator to all viewers
- Comment retains original creation timestamp but shows last edited timestamp
- Edit mode is exited and comment returns to read-only view
- All authorized users see the updated comment text

---

### Test Case: Reject comment edit outside allowed time window
- **ID:** tc-005
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- Employee is logged into the system with valid credentials
- Employee has previously posted a comment on a task
- The comment was posted more than 15 minutes ago
- Edit time window is configured to 15 minutes
- System time validation is functioning correctly

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Employee navigates to the task details page containing their comment that was posted more than 15 minutes ago | Task details page loads successfully. Employee's comment is displayed but the 'Edit' button or icon is either not visible, disabled (grayed out), or shows a tooltip indicating edit time has expired |
| 2 | Employee attempts to edit the comment (if edit option is still clickable) or hovers over the disabled edit button | System validates the edit time window and determines it has expired. Edit functionality is blocked. Informative message is displayed (e.g., 'Comments can only be edited within 15 minutes of posting' or 'Edit time window has expired'). Comment remains in read-only state and cannot be modified |

**Postconditions:**
- Comment text remains unchanged in the database
- No edit history record is created
- User is informed of the time restriction policy
- Comment continues to display in its original form
- System enforces business rule consistently

---

### Test Case: Prevent editing of others' comments
- **ID:** tc-006
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- Employee is logged into the system with valid credentials
- Another user has posted a comment on a task
- The other user's comment was posted within the last 15 minutes (within edit window)
- Employee has access to view the task and comments
- Ownership verification is properly configured in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Employee navigates to task details page and views a comment posted by another user | Task details page loads successfully. Other user's comment is visible but no 'Edit' button or option appears for the employee on comments they did not author, regardless of how recent the comment is |
| 2 | Employee attempts to edit another user's comment by directly accessing the edit API endpoint PUT /api/comments/{commentId} or through any other means | System performs ownership verification check. Access is denied with HTTP 403 (Forbidden) status code. Authorization error message is displayed (e.g., 'You can only edit your own comments' or 'Access denied: insufficient permissions'). Comment remains unchanged. Security event is logged |

**Postconditions:**
- Other user's comment remains unchanged in the database
- No edit history record is created
- Security violation attempt is logged in audit trail
- Employee cannot modify content they do not own
- System maintains data integrity and ownership controls
- Original comment author retains full control over their content

---

