# Manual Test Cases

## Story: As Employee, I want to receive notifications of schedule changes to stay informed
**Story ID:** story-10

### Test Case: Validate real-time delivery of schedule change notifications
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Employee account exists in the system with valid credentials
- Employee has at least one scheduled shift in the system
- Backend system is operational and accessible
- ScheduleChangeEvents API is functioning correctly
- Employee is not currently logged into the web interface

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Access the backend system with administrator privileges | Administrator is successfully logged into the backend system |
| 2 | Navigate to the employee schedule management section | Schedule management interface is displayed with list of employees and their schedules |
| 3 | Locate the target employee's schedule and modify a shift (change time, date, or location) | Schedule modification form is displayed and accepts the changes |
| 4 | Save the schedule changes and note the exact timestamp | Schedule is updated successfully and confirmation message is displayed |
| 5 | Wait for up to 1 minute and monitor the notification generation | Notification is generated and sent to the employee within 1 minute of the schedule update |
| 6 | Employee logs into the web interface using valid credentials | Employee is successfully authenticated and redirected to the dashboard |
| 7 | Navigate to the notifications section or view the notification indicator | Notifications section is accessible and displays a notification badge or count indicating new notifications |
| 8 | Click on the notifications section to view all notifications | New schedule change notification is visible with details of the schedule modification, timestamp, and unread status |
| 9 | Click on the acknowledge button or mark as read option for the notification | Notification status changes to 'read' or 'acknowledged' with visual confirmation (e.g., color change, checkmark icon) |
| 10 | Refresh the notifications page | Notification remains marked as read and is moved to the read notifications section or displays read status |

**Postconditions:**
- Schedule change is saved in the system
- Notification is marked as read in the database
- Employee is aware of the schedule change
- Notification delivery time is logged and within 1 minute threshold

---

### Test Case: Verify notification visibility and security
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Two employee accounts exist: Employee A and Employee B with valid credentials
- Both employees have different schedules in the system
- Schedule changes have been made for both Employee A and Employee B
- Notifications have been generated for both employees
- Role-based access control is configured correctly

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into the web interface using Employee A's credentials | Employee A is successfully authenticated and redirected to their dashboard |
| 2 | Navigate to the notifications section | Notifications page is displayed for Employee A |
| 3 | Review all visible notifications and verify the content | Only notifications relevant to Employee A are visible, showing schedule changes specific to Employee A's shifts |
| 4 | Verify that no notifications belonging to Employee B or any other employee are displayed | No notifications for other employees are visible in Employee A's notification list |
| 5 | Log out from Employee A's account | Employee A is successfully logged out and redirected to the login page |
| 6 | Log into the web interface using Employee B's credentials | Employee B is successfully authenticated and redirected to their dashboard |
| 7 | Navigate to the notifications section | Notifications page is displayed for Employee B |
| 8 | Review all visible notifications and verify the content | Only notifications relevant to Employee B are visible, showing schedule changes specific to Employee B's shifts |
| 9 | Verify that Employee A's notifications are not visible to Employee B | Employee B does not see any of Employee A's notifications, confirming proper data isolation |
| 10 | Attempt to access Employee A's notification directly via URL manipulation (if notification IDs are predictable) | Access is denied with appropriate error message (403 Forbidden or similar) and Employee B cannot view Employee A's notification |

**Postconditions:**
- Employee A can only access their own notifications
- Employee B can only access their own notifications
- Data privacy is maintained between employee accounts
- Security logs record any unauthorized access attempts

---

### Test Case: Test notification history accessibility
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 6 mins

**Preconditions:**
- Employee account exists with valid credentials
- Employee has received multiple schedule change notifications over time
- Notification history includes both read and unread notifications
- At least 5 notifications exist in the system for the employee
- Employee is logged into the web interface

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | From the employee dashboard, locate and click on the notifications section or notification history link | Notifications page or notification history section is displayed |
| 2 | Verify that the notification history section is accessible and loads properly | Notification history page loads successfully without errors |
| 3 | Review the list of notifications displayed in the history | All past notifications are listed in chronological order (newest first or oldest first based on design) |
| 4 | Verify that each notification displays its read/unread status clearly | Each notification shows a clear visual indicator of read status (e.g., bold text for unread, different background color, read/unread icon) |
| 5 | Check that unread notifications are visually distinct from read notifications | Unread notifications are clearly distinguishable from read notifications through visual styling |
| 6 | Verify that each notification includes relevant details (schedule change details, timestamp, notification type) | Each notification displays complete information including what changed, when it was sent, and the affected schedule |
| 7 | Scroll through the notification history to verify all notifications are accessible | All historical notifications are accessible through scrolling or pagination |
| 8 | Click on an individual notification to view full details | Notification expands or opens to show complete details of the schedule change |
| 9 | Verify that the notification count matches the total number of notifications received | The total count of notifications in history matches the expected number of schedule changes |

**Postconditions:**
- Employee has viewed their complete notification history
- All notifications remain in the system for future reference
- Read/unread status is accurately reflected for all notifications

---

## Story: As Employee, I want to acknowledge schedule change notifications to confirm awareness
**Story ID:** story-12

### Test Case: Validate acknowledgment of a notification
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Employee account exists with valid credentials
- Employee is logged into the web interface
- At least one unacknowledged schedule change notification exists for the employee
- POST /api/notifications/{id}/acknowledge endpoint is operational
- Employee has proper role-based access permissions

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the notifications section from the employee dashboard | Notifications page is displayed with list of schedule change notifications |
| 2 | Locate an unacknowledged schedule change notification in the list | Unacknowledged notification is visible with schedule change details and unacknowledged status |
| 3 | Verify that the notification displays an acknowledge button or checkbox | Acknowledge button is clearly visible and enabled on the notification |
| 4 | Review the notification content to ensure it contains schedule change information | Notification displays complete schedule change details including date, time, and nature of change |
| 5 | Click the acknowledge button on the notification | System processes the acknowledgment request and sends POST request to /api/notifications/{id}/acknowledge |
| 6 | Observe the system response and visual feedback | Immediate visual confirmation is displayed (e.g., success message, checkmark icon, color change) within 1 second |
| 7 | Verify that the notification status has updated to acknowledged | Notification status changes to 'acknowledged' with visual indicator (e.g., different background, acknowledged badge) |
| 8 | Check that the acknowledge button is no longer available or is disabled | Acknowledge button is either removed, disabled, or replaced with 'Acknowledged' label |
| 9 | Attempt to click the acknowledge button or area again | System prevents duplicate acknowledgment - button is disabled or no action occurs |
| 10 | Refresh the notifications page | Notification remains in acknowledged status and duplicate acknowledgment is still prevented |
| 11 | Verify in the notification history that the acknowledgment timestamp is recorded | Notification shows acknowledgment timestamp and acknowledged status is persisted |

**Postconditions:**
- Notification status is updated to acknowledged in the database
- Acknowledgment timestamp is recorded
- Employee cannot acknowledge the same notification again
- Management can track that the employee has acknowledged the schedule change

---

### Test Case: Verify acknowledgment access control
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- At least one schedule change notification exists in the system
- User is not currently authenticated in the web interface
- Login page is accessible
- Role-based access control is properly configured
- Session management is functioning correctly

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open a web browser and ensure no user is currently logged in (clear session/cookies if necessary) | Browser session is cleared and no authentication tokens are present |
| 2 | Attempt to directly access the notifications page URL without logging in | System detects unauthenticated access and redirects to the login page |
| 3 | Attempt to send a POST request to /api/notifications/{id}/acknowledge endpoint without authentication token | API returns 401 Unauthorized error and rejects the acknowledgment request |
| 4 | Verify that the error response includes appropriate message indicating authentication is required | Error message clearly states that authentication is required to perform this action |
| 5 | Navigate to the login page | Login page is displayed with username and password fields |
| 6 | Verify that the user is prompted to log in before accessing notifications | Login form is presented and user cannot proceed without valid credentials |
| 7 | Attempt to use an invalid or expired authentication token to acknowledge a notification | System rejects the request with 401 Unauthorized or 403 Forbidden error |
| 8 | Verify that the system redirects unauthenticated users to the login page | User is automatically redirected to login page with appropriate message |
| 9 | Check that no notification data is exposed to unauthenticated users | No notification content or details are visible without proper authentication |

**Postconditions:**
- Unauthenticated access attempts are logged for security monitoring
- No notifications are acknowledged without proper authentication
- User is redirected to login page
- System security is maintained and unauthorized actions are prevented

---

