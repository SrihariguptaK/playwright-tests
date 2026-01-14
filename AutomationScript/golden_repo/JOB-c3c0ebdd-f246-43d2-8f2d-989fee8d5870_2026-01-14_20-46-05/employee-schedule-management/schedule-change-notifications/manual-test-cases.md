# Manual Test Cases

## Story: As Employee, I want to receive notifications of schedule changes to stay informed of updates
**Story ID:** story-17

### Test Case: Validate display of schedule change notifications
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Employee account exists in the system with valid credentials
- Employee has at least one scheduled shift in the system
- Schedule change event database is accessible
- API endpoint GET /api/notifications is operational
- Browser supports real-time updates

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the application login page | Login page is displayed with username and password fields |
| 2 | Enter valid employee credentials and click login button | Employee is successfully authenticated and redirected to the schedule dashboard |
| 3 | Verify the schedule dashboard loads completely | Schedule dashboard is displayed with all components loaded within 2 seconds, including notification area |
| 4 | Trigger a schedule change event (modify an existing shift time for the logged-in employee) | A new notification appears on the dashboard in real-time without requiring page refresh, displaying details of the schedule change |
| 5 | Verify notification content and visibility | Notification is prominently displayed with clear information about the schedule change (shift date, time, type of change) |
| 6 | Click the acknowledge button on the notification | Notification status changes to acknowledged and the notification is removed from the active notification list |
| 7 | Verify the notification counter updates | Active notification count decreases by one |

**Postconditions:**
- Notification is marked as acknowledged in the database
- Notification is moved to archived notifications
- Employee remains logged in on the schedule dashboard
- No active notifications are displayed for the acknowledged change

---

### Test Case: Verify notification history accessibility
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 6 mins

**Preconditions:**
- Employee account exists in the system with valid credentials
- At least one notification has been previously acknowledged by the employee
- Notification history database contains archived notifications
- API endpoint for notification history is operational
- Employee has permission to access notification history

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the application login page | Login page is displayed with username and password fields |
| 2 | Enter valid employee credentials and click login button | Employee is successfully authenticated and redirected to the schedule dashboard |
| 3 | Verify the schedule dashboard loads completely | Schedule dashboard is displayed with all navigation options visible |
| 4 | Locate and click on the notification history section or link | System navigates to the notification history page |
| 5 | Verify archived notifications are displayed | All previously acknowledged notifications are displayed in chronological order with complete details (date, time, change type, acknowledgment timestamp) |
| 6 | Verify notification history loads within performance requirements | Notification history page loads within 2 seconds |
| 7 | Verify only employee-specific notifications are shown | Only notifications belonging to the logged-in employee are displayed in the history |

**Postconditions:**
- Employee remains logged in
- Notification history remains accessible for future reference
- No changes are made to notification statuses
- Employee can navigate back to the main dashboard

---

## Story: As Employee, I want to acknowledge schedule notifications to confirm I have seen updates
**Story ID:** story-18

### Test Case: Validate notification acknowledgment process
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Employee account exists with valid credentials
- At least one unacknowledged schedule change notification exists for the employee
- API endpoint POST /api/notifications/acknowledge is operational
- Employee has active session and is logged in
- Notification history feature is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the application login page | Login page is displayed with username and password fields |
| 2 | Enter valid employee credentials and click login button | Employee is successfully authenticated and redirected to the schedule dashboard |
| 3 | Verify schedule dashboard displays with active notifications | Schedule dashboard is displayed with at least one unacknowledged notification visible in the notification area |
| 4 | Note the notification details (content, timestamp) and the current count of active notifications | Notification details are clearly visible and notification count is displayed |
| 5 | Click the acknowledge button on the notification | System processes the acknowledgment request within 1 second and displays a confirmation indicator |
| 6 | Verify notification status updates immediately | Notification status changes to acknowledged and the notification is removed from the active notification list without page refresh |
| 7 | Verify the active notification count decreases | Active notification counter decreases by one |
| 8 | Navigate to the notification history section | Notification history page is displayed |
| 9 | Verify the acknowledged notification appears in history | The previously acknowledged notification is listed in archived notifications with acknowledgment timestamp and status marked as acknowledged |
| 10 | Verify notification details match the original notification | All notification details (content, original timestamp, schedule change information) match the original notification |

**Postconditions:**
- Notification status is updated to acknowledged in the database
- Notification is removed from active notifications list
- Notification is archived and accessible in notification history
- Employee remains logged in on the dashboard
- No duplicate notifications exist for the same change

---

### Test Case: Verify acknowledgment access control
- **ID:** tc-004
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Two employee accounts exist in the system (Employee A and Employee B)
- Employee A has at least one unacknowledged notification
- Employee B is logged into the system
- API endpoint POST /api/notifications/acknowledge has proper authorization checks
- Security controls are enabled for notification ownership validation

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in as Employee B using valid credentials | Employee B is successfully authenticated and redirected to their schedule dashboard |
| 2 | Verify Employee B's dashboard loads with their own notifications | Dashboard displays only notifications belonging to Employee B |
| 3 | Obtain the notification ID of an unacknowledged notification belonging to Employee A | Notification ID for Employee A's notification is identified |
| 4 | Attempt to acknowledge Employee A's notification using Employee B's session (via direct API call or URL manipulation) | System denies the acknowledgment action |
| 5 | Verify error message is displayed | System displays an appropriate error message indicating insufficient permissions or unauthorized access (e.g., 'You do not have permission to acknowledge this notification' or 'Access Denied') |
| 6 | Verify Employee A's notification status remains unchanged | Employee A's notification remains in unacknowledged state and is still visible in Employee A's active notifications |
| 7 | Verify no changes were made to Employee B's notification list | Employee B's notification list remains unchanged and does not include Employee A's notification |
| 8 | Log out Employee B and log in as Employee A | Employee A successfully logs in and sees their dashboard |
| 9 | Verify Employee A's notification is still unacknowledged | The notification that Employee B attempted to acknowledge is still present in Employee A's active notification list with unacknowledged status |

**Postconditions:**
- Employee A's notification remains unacknowledged
- No unauthorized changes were made to the notification database
- Security audit log records the unauthorized access attempt
- Employee B's session remains active and unaffected
- System security controls are validated as functioning correctly

---

