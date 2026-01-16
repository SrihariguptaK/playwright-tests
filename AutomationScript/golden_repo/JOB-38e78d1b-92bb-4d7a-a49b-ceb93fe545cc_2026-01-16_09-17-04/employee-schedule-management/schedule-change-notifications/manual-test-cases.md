# Manual Test Cases

## Story: As Employee, I want to receive notifications of schedule changes to stay informed and avoid conflicts
**Story ID:** story-15

### Test Case: Validate display of schedule change notifications on login
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee account exists and is active in the system
- Employee has valid login credentials
- At least one schedule change exists for the employee in ScheduleChangeEvents table
- Schedule changes have not been dismissed by the employee
- Web portal is accessible and functional
- API endpoint GET /api/notifications/scheduleChanges is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the web portal login page | Login page is displayed with username and password fields |
| 2 | Enter valid employee credentials (username and password) | Credentials are accepted and login button is enabled |
| 3 | Click the login button to authenticate | Employee is successfully authenticated and redirected to the dashboard |
| 4 | Observe the dashboard page immediately after login | Notification banner appears prominently at the top of the page indicating schedule changes exist |
| 5 | Review the notification banner content | Banner displays summary information including number of schedule changes and a prompt to view details |
| 6 | Click on the notification banner or 'View Details' link | Notification details panel expands or opens showing comprehensive information |
| 7 | Review the detailed notification information | Detailed information is displayed including: type of change (shift added/removed/modified), date and time of affected shift, previous shift details (if modified), new shift details, and timestamp of when change was made |

**Postconditions:**
- Employee remains logged into the system
- Notification remains visible and undismissed
- Notification details are accessible for further review
- Employee session is active

---

### Test Case: Verify notification dismissal functionality
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Employee is logged into the web portal
- At least one schedule change notification is visible to the employee
- Notification has not been previously dismissed
- Employee has access to dismiss notifications functionality
- Database connection is active for updating notification status

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Locate the visible schedule change notification on the dashboard | Notification banner is displayed with schedule change information |
| 2 | Identify the dismiss button or close icon on the notification | Dismiss button (X icon or 'Dismiss' button) is visible and clickable on the notification |
| 3 | Click the dismiss button on the notification | Notification immediately disappears from the view with a smooth animation or transition |
| 4 | Verify the notification is no longer visible on the current page | Notification banner is completely removed from the dashboard and no longer displayed |
| 5 | Refresh the browser page (F5 or refresh button) | Page reloads successfully and dismissed notification does not reappear |
| 6 | Log out of the web portal | Employee is successfully logged out and redirected to login page |
| 7 | Log back into the web portal with the same employee credentials | Employee successfully logs in and is redirected to dashboard |
| 8 | Check the dashboard for the previously dismissed notification | Previously dismissed notification does not reappear on the dashboard |

**Postconditions:**
- Notification status is updated to 'dismissed' in the database
- Dismissed notification is moved to notification history
- Employee remains logged into the system
- No active notifications are displayed for the dismissed change

---

### Test Case: Test notification visibility restricted to affected employee
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Two or more employee accounts exist in the system (Employee A and Employee B)
- Employee A has schedule changes with pending notifications
- Employee B has no schedule changes or different schedule changes than Employee A
- Both employees have valid login credentials
- Web portal is accessible
- Security and authentication mechanisms are properly configured

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in as Employee A who has pending schedule change notifications | Employee A successfully logs in and notification banner appears showing their schedule changes |
| 2 | Note the specific details of Employee A's schedule change notifications (date, time, shift details) | Specific notification details are visible and documented for Employee A |
| 3 | Log out of Employee A's account | Employee A is successfully logged out and redirected to login page |
| 4 | Log in as Employee B using their valid credentials | Employee B successfully logs in and is redirected to their dashboard |
| 5 | Check the dashboard for any schedule change notifications | No notifications related to Employee A's schedule changes are displayed |
| 6 | Verify that only Employee B's own notifications (if any exist) are visible | Only notifications specific to Employee B's schedule changes are shown, or no notifications appear if Employee B has no changes |
| 7 | Attempt to access notification history or notification details | Employee B can only see their own notification history and cannot access Employee A's notifications |
| 8 | Verify API response by checking network traffic (if applicable) | API GET /api/notifications/scheduleChanges returns only notifications where employeeId matches Employee B's ID |

**Postconditions:**
- Employee B remains logged in with access only to their own data
- Employee A's notifications remain private and inaccessible to Employee B
- Security and data isolation is maintained
- No unauthorized data exposure has occurred

---

