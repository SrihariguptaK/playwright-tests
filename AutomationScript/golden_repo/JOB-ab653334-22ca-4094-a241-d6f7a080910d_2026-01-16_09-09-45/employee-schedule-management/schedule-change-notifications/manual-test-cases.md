# Manual Test Cases

## Story: As Employee, I want to receive notifications of schedule changes to stay informed and avoid conflicts
**Story ID:** story-15

### Test Case: Validate display of schedule change notifications on login
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee account exists in the system with valid credentials
- At least one schedule change exists for the employee in ScheduleChangeEvents table
- Schedule changes have not been previously dismissed by the employee
- Web portal is accessible and functional
- API endpoint GET /api/notifications/scheduleChanges is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the web portal login page | Login page is displayed with username and password fields |
| 2 | Enter valid employee credentials (username and password) | Credentials are accepted and login button is enabled |
| 3 | Click the login button to authenticate | Employee is successfully authenticated and redirected to the dashboard |
| 4 | Observe the dashboard for notification banner upon login | Notification banner appears prominently at the top of the page indicating pending schedule changes |
| 5 | Review the notification banner content | Banner displays summary of schedule changes including number of changes and brief description |
| 6 | Click on the notification banner or 'View Details' link | Notification details panel expands or opens showing comprehensive information |
| 7 | Review the detailed notification information | Detailed information is displayed including: type of change (shift added/removed/modified), date and time of affected shift, original vs new shift details, and timestamp of when change was made |

**Postconditions:**
- Employee remains logged into the system
- Notification remains visible and undismissed
- Notification details are accessible for further review
- No data is modified in the system

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
- Employee has authenticated access to dismiss notifications
- Database connection is active to persist dismissal state

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Locate the visible schedule change notification on the dashboard | Notification banner is displayed with schedule change details |
| 2 | Identify the dismiss button or 'X' icon on the notification | Dismiss control (button or icon) is visible and clickable on the notification |
| 3 | Click the dismiss button to remove the notification | Notification immediately disappears from the screen with smooth transition or animation |
| 4 | Verify the notification is no longer visible on the current page | Notification banner is completely removed from the dashboard view |
| 5 | Log out of the web portal | Employee is successfully logged out and redirected to login page |
| 6 | Log back into the web portal using the same employee credentials | Employee is successfully authenticated and redirected to dashboard |
| 7 | Check the dashboard for the previously dismissed notification | The dismissed notification does not reappear on the dashboard |
| 8 | Navigate to notification history section if available | Dismissed notification appears in history with 'dismissed' or 'acknowledged' status |

**Postconditions:**
- Notification is marked as dismissed in the database
- Dismissed notification does not appear on subsequent logins
- Notification remains in history for audit purposes
- Employee session remains active
- Other undismissed notifications (if any) remain visible

---

### Test Case: Test notification visibility restricted to affected employee
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Two or more employee accounts exist in the system (Employee A and Employee B)
- Employee A has pending schedule changes with active notifications
- Employee B has no schedule changes or different schedule changes than Employee A
- Both employees have valid login credentials
- Security and authentication mechanisms are properly configured
- API correctly filters notifications by employeeId parameter

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in as Employee A who has pending schedule change notifications | Employee A is successfully logged in and notification banner appears showing their schedule changes |
| 2 | Note the specific details of Employee A's schedule change notifications (shift date, time, type of change) | Notification details are clearly visible and documented for comparison |
| 3 | Log out of Employee A's account | Employee A is successfully logged out and redirected to login page |
| 4 | Log in as Employee B using their valid credentials | Employee B is successfully authenticated and redirected to their dashboard |
| 5 | Observe the dashboard for any schedule change notifications | No notifications related to Employee A's schedule changes are displayed |
| 6 | Check if Employee B sees only their own notifications (if any exist) | Only notifications specific to Employee B's schedule changes are visible, completely separate from Employee A's notifications |
| 7 | Attempt to access notification history or details section | Employee B can only view their own notification history with no access to Employee A's notifications |
| 8 | Verify API call includes correct employeeId parameter for Employee B | API request shows GET /api/notifications/scheduleChanges?employeeId={Employee B's ID} with proper authentication token |

**Postconditions:**
- Employee B remains logged in with access only to their own data
- No data leakage between employee accounts
- Security and privacy controls are validated
- Employee A's notifications remain intact and unaffected
- Audit logs show separate access patterns for each employee

---

