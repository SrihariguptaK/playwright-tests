# Manual Test Cases

## Story: As Employee, I want to receive notifications about schedule changes to stay informed
**Story ID:** story-16

### Test Case: Validate display of schedule change notifications on login
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Employee account exists and is active in the system
- Employee has valid login credentials
- At least one unread schedule change notification exists for the employee in ScheduleChangeNotifications table
- Web portal is accessible and functional
- Employee is not currently logged in

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the web portal login page | Login page is displayed with username and password fields |
| 2 | Enter valid employee credentials and click login button | Employee is successfully authenticated and redirected to the dashboard |
| 3 | Observe the notification area on the dashboard upon login | Notification banner or icon is displayed prominently indicating there are unread notifications |
| 4 | Click on the notification banner or icon to view notification details | Notification panel opens displaying the schedule change notification with complete details including date, time, shift information, and change description |
| 5 | Review the notification details for accuracy | All notification details are displayed correctly and match the schedule change information |
| 6 | Click the 'Mark as Read' button or option on the notification | Notification is marked as read, visual indicator changes (e.g., notification becomes grayed out or moves to read section) |
| 7 | Refresh the page or navigate away and return to the notifications area | The notification remains in the read state, confirming status persistence |
| 8 | Log out from the web portal | Employee is successfully logged out and redirected to login page |
| 9 | Log back in with the same employee credentials | Employee logs in successfully and the previously marked notification remains in read status, confirming persistence across sessions |

**Postconditions:**
- Notification status is updated to 'read' in the ScheduleChangeNotifications table
- Notification no longer appears in the unread notifications list
- Notification status persists across sessions
- Employee remains logged in or is logged out based on final action

---

### Test Case: Verify notifications are only shown to relevant employees
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Multiple employee accounts exist in the system
- Schedule change notifications exist for specific employees in ScheduleChangeNotifications table
- Test employee account has at least one notification assigned to them
- Other employees have different notifications not related to the test employee
- Web portal is accessible and functional
- Employee is not currently logged in

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Identify and document the notifications assigned to the test employee in the database | List of notification IDs and details specific to the test employee is documented |
| 2 | Navigate to the web portal login page | Login page is displayed successfully |
| 3 | Enter the test employee's valid credentials and click login | Test employee is successfully authenticated and redirected to the dashboard |
| 4 | Access the notifications section by clicking on the notification banner or icon | Notifications panel opens displaying a list of notifications |
| 5 | Review all displayed notifications and compare them with the documented list from step 1 | Only notifications related to the test employee's schedule are displayed; no notifications belonging to other employees are shown |
| 6 | Verify each notification contains information relevant to the logged-in employee (employee ID, name, or schedule details) | All notifications contain the test employee's information and are relevant to their schedule changes |
| 7 | Check that the notification count matches the expected number of notifications for this employee | Notification count is accurate and matches the number of notifications assigned to the test employee in the database |

**Postconditions:**
- Only employee-specific notifications are displayed
- No unauthorized access to other employees' notifications occurred
- Employee remains logged in
- Notification data integrity is maintained

---

## Story: As Employee, I want to dismiss notifications to manage my notification list effectively
**Story ID:** story-17

### Test Case: Validate notification dismissal process
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee is logged into the web portal
- At least one active notification exists for the employee
- Notification is visible in the employee's notification list
- POST /api/notifications/dismiss endpoint is functional
- Employee has authenticated access to dismiss notifications

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the notifications section on the dashboard | Notifications panel is displayed with a list of active notifications |
| 2 | Identify a notification to dismiss and note its details (ID, content) | Target notification is clearly visible with dismiss option available |
| 3 | Click the 'Dismiss' button or icon on the selected notification | Confirmation dialog is displayed asking 'Are you sure you want to dismiss this notification?' with 'Confirm' and 'Cancel' options |
| 4 | Review the confirmation dialog message | Confirmation message is clear and provides context about the dismissal action |
| 5 | Click the 'Confirm' button in the confirmation dialog | Confirmation dialog closes and the notification is immediately removed from the active notification list |
| 6 | Verify the notification is no longer visible in the notification list | The dismissed notification is not present in the active notification list |
| 7 | Check the backend database or use API to verify notification status | Notification status in ScheduleChangeNotifications table is updated to 'dismissed' and the change is persisted |
| 8 | Refresh the page to confirm the dismissal persists | Dismissed notification remains removed from the list after page refresh |

**Postconditions:**
- Notification is removed from the active notification list
- Notification status is updated to 'dismissed' in the backend database
- Dismissal action is persisted across sessions
- Employee remains logged in
- Other notifications remain unaffected

---

### Test Case: Verify dismissal action completes within performance SLA
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 7 mins

**Preconditions:**
- Employee is logged into the web portal
- At least one active notification exists for the employee
- Network connection is stable
- Performance monitoring tool or browser developer tools are available to measure response time
- POST /api/notifications/dismiss endpoint is functional

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open browser developer tools and navigate to the Network tab | Developer tools are open and Network tab is active for monitoring API calls |
| 2 | Navigate to the notifications section on the dashboard | Notifications panel is displayed with active notifications |
| 3 | Start timing or prepare to monitor the network request timing | Timer is ready or network monitoring is active |
| 4 | Click the 'Dismiss' button on a notification | Confirmation dialog is displayed |
| 5 | Click 'Confirm' in the confirmation dialog and monitor the API call timing | POST request to /api/notifications/dismiss is initiated and visible in Network tab |
| 6 | Observe the time taken for the notification to be removed from the UI | Notification is removed from the list and the entire dismissal action completes within 2 seconds |
| 7 | Check the Network tab for the API response time of the dismiss endpoint | API response time is recorded and is within 2 seconds, meeting the performance SLA |
| 8 | Repeat the dismissal process for 2-3 additional notifications to ensure consistent performance | All dismissal actions complete within 2 seconds consistently |

**Postconditions:**
- All tested notifications are dismissed successfully
- Performance SLA of 2 seconds is met for all dismissal actions
- Backend status is updated for all dismissed notifications
- Employee remains logged in
- Performance metrics are documented

---

