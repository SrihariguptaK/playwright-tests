# Manual Test Cases

## Story: As Employee, I want to receive notifications for schedule changes to stay informed
**Story ID:** story-12

### Test Case: Validate notification generation and display for schedule changes
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Employee account exists in the system with valid credentials
- Employee has at least one scheduled shift in the system
- Manager/Admin has permissions to modify employee schedules
- Notification system is operational and configured
- Employee is not currently logged into the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in as Manager/Admin with valid credentials | Manager/Admin successfully logs in and dashboard is displayed |
| 2 | Navigate to the schedule management section | Schedule management interface loads with current employee schedules visible |
| 3 | Select the target employee's existing shift and modify the schedule (change time, date, or location) | Schedule modification form is displayed with current shift details |
| 4 | Save the schedule change | System confirms schedule change is saved successfully and notification is generated in the system |
| 5 | Log out as Manager/Admin | Manager/Admin is successfully logged out |
| 6 | Log in as the affected employee using valid credentials | Employee successfully logs in and dashboard is displayed |
| 7 | Navigate to the notifications section in the web interface | Notifications page loads displaying all notifications for the employee |
| 8 | Verify the new schedule change notification is displayed with details of the change | New notification is visible showing schedule change details (date, time, shift information) with unread status indicator |
| 9 | Click on the notification to mark it as read | Notification is marked as read and visual indicator changes (e.g., bold text becomes normal, unread badge disappears) |
| 10 | Refresh the notifications page | Notification status remains as read and the updated status persists in the UI |
| 11 | Log out as employee | Employee is successfully logged out |

**Postconditions:**
- Notification is generated and stored in the database
- Notification status is marked as read in the system
- Schedule change is reflected in employee's schedule
- Employee is logged out of the system

---

### Test Case: Verify notification access control
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Two employee accounts exist in the system (Employee A and Employee B)
- Employee A has valid login credentials
- Employee B has at least one notification in the system
- Authentication and authorization mechanisms are properly configured
- API endpoint GET /api/notifications is secured with authentication

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in as Employee A with valid credentials | Employee A successfully logs in and dashboard is displayed |
| 2 | Navigate to the notifications section | Notifications page loads displaying only Employee A's notifications |
| 3 | Attempt to access Employee B's notifications by manipulating the URL or API request (e.g., changing employee ID parameter) | System denies access and displays an error message indicating 'Access Denied' or 'Unauthorized' (HTTP 403 or 401) |
| 4 | Verify that no notification data from Employee B is visible or accessible | No notifications belonging to Employee B are displayed or returned in the response |
| 5 | Check browser console or network tab for error response | Error response confirms authorization failure with appropriate error code and message |
| 6 | Log out as Employee A | Employee A is successfully logged out |

**Postconditions:**
- Employee A remains unable to access Employee B's notifications
- Security audit log records the unauthorized access attempt
- Employee A is logged out of the system
- No data breach or unauthorized data access occurred

---

### Test Case: Test notification delivery timing
- **ID:** tc-003
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Employee account exists with valid credentials
- Employee has at least one scheduled shift
- Manager/Admin has permissions to modify schedules
- System clock is synchronized and accurate
- Notification delivery system is operational
- Employee is logged into the system with notifications page open

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in as Employee and navigate to the notifications section | Employee successfully logs in and notifications page is displayed |
| 2 | Note the current timestamp and number of existing notifications | Current time is recorded and baseline notification count is established |
| 3 | In a separate browser session, log in as Manager/Admin and navigate to schedule management | Manager/Admin successfully accesses schedule management interface |
| 4 | Record the exact timestamp and make a schedule change for the logged-in employee | Schedule change is saved with timestamp recorded (T0) |
| 5 | Return to the employee's browser session and refresh the notifications page every 10 seconds | Notifications page refreshes and displays updated notification list |
| 6 | Record the timestamp when the new notification appears in the employee's interface | New notification is visible with timestamp recorded (T1) |
| 7 | Calculate the time difference between schedule change (T0) and notification delivery (T1) | Time difference is calculated: (T1 - T0) |
| 8 | Verify that the notification delivery time is within 1 minute (60 seconds) of the schedule change | Notification delivery time (T1 - T0) is less than or equal to 60 seconds, meeting the performance requirement |
| 9 | Log out from both employee and manager sessions | Both users are successfully logged out |

**Postconditions:**
- Notification was delivered within the 1-minute SLA
- Schedule change is reflected in the system
- Performance metric is recorded for monitoring
- Both users are logged out of the system

---

