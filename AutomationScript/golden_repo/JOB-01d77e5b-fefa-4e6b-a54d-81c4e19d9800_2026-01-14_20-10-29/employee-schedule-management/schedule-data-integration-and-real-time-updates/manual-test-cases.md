# Manual Test Cases

## Story: As Employee, I want to receive notifications for schedule changes to stay informed
**Story ID:** story-13

### Test Case: Validate schedule change notification delivery
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Employee account exists and is active in the system
- Employee has an assigned schedule
- Administrator/Manager has permissions to update schedules
- System notification service is running
- Employee is not currently logged in

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Administrator/Manager accesses the schedule management system and updates the employee's schedule (e.g., changes shift time from 9:00 AM to 10:00 AM) | Schedule update is saved successfully in the ScheduleChanges table and a notification is generated and queued for the employee |
| 2 | Wait for notification processing (maximum 1 minute) | Notification is processed and marked as ready for delivery within 1 minute of the schedule change |
| 3 | Employee logs into the web interface using valid credentials | Employee is successfully authenticated and redirected to the dashboard with a prominent notification alert displayed indicating schedule change |
| 4 | Employee clicks on the notification alert to view details | Notification details are displayed showing the specific schedule change information (old time vs new time, date, shift details) |
| 5 | Employee clicks the 'Mark as Read' button on the notification | Notification status changes to 'Read', the alert badge is removed or decremented, and the notification is moved to the notification history/archive |
| 6 | Employee navigates to the notification history section | Previously read notification is visible in the history with timestamp and 'Read' status indicator |

**Postconditions:**
- Notification is marked as read in the database
- Notification is archived and accessible in history
- Employee's schedule displays the updated information
- No active notification alerts remain for this schedule change

---

### Test Case: Verify notification access control
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Two employee accounts exist: Employee A and Employee B
- Employee A has a schedule change notification pending
- Employee B is logged into the system
- Both employees have active accounts with different credentials
- Security and authentication mechanisms are enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Employee B is logged in and attempts to access the notifications endpoint for Employee A by manipulating the URL or API request (e.g., GET /api/notifications/schedule-changes?employeeId=EmployeeA) | System validates the authentication token and detects unauthorized access attempt |
| 2 | System processes the unauthorized access request | Access is denied with HTTP 403 Forbidden or 401 Unauthorized status code, and an error message is displayed: 'You do not have permission to view these notifications' or similar |
| 3 | Verify that Employee B can only see their own notifications by navigating to their notification page | Only notifications belonging to Employee B are displayed; no notifications from Employee A are visible |
| 4 | Check system logs for the unauthorized access attempt | Security log entry is created documenting the unauthorized access attempt with timestamp, user ID, and attempted resource |

**Postconditions:**
- Employee A's notifications remain secure and unaccessed by Employee B
- Employee B only has access to their own notifications
- Security audit log contains record of the access attempt
- No data breach or unauthorized information disclosure occurred

---

## Story: As Employee, I want to receive confirmation that my schedule is up to date when I log in
**Story ID:** story-20

### Test Case: Validate schedule status message on login
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Employee account exists and is active
- Employee has a schedule assigned in the system
- System has access to schedule timestamp data
- API endpoint GET /api/schedules/status is functional
- Employee is not currently logged in

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Verify that the employee's schedule data has been updated within the acceptable timeframe (e.g., within the last 24 hours or as per system configuration) | Schedule last updated timestamp is current and within acceptable threshold |
| 2 | Employee enters valid credentials and clicks the login button | Employee is successfully authenticated and redirected to the dashboard |
| 3 | System automatically checks schedule data freshness by calling GET /api/schedules/status | API returns status indicating schedule is current with timestamp information |
| 4 | Observe the dashboard or schedule page immediately after login | A prominent confirmation banner or message is displayed stating 'Schedule is up to date' with a success indicator (e.g., green checkmark or banner) |
| 5 | Simulate outdated schedule data by setting the schedule last updated timestamp to an old date (e.g., more than 48 hours ago) in the test database | Schedule timestamp is successfully updated to reflect outdated data |
| 6 | Log out the employee and log back in with the same credentials | Employee is successfully authenticated and redirected to the dashboard |
| 7 | System automatically checks schedule data freshness by calling GET /api/schedules/status | API returns status indicating schedule is outdated with timestamp information |
| 8 | Observe the dashboard or schedule page immediately after login | A prominent warning banner or message is displayed stating 'Your schedule may be outdated. Please contact your manager for the latest updates' or similar warning message with a warning indicator (e.g., yellow/orange banner or icon) |

**Postconditions:**
- Appropriate status message (confirmation or warning) is displayed based on schedule data currency
- Employee is informed of their schedule status immediately upon login
- Schedule data timestamp remains unchanged
- Employee can proceed to view their schedule with awareness of its currency status

---

