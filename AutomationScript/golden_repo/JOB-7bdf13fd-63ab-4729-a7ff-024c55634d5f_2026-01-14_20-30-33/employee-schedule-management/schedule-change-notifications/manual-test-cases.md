# Manual Test Cases

## Story: As Employee, I want to receive notifications of schedule changes to stay informed
**Story ID:** story-5

### Test Case: Validate display of schedule change notifications on login
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Employee account exists in the system with valid credentials
- At least one schedule change has been made for the employee within the last 30 days
- ScheduleChanges table contains recent entries linked to the employee
- API endpoint GET /api/notifications/scheduleChanges is operational
- Employee is not currently logged into the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the employee web portal login page | Login page is displayed with username and password fields |
| 2 | Enter valid employee credentials (username and password) | Credentials are accepted and login button is enabled |
| 3 | Click the login button | Employee is successfully authenticated and redirected to the dashboard |
| 4 | Observe the notification panel on the dashboard | Notification panel is visible and displays recent schedule change notifications within 2 seconds of login |
| 5 | Review the details of each notification displayed | Each notification shows accurate change type (added, modified, or cancelled), shift date, shift time, and location information |
| 6 | Verify the timestamp of each notification | Notifications display when the schedule change occurred and are sorted by most recent first |
| 7 | Click on a notification to mark it as read | The selected notification is visually marked as read with a different background color or read indicator |
| 8 | Click the dismiss or close button on the marked notification | The notification is removed from the main notification panel view |
| 9 | Refresh the page | Previously dismissed notifications remain hidden and read status is persisted |

**Postconditions:**
- Employee remains logged into the system
- Marked notifications are stored as read in the database
- Dismissed notifications are hidden from the main notification panel
- Notification history is updated with read status

---

### Test Case: Verify notification history accessibility
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 6 mins

**Preconditions:**
- Employee is logged into the web portal
- Employee has schedule change notifications from various dates within the past 30 days
- Employee has schedule change notifications older than 30 days in the system
- Notification history feature is enabled and accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Locate and click on the notification history link or icon in the navigation menu | Notification history page or section is displayed |
| 2 | Observe the list of notifications displayed in the history section | All notifications from the past 30 days are displayed in chronological order with complete details |
| 3 | Verify the date range of displayed notifications | The oldest notification displayed is no more than 30 days old from the current date |
| 4 | Check for any notifications older than 30 days in the history list | No notifications older than 30 days are visible in the notification history |
| 5 | Scroll through the notification history to view all entries | All notifications within the 30-day window are accessible and display complete information including change type, shift details, and timestamp |
| 6 | Filter or search for a specific notification within the 30-day period if filtering is available | Filtering functionality works correctly and returns relevant notifications within the 30-day retention period |

**Postconditions:**
- Employee remains on the notification history page
- Notification history data remains unchanged
- 30-day retention policy is confirmed to be enforced

---

### Test Case: Ensure unauthorized users cannot access notifications
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Employee web portal is accessible via browser
- User is not currently logged into the system
- Authentication and authorization mechanisms are active
- Direct URL to notifications endpoint is known for testing purposes

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open a web browser and navigate directly to the notifications page URL without logging in | Access is denied and user is automatically redirected to the login page |
| 2 | Observe any error messages or notifications displayed | An appropriate error message is displayed indicating authentication is required (e.g., 'Please log in to access this page' or 'Unauthorized access') |
| 3 | Attempt to access the API endpoint GET /api/notifications/scheduleChanges directly without authentication token | API returns 401 Unauthorized status code and access is denied |
| 4 | Try to access notifications using an invalid or expired authentication token | Access is denied with 401 Unauthorized response and user is redirected to login |
| 5 | Verify that no notification data is exposed in the response or browser | No sensitive notification data or employee schedule information is visible or accessible |
| 6 | Confirm the login page is displayed with proper authentication fields | Login page is shown with username and password fields ready for credential entry |

**Postconditions:**
- User remains unauthenticated
- No unauthorized access to notification data has occurred
- Security logs record the unauthorized access attempt
- User is positioned at the login page ready to authenticate

---

