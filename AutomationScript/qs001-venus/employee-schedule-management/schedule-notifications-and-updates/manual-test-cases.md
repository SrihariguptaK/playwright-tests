# Manual Test Cases

## Story: As Employee, I want to receive notifications about schedule changes to stay informed
**Story ID:** story-16

### Test Case: Validate notification display on schedule update
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Employee account exists and is active in the system
- Employee has at least one scheduled shift
- Admin user has permissions to modify employee schedules
- Notification system is enabled and operational
- Employee is not currently logged into the portal

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Admin user logs into the system with valid credentials | Admin is successfully authenticated and redirected to the admin dashboard |
| 2 | Admin navigates to the schedule management section | Schedule management interface is displayed with current employee schedules |
| 3 | Admin selects the employee's existing schedule entry | Employee's schedule details are displayed and editable |
| 4 | Admin modifies the schedule (e.g., changes shift time from 9:00 AM to 10:00 AM) and saves the changes | Schedule is successfully updated, confirmation message is displayed, and schedule change event is triggered in the system |
| 5 | Employee navigates to the portal login page and enters valid credentials | Employee is successfully authenticated and redirected to the employee dashboard |
| 6 | Employee observes the dashboard for notification indicators | Visual notification indicator (e.g., badge, icon, or banner) is prominently displayed indicating new schedule changes |
| 7 | Employee clicks on the notification indicator to view notification details | Notification panel opens displaying the schedule change details including date, old time, new time, and change timestamp |
| 8 | Employee verifies the notification content matches the schedule change made by admin | Notification shows correct schedule change information: shift time changed from 9:00 AM to 10:00 AM with accurate date and details |

**Postconditions:**
- Notification is displayed in the employee's notification list
- Schedule change is reflected in the employee's schedule view
- Notification remains unacknowledged until employee takes action
- Admin remains logged in to the system

---

### Test Case: Verify notification acknowledgment process
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Employee is logged into the portal
- Employee has at least one unacknowledged notification in the system
- Notification history feature is enabled
- Database is accessible for storing acknowledgment status

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Employee navigates to the notifications section from the dashboard | Notifications panel is displayed showing all unacknowledged notifications with visual indicators |
| 2 | Employee locates the schedule change notification and clicks the 'Acknowledge' button | Notification status changes to 'Acknowledged', visual indicator (e.g., checkmark or color change) appears, and confirmation message is displayed |
| 3 | Employee verifies the notification is no longer in the unacknowledged list | Notification is removed from the unacknowledged notifications list or moved to acknowledged section |
| 4 | Employee clicks on 'Notification History' or 'View All Notifications' link | Notification history page is displayed showing all notifications including acknowledged and unacknowledged ones |
| 5 | Employee locates the previously acknowledged notification in the history | Acknowledged notification is present in the history with 'Acknowledged' status, acknowledgment timestamp, and complete details are visible |
| 6 | Employee clicks the logout button to end the current session | Employee is successfully logged out and redirected to the login page, session is terminated |
| 7 | Employee logs back into the portal using valid credentials | Employee is successfully authenticated and redirected to the dashboard |
| 8 | Employee navigates to the notification history section | Notification history is displayed with all previous notifications |
| 9 | Employee verifies the previously acknowledged notification still shows as acknowledged | Previously acknowledged notification remains marked as 'Acknowledged' with the original acknowledgment timestamp, status persists across sessions |

**Postconditions:**
- Notification acknowledgment status is permanently saved in the database
- Notification history accurately reflects all acknowledgment actions
- Employee session is active after re-login
- No unacknowledged notifications remain for the tested notification

---

### Test Case: Test notification delivery time
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Admin user has permissions to modify schedules
- Employee account exists with scheduled shifts
- System clock is synchronized and accurate
- Notification service is running and operational
- Employee is ready to log in immediately after schedule update
- Timing measurement tool or system logs are available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Record the current system timestamp before making any changes | Baseline timestamp is recorded for comparison (e.g., T0 = 10:00:00) |
| 2 | Admin logs into the system and navigates to schedule management | Admin is authenticated and schedule management interface is displayed |
| 3 | Admin updates the employee's schedule (e.g., adds a new shift or modifies existing shift) and saves the changes | Schedule update is saved successfully, and exact timestamp of the update is recorded (e.g., T1 = 10:00:05) |
| 4 | Verify in system logs or database that notification generation event was triggered | Notification record is created in the database with generation timestamp, status shows as 'Pending' or 'Sent' |
| 5 | Employee logs into the portal within 30 seconds of the schedule update | Employee is successfully authenticated and redirected to the dashboard (e.g., T2 = 10:00:25) |
| 6 | Employee immediately checks for notification indicators on the dashboard | Notification indicator is displayed showing the schedule change notification |
| 7 | Employee clicks on the notification to view details and records the notification timestamp | Notification details are displayed with creation timestamp visible (e.g., notification created at 10:00:06) |
| 8 | Calculate the time difference between schedule update (T1) and notification generation timestamp | Time difference is less than or equal to 60 seconds, meeting the 1-minute SLA requirement |
| 9 | Verify in system logs that no delays or errors occurred during notification processing | System logs show successful notification processing with no errors, delays, or retry attempts beyond the 1-minute threshold |

**Postconditions:**
- Notification delivery time is documented and meets SLA of 1 minute or less
- Notification is successfully delivered and visible to employee
- System logs contain complete audit trail of notification generation and delivery
- Schedule update is reflected in employee's schedule view
- Performance metrics are recorded for monitoring

---

