# Manual Test Cases

## Story: As Employee, I want to receive notifications about schedule changes to stay informed
**Story ID:** story-15

### Test Case: Validate notification generation on schedule change
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Admin user account exists and has permissions to modify schedules
- Employee user account exists and is active in the system
- Employee has an assigned schedule in the system
- Web interface is accessible and functional
- Authentication system is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in to the system as an admin user with valid credentials | Admin is successfully authenticated and redirected to the admin dashboard |
| 2 | Navigate to the schedule management section | Schedule management interface is displayed with list of employees and their schedules |
| 3 | Select the target employee's schedule from the list | Employee's current schedule details are displayed and editable |
| 4 | Modify the employee's schedule (change shift time, date, or assignment) | Schedule modification form accepts the changes |
| 5 | Save the schedule changes | System confirms schedule update is saved successfully and a notification is generated for the employee |
| 6 | Log out from the admin account | Admin is successfully logged out |
| 7 | Log in to the web interface as the employee whose schedule was changed | Employee is successfully authenticated and redirected to the employee dashboard |
| 8 | Observe the notification area on the web interface | Notification about the schedule change is displayed prominently (e.g., banner, badge, or notification icon with count) |
| 9 | Click on the notification to view details | Notification details are displayed showing the schedule change information (old vs new schedule) |
| 10 | Click the acknowledge button on the notification | Notification is marked as read, removed from the active notifications list, and confirmation message is displayed |
| 11 | Verify the notification is no longer in the active notifications list | Notification counter decreases and the acknowledged notification is not visible in active list |

**Postconditions:**
- Schedule change is saved in the database
- Notification is marked as read in the system
- Notification is moved to notification history
- Employee is aware of the schedule change

---

### Test Case: Verify notification delivery within 5 minutes
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Admin user account exists with schedule modification permissions
- Employee user account exists and is active
- Employee has an assigned schedule
- System time is synchronized and accurate
- Notification service is running and operational
- API endpoint GET /api/notifications is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in to the system as an admin user | Admin is successfully authenticated and can access schedule management |
| 2 | Navigate to the schedule management section and select an employee's schedule | Employee's schedule is displayed and ready for editing |
| 3 | Note the current system time before making changes | Current timestamp is recorded for reference |
| 4 | Make a change to the employee's schedule (modify shift time or date) | Schedule change is accepted by the system |
| 5 | Save the schedule changes and note the exact time of save | System confirms schedule is saved with timestamp displayed |
| 6 | Wait for 1 minute after saving the schedule change | Time elapses to 1 minute mark |
| 7 | Verify notification generation in the backend system or database within 1 minute of schedule change | Notification record is created in the system with timestamp within 1 minute of schedule change |
| 8 | Log in to the web interface as the affected employee within 5 minutes of the schedule change | Employee is successfully authenticated and dashboard loads |
| 9 | Check the notification area immediately upon login | Notification about the schedule change is visible and accessible |
| 10 | Verify the notification timestamp shows it was generated within 5 minutes of the schedule change | Notification timestamp confirms delivery within the 5-minute SLA requirement |

**Postconditions:**
- Notification is successfully delivered within 5 minutes
- Performance metric for notification delivery is met
- Notification remains visible until acknowledged or dismissed

---

### Test Case: Ensure employees can dismiss notifications
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 6 mins

**Preconditions:**
- Employee user account exists and is logged in
- At least one unread notification exists for the employee
- Notification is displayed on the web interface
- API endpoint POST /api/notifications/acknowledge is functional

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in to the web interface as an employee with pending notifications | Employee is successfully authenticated and notification indicator shows unread notifications |
| 2 | Navigate to the notifications section or click on the notification indicator | List of notifications is displayed with details of schedule changes |
| 3 | Select a specific notification to view its details | Notification details are expanded showing full information about the schedule change |
| 4 | Verify that a dismiss button or dismiss option is visible on the notification | Dismiss button is clearly visible and accessible (e.g., 'Dismiss', 'X', or similar UI element) |
| 5 | Click the dismiss button on the notification | System processes the dismiss action and shows a brief confirmation (e.g., 'Notification dismissed') |
| 6 | Verify the notification is removed from the active notifications list | Dismissed notification is no longer visible in the active notifications area |
| 7 | Check the notification counter or badge | Notification count decreases by one, reflecting the dismissed notification |
| 8 | Navigate to notification history (if available) to verify dismissed notification is archived | Dismissed notification appears in history with 'dismissed' or 'read' status |
| 9 | Refresh the page or log out and log back in | Dismissed notification remains dismissed and does not reappear in active notifications |

**Postconditions:**
- Notification is marked as dismissed in the database
- Notification is removed from active notifications list
- Notification counter is updated accurately
- Dismissed notification is stored in notification history

---

