# Manual Test Cases

## Story: As Employee, I want to receive notifications of schedule changes to stay informed and avoid missed shifts
**Story ID:** story-11

### Test Case: Validate display of schedule change notifications on login
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Employee account exists and is active in the system
- Employee has valid login credentials
- At least one schedule change has been made for the employee within the last 24 hours
- Schedule change notification has been generated in ScheduleChangeNotifications table
- Employee has not yet logged in since the schedule change occurred
- Web application is accessible and running

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule portal login page | Login page is displayed with username and password fields |
| 2 | Enter valid employee credentials (username and password) | Credentials are accepted and login button is enabled |
| 3 | Click the login button | Employee is successfully authenticated and redirected to the main dashboard |
| 4 | Observe the notification area on the dashboard | New schedule change notifications are displayed prominently in a notification panel or banner with visual indicators (e.g., badge count, highlighted section) |
| 5 | Review the notification content | Notification displays complete details including change type (new/updated/canceled), date of change, shift date, shift time, and any relevant shift information |
| 6 | Click on the notification to view full details | Notification expands or opens to show comprehensive information about the schedule change |
| 7 | Click the acknowledge button or mark as read option on the notification | Notification is marked as read, visual indicator changes (e.g., color change, opacity reduction), and notification is removed from the new notifications list |
| 8 | Verify the notification counter or badge | Notification count decreases by one and updates in real-time |
| 9 | Refresh the page or navigate away and return to dashboard | Previously acknowledged notification remains marked as read and does not reappear in new notifications |

**Postconditions:**
- Employee remains logged into the system
- Notification is marked as read in the database
- Notification is moved from unread to read status
- Employee is aware of the schedule change
- Notification history is updated with acknowledgment timestamp

---

### Test Case: Verify notification history accessibility
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Employee is logged into the schedule portal
- Employee has received multiple schedule change notifications over time (at least 5 historical notifications)
- Some notifications are marked as read and some as unread
- Notification history feature is enabled in the system
- Employee has proper permissions to access notification history

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Locate the notification icon or menu in the navigation bar | Notification icon is visible with current unread notification count displayed |
| 2 | Click on the notification icon or menu | Notification dropdown or panel opens showing recent notifications |
| 3 | Locate and click on 'View All Notifications' or 'Notification History' link | System navigates to the notification history page |
| 4 | Observe the notification history page layout | Page displays a comprehensive list of all past notifications in chronological order (newest first) |
| 5 | Verify the details displayed for each notification entry | Each notification shows accurate details including: change type (new/updated/canceled), shift date, shift time, notification timestamp, read/unread status, and any additional shift information |
| 6 | Check the visual distinction between read and unread notifications | Read and unread notifications are clearly differentiated through visual styling (e.g., bold text for unread, different background colors) |
| 7 | Scroll through the notification history list | All historical notifications are accessible and properly paginated or infinitely scrollable |
| 8 | Click on a specific historical notification to view full details | Notification expands or opens a detail view showing complete information about that specific schedule change |
| 9 | Verify the timestamp accuracy of notifications | Each notification displays the correct date and time when the schedule change occurred and when the notification was generated |
| 10 | Apply any available filters (if present) such as date range or notification type | Notification list filters correctly based on selected criteria |

**Postconditions:**
- Employee remains on the notification history page or returns to dashboard
- All notification data remains intact and unchanged
- Notification history is available for future reference
- No notifications are lost or corrupted

---

### Test Case: Test access control for notifications
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Two employee accounts exist in the system: Employee A and Employee B
- Employee A is logged into the schedule portal
- Employee B has schedule change notifications in the system
- Access control and authorization mechanisms are properly configured
- API endpoint security is enabled
- Employee A does not have administrative privileges

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | As Employee A, navigate to the notification history page | Employee A's notification history page loads successfully showing only their own notifications |
| 2 | Note Employee A's employee ID from the URL or profile section | Employee A's ID is visible (e.g., employeeId=123 in URL or profile) |
| 3 | Attempt to manually modify the URL to access Employee B's notifications by changing the employeeId parameter (e.g., change employeeId=123 to employeeId=456) | System detects unauthorized access attempt |
| 4 | Press Enter to navigate to the modified URL | Access denied error message is displayed (e.g., '403 Forbidden' or 'You do not have permission to view these notifications') |
| 5 | Verify that no notification data from Employee B is visible on the page | No unauthorized notification information is displayed; page shows only error message or redirects to Employee A's own notifications |
| 6 | Open browser developer tools and attempt to make a direct API call to GET /api/notifications?scheduleChanges&employeeId={Employee B's ID} | API returns 403 Forbidden status code with appropriate error message |
| 7 | Verify the response body of the API call | Response contains error message indicating insufficient permissions and no notification data is returned |
| 8 | Attempt to access notification details directly using a notification ID that belongs to Employee B | Access is denied and error message is displayed |
| 9 | Check the application logs (if accessible) for security events | Unauthorized access attempt is logged with appropriate details (timestamp, employee ID, attempted resource) |
| 10 | Return to Employee A's legitimate notification page | Employee A can successfully access their own notifications without any issues |

**Postconditions:**
- Employee A remains logged in with access only to their own notifications
- Employee B's notification data remains secure and inaccessible to Employee A
- Security logs contain record of unauthorized access attempt
- No data breach or unauthorized access occurred
- System security integrity is maintained

---

