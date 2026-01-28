# Manual Test Cases

## Story: As Employee, I want to view my notification history to achieve better tracking of past updates
**Story ID:** db-story-story-2

### Test Case: Verify employee can access notification history for the last 30 days
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- Employee account is created and active in the system
- Employee has valid login credentials
- Employee has received at least 5 notifications within the last 30 days
- Notification history database is accessible
- System is up and running

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the system login page | Login page is displayed with username and password fields |
| 2 | Enter valid employee credentials and click Login button | Employee is successfully authenticated and redirected to the dashboard |
| 3 | Locate and click on the Notification History menu option or icon | Notification History page is displayed |
| 4 | Observe the list of notifications displayed on the page | All notifications from the last 30 days are displayed in chronological order with date, time, and notification summary |
| 5 | Verify the date range of notifications displayed | All notifications shown are within the last 30 days from current date, no notifications older than 30 days are visible |
| 6 | Check the page load time from step 3 to step 4 | Notification history loads and displays within 2 seconds |

**Postconditions:**
- Employee remains logged into the system
- Notification history page is displayed with all notifications from last 30 days
- No data is modified in the system

---

### Test Case: Verify search functionality for specific notifications within history
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- Employee is logged into the system
- Employee has access to notification history page
- Multiple notifications exist in the history with different content and keywords
- At least one notification contains the keyword 'meeting' in the last 30 days

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the Notification History page | Notification History page is displayed with list of notifications and search functionality visible |
| 2 | Locate the search input field on the notification history page | Search input field is visible and enabled for text entry |
| 3 | Enter the keyword 'meeting' in the search field | Text 'meeting' is entered in the search field |
| 4 | Click the Search button or press Enter key | Search is executed and results are filtered |
| 5 | Review the filtered notification list | Only notifications containing the keyword 'meeting' are displayed in the results |
| 6 | Clear the search field and verify results | All notifications from the last 30 days are displayed again without filters |

**Postconditions:**
- Search functionality is working correctly
- Employee can view filtered or unfiltered notification history
- No notifications are deleted or modified

---

### Test Case: Verify notification details are displayed clearly and accurately
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- Employee is logged into the system
- Employee has navigated to the Notification History page
- At least one notification exists in the history with complete details (title, message, timestamp, sender)

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | View the list of notifications in the notification history | List of notifications is displayed with summary information for each notification |
| 2 | Select a specific notification from the list by clicking on it | Notification is highlighted or selected, and detailed view is opened |
| 3 | Review the notification details displayed | Complete notification details are shown including: notification title, full message content, date and time sent, sender information, and notification type |
| 4 | Verify the timestamp format and accuracy | Timestamp is displayed in readable format (e.g., DD/MM/YYYY HH:MM) and matches the actual time the notification was sent |
| 5 | Check the readability and formatting of the notification content | Text is clearly readable with appropriate font size, proper spacing, and correct formatting without any truncation or display issues |
| 6 | Close the notification detail view | Detail view closes and user returns to the notification history list |

**Postconditions:**
- Notification details are accurately displayed
- Employee can view complete information for any notification
- User interface remains responsive and clear

---

### Test Case: Verify user can delete notifications from their history
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 3 mins

**Preconditions:**
- Employee is logged into the system
- Employee has navigated to the Notification History page
- At least 3 notifications exist in the employee's notification history
- Employee has permission to delete notifications from their own history

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | View the notification history list and count the total number of notifications | Notification list is displayed with at least 3 notifications, total count is noted |
| 2 | Select a notification to delete by clicking on it or hovering over it | Notification is selected and delete option/button becomes visible |
| 3 | Click on the Delete button or delete icon for the selected notification | Confirmation dialog appears asking 'Are you sure you want to delete this notification?' |
| 4 | Click Confirm or Yes button in the confirmation dialog | Confirmation dialog closes and notification is removed from the list |
| 5 | Verify the notification is no longer visible in the history list | Deleted notification is not displayed in the list, total count is reduced by 1 |
| 6 | Refresh the notification history page | Page refreshes and the deleted notification remains absent from the list, confirming permanent deletion |

**Postconditions:**
- Selected notification is permanently deleted from employee's history
- Remaining notifications are still visible and accessible
- Total notification count is updated correctly

---

### Test Case: Verify notification history does not display notifications older than 30 days
- **ID:** tc-005
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee is logged into the system
- Test data includes notifications that are exactly 30 days old, 31 days old, and within the last 30 days
- System date and time are correctly configured
- Notification history database contains notifications spanning more than 30 days

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the Notification History page | Notification History page is displayed with list of notifications |
| 2 | Review all notifications displayed and note the oldest notification date | All notifications displayed have dates within the last 30 days from current date |
| 3 | Verify that notifications exactly 30 days old are visible | Notifications that are exactly 30 days old from current date are displayed in the list |
| 4 | Attempt to search or scroll for notifications older than 30 days | No notifications older than 30 days are found or displayed in the history |
| 5 | Check if there is any option or filter to view notifications older than 30 days | No option exists to view notifications beyond the 30-day limit |

**Postconditions:**
- Only notifications within 30-day window are accessible
- System enforces the 30-day retention policy correctly
- No data integrity issues are present

---

### Test Case: Verify notification history requires user authentication
- **ID:** tc-006
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- Employee account exists in the system
- Employee is not currently logged into the system
- Notification history page URL is known
- Security authentication is enabled on the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open a web browser and ensure no user is logged into the system | Browser is open with no active user session |
| 2 | Attempt to directly access the notification history page by entering the URL (e.g., /notifications/history) | Access is denied and user is redirected to the login page |
| 3 | Verify that an appropriate error message or authentication prompt is displayed | Message displayed: 'Please log in to access this page' or 'Authentication required' |
| 4 | Enter valid employee credentials on the login page | Employee is successfully authenticated and logged into the system |
| 5 | Navigate to the notification history page after successful login | Notification history page is accessible and displays the employee's notification history |

**Postconditions:**
- Unauthorized access to notification history is prevented
- Security authentication is enforced correctly
- Authenticated users can access their notification history

---

### Test Case: Verify notification history loads within 2 seconds performance requirement
- **ID:** tc-007
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee is logged into the system
- Employee's notification history contains at least 20 notifications
- Network connection is stable with normal bandwidth
- System is under normal load conditions
- Performance monitoring tool or browser developer tools are available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open browser developer tools and navigate to the Network tab | Developer tools are open and Network tab is active for monitoring |
| 2 | Clear browser cache and refresh the page to ensure clean test | Cache is cleared and page is ready for fresh load |
| 3 | Start timer and click on the Notification History menu option | Navigation to notification history is initiated and timer is running |
| 4 | Monitor the page load time until notification history is fully displayed | Notification history page loads completely with all notifications visible |
| 5 | Stop timer and record the total load time from click to full display | Total load time is recorded and is 2 seconds or less |
| 6 | Review the Network tab to verify API response time for GET /api/notifications/history | API endpoint responds successfully with status 200 and contributes to overall load time within acceptable limits |

**Postconditions:**
- Performance requirement of 2 seconds load time is met
- Notification history is fully functional after load
- System performance is within acceptable parameters

---

### Test Case: Verify employee can only view their own notification history
- **ID:** tc-008
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Two employee accounts exist: Employee A and Employee B
- Both employees have notifications in their respective histories
- Employee A is logged into the system
- User permission validation is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in as Employee A with valid credentials | Employee A is successfully logged into the system |
| 2 | Navigate to the Notification History page | Notification history page is displayed showing Employee A's notifications |
| 3 | Review all notifications displayed and verify ownership | All notifications displayed belong to Employee A only, no notifications from other employees are visible |
| 4 | Attempt to manipulate URL parameters to access Employee B's notification history (e.g., change user ID in URL) | Access is denied with error message 'Unauthorized access' or user is redirected to their own notification history |
| 5 | Verify that no API calls can retrieve other employees' notification data | API endpoint GET /api/notifications/history returns only Employee A's notifications and rejects requests for other users' data |

**Postconditions:**
- Employee A can only access their own notification history
- Security and privacy controls are functioning correctly
- Unauthorized access attempts are blocked and logged

---

### Test Case: Verify notification history displays empty state when no notifications exist
- **ID:** tc-009
- **Type:** edge-case
- **Priority:** Low
- **Estimated Time:** 3 mins

**Preconditions:**
- New employee account is created in the system
- Employee has never received any notifications
- Employee is logged into the system
- Notification history database is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in as the new employee with no notification history | Employee is successfully logged into the system |
| 2 | Navigate to the Notification History page | Notification History page loads successfully |
| 3 | Observe the content displayed on the notification history page | Empty state message is displayed such as 'No notifications found' or 'You have no notification history' |
| 4 | Verify that the page layout and UI elements are properly displayed | Page displays correctly with appropriate empty state icon or graphic, no errors or broken elements are visible |
| 5 | Verify search functionality behavior with no notifications | Search field is either disabled or returns 'No results found' message when used |

**Postconditions:**
- Empty state is handled gracefully with appropriate messaging
- No errors occur when notification history is empty
- User interface remains functional and user-friendly

---

### Test Case: Verify canceling delete operation does not remove notification from history
- **ID:** tc-010
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 3 mins

**Preconditions:**
- Employee is logged into the system
- Employee has navigated to the Notification History page
- At least one notification exists in the history
- Delete confirmation dialog is implemented in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | View the notification history list and select a specific notification to delete | Notification is selected and delete option is visible |
| 2 | Note the details of the selected notification (title, date, content) | Notification details are recorded for verification |
| 3 | Click on the Delete button for the selected notification | Confirmation dialog appears asking 'Are you sure you want to delete this notification?' with Cancel and Confirm options |
| 4 | Click the Cancel or No button in the confirmation dialog | Confirmation dialog closes without deleting the notification |
| 5 | Verify the notification is still present in the history list | The notification remains in the list with all original details intact |
| 6 | Refresh the page and verify the notification is still present | After page refresh, the notification is still visible in the history confirming no deletion occurred |

**Postconditions:**
- Notification remains in the history unchanged
- Cancel operation functions correctly
- No unintended data modifications occur

---

