# Manual Test Cases

## Story: As Employee, I want to receive notifications of schedule changes to stay informed
**Story ID:** story-16

### Test Case: Validate real-time notification display on dashboard
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 20 mins

**Preconditions:**
- Employee account exists in the system with valid credentials
- Employee is assigned to at least one shift in the schedule
- Employee has access to the web portal
- ScheduleChangeEvents table is accessible and functional
- Notification service is running and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in to the employee portal using valid credentials | Employee successfully logs in and is redirected to the dashboard |
| 2 | Manager or system administrator creates a schedule change event for the employee (modify shift time, date, or location) | Schedule change event is created and saved in ScheduleChangeEvents table |
| 3 | Wait and monitor the employee dashboard for notification appearance (maximum 15 minutes) | Notification appears on employee dashboard within 15 minutes displaying the schedule change details |
| 4 | Verify notification content includes change type, old schedule details, new schedule details, and timestamp | Notification displays complete and accurate schedule change information |
| 5 | Click on the notification to view full details | Notification expands or opens to show comprehensive schedule change information |
| 6 | Click the 'Acknowledge' button on the notification | Acknowledgment is recorded in the system and notification is marked as read with visual indicator (e.g., color change, checkmark) |
| 7 | Verify the notification status changes from unread to read/acknowledged | Notification displays acknowledged status with timestamp of acknowledgment |

**Postconditions:**
- Notification is marked as acknowledged in the database
- Acknowledgment timestamp is recorded in NotificationStatus table
- Employee remains logged in to the portal
- Notification remains visible in notification history

---

### Test Case: Verify email alert delivery for schedule changes
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 20 mins

**Preconditions:**
- Employee account exists with valid email address configured
- Email notification service is enabled and operational
- Employee has opted in for email notifications (if applicable)
- SMTP server is configured and accessible
- Employee has access to their email inbox

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Manager or system administrator creates a schedule change event for the employee | Schedule change event is saved and triggers email alert process |
| 2 | Monitor the email delivery system logs for email dispatch confirmation | System logs show email queued and sent to employee's email address |
| 3 | Check employee's email inbox within 15 minutes of schedule change | Employee receives email alert within 15 minutes of the schedule change event |
| 4 | Open the email and verify sender address matches system notification address | Email is from official system notification address and not marked as spam |
| 5 | Review email subject line for clarity and relevance | Subject line clearly indicates schedule change notification (e.g., 'Schedule Change Alert - [Date]') |
| 6 | Verify email content includes original schedule details, new schedule details, change type, and effective date | Email content matches schedule change details exactly as stored in the system |
| 7 | Check for any links in the email to view full details or acknowledge in the portal | Email contains working link to employee portal for acknowledgment |
| 8 | Compare email content with the notification displayed on the dashboard | Email content matches dashboard notification content exactly |

**Postconditions:**
- Email is delivered and accessible in employee's inbox
- Email delivery is logged in system
- Employee can access portal link from email
- Schedule change remains active in the system

---

### Test Case: Test notification history access
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 15 mins

**Preconditions:**
- Employee account exists with valid credentials
- Employee has received at least 3-5 schedule change notifications in the past
- Some notifications are acknowledged and some are unacknowledged
- Employee is logged into the web portal
- Notification history feature is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | From the employee dashboard, locate and click on 'Notification History' or 'View All Notifications' link/button | System navigates to the notification history page |
| 2 | Verify the notification history page loads completely | Notification history page displays with all UI elements loaded (headers, filters, notification list) |
| 3 | Review the list of notifications displayed on the history page | All past schedule change notifications for the employee are displayed in chronological order (newest first) |
| 4 | Verify each notification entry shows key information: date/time of change, change type, old schedule, new schedule, and acknowledgment status | Each notification displays complete information with clear visual distinction between acknowledged and unacknowledged notifications |
| 5 | Check for acknowledgment timestamps on acknowledged notifications | Acknowledged notifications display the date and time when they were acknowledged |
| 6 | Verify unacknowledged notifications are clearly marked and allow acknowledgment from history page | Unacknowledged notifications show 'Acknowledge' button and are visually distinct (e.g., bold, highlighted) |
| 7 | Test pagination or scrolling if more than 10-20 notifications exist | All notifications are accessible through pagination or infinite scroll functionality |
| 8 | Apply any available filters (date range, acknowledged/unacknowledged status) | Filters work correctly and display only notifications matching the filter criteria |
| 9 | Click on a specific notification to view full details | Notification expands or opens detail view showing complete schedule change information |

**Postconditions:**
- Employee remains on notification history page or returns to dashboard
- All notifications remain accessible for future reference
- No data is modified unless employee acknowledges an unacknowledged notification
- Employee session remains active

---

## Story: As Employee, I want to acknowledge schedule change notifications to confirm awareness
**Story ID:** story-17

### Test Case: Validate acknowledgment of schedule change notification
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Employee account exists with valid credentials
- Employee is logged into the web portal
- At least one unacknowledged schedule change notification exists for the employee
- NotificationStatus table is accessible and functional
- POST /api/notifications/acknowledge endpoint is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the employee dashboard where notifications are displayed | Dashboard loads successfully showing unacknowledged notification(s) with visual indicator (e.g., badge, highlight) |
| 2 | Identify an unacknowledged schedule change notification in the notification list | Unacknowledged notification is clearly visible with 'Acknowledge' button enabled |
| 3 | Click the 'Acknowledge' button on the notification | System processes the acknowledgment request within 1 second |
| 4 | Verify notification status updates visually on the UI | Notification status changes to 'Acknowledged' with visual confirmation (checkmark, color change, or status label) |
| 5 | Check for confirmation message displayed to the employee | System displays confirmation message such as 'Notification acknowledged successfully' or similar positive feedback |
| 6 | Verify the 'Acknowledge' button is disabled or removed from the acknowledged notification | 'Acknowledge' button is no longer available for the acknowledged notification |
| 7 | Refresh the page or navigate away and return to the dashboard | Notification remains in acknowledged state after page refresh |
| 8 | Locate the same notification and attempt to click 'Acknowledge' again (if button is still visible) | System prevents duplicate acknowledgment and displays message such as 'This notification has already been acknowledged' |
| 9 | Attempt to send duplicate acknowledgment via direct API call using POST /api/notifications/acknowledge with same notification ID | API returns error response (e.g., 400 Bad Request or 409 Conflict) with message indicating notification already acknowledged |

**Postconditions:**
- Notification status is updated to 'Acknowledged' in NotificationStatus table
- Acknowledgment timestamp is recorded in database
- Employee ID is logged with the acknowledgment
- Notification cannot be acknowledged again
- Employee remains logged in to the portal

---

### Test Case: Verify acknowledgment logging
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Employee account exists with valid credentials and known employee ID
- Employee is logged into the web portal
- At least one unacknowledged schedule change notification exists for the employee
- Database access is available to verify NotificationStatus table
- System timestamp is accurate and synchronized

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Record the current system timestamp before performing acknowledgment | Current timestamp is noted for comparison (e.g., 2024-01-15 10:30:00) |
| 2 | Navigate to employee dashboard and identify the notification ID of an unacknowledged notification | Notification ID is visible or retrievable from UI/API (e.g., notification-12345) |
| 3 | Click the 'Acknowledge' button on the selected notification | System displays confirmation message that acknowledgment was successful |
| 4 | Query the NotificationStatus table in the database for the specific notification ID | Database record exists for the notification with updated status |
| 5 | Verify the acknowledgment status field is set to 'Acknowledged' or equivalent value | Status field shows 'Acknowledged' or boolean value TRUE |
| 6 | Verify the acknowledgment timestamp is recorded in the database | Timestamp field contains the date and time of acknowledgment, matching the time when 'Acknowledge' was clicked (within 1-2 seconds tolerance) |
| 7 | Verify the employee ID/user ID is recorded with the acknowledgment | Employee ID field matches the logged-in employee's ID who performed the acknowledgment |
| 8 | Check for any additional audit fields (created_by, modified_by, IP address if applicable) | All relevant audit fields are populated with correct information |
| 9 | Verify the acknowledgment timestamp format is consistent with system standards (ISO 8601 or configured format) | Timestamp is stored in correct format and timezone |

**Postconditions:**
- NotificationStatus table contains complete acknowledgment record
- Acknowledgment timestamp is accurately recorded
- Employee ID is correctly associated with the acknowledgment
- Database integrity is maintained
- Acknowledgment data is available for reporting and audit purposes

---

