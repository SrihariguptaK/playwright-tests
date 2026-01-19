# Manual Test Cases

## Story: As Scheduling Manager, I want to view employee schedules in a calendar format to easily understand shift assignments
**Story ID:** story-6

### Test Case: Display schedules in weekly calendar view
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as Scheduling Manager
- User has role-based access to view employee schedules
- At least one employee schedule exists in the system for the current week
- Calendar UI component is functional and accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule calendar page from the main menu | Calendar page loads successfully and displays the current week view by default with all scheduled shifts visible |
| 2 | Locate and click on the employee filter dropdown | Employee filter dropdown opens and displays a list of all employees |
| 3 | Select a specific employee from the filter dropdown | Calendar updates immediately to show only the selected employee's shifts for the current week, other employees' shifts are hidden |
| 4 | Click on one of the displayed shifts in the calendar | A shift details popup appears displaying complete shift information including employee name, shift time, shift template, and any additional notes |
| 5 | Close the shift details popup | Popup closes and calendar view remains filtered to the selected employee |

**Postconditions:**
- Calendar remains in weekly view with employee filter applied
- No data is modified in the system
- User session remains active

---

### Test Case: Highlight scheduling conflicts in calendar
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in as Scheduling Manager
- User has role-based access to view employee schedules
- At least one employee has overlapping shifts assigned in the system
- Calendar view is accessible and functional
- Conflict highlighting feature is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule calendar page | Calendar page loads successfully displaying the current week view |
| 2 | Locate the employee with overlapping shifts in the calendar view | The overlapping shifts are visually highlighted with a distinct color or border (e.g., red border or warning icon) to indicate a scheduling conflict |
| 3 | Hover over or click on one of the conflicting shifts | Shift details popup displays with conflict information clearly indicated, showing the overlapping time periods and affected shifts |
| 4 | Verify that non-conflicting shifts are displayed normally without highlighting | Non-conflicting shifts appear in standard display format without conflict indicators |

**Postconditions:**
- Scheduling conflicts remain highlighted in the calendar
- No schedule data is modified
- Conflict information is accurately displayed
- User can proceed to resolve conflicts if needed

---

## Story: As Scheduling Manager, I want to modify existing employee schedules to accommodate changes
**Story ID:** story-7

### Test Case: Modify employee schedule and log changes
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in as Scheduling Manager
- User has role-based access to modify employee schedules
- At least one employee schedule exists in the system
- Audit logging functionality is enabled and operational
- Database connection to EmployeeSchedules and AuditLogs is active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the employee schedules page and locate an existing employee schedule | Employee schedules list is displayed with all available schedules |
| 2 | Click on a specific employee schedule to select it | Schedule details are displayed showing current shift times, employee information, and shift template |
| 3 | Click the 'Edit' button or icon to enter edit mode | Schedule enters edit mode with editable fields for shift times and other modifiable attributes |
| 4 | Modify the shift start time and end time to new valid values | New time values are accepted and displayed in the input fields without validation errors |
| 5 | Click the 'Save' button to save the changes | Changes are saved successfully, confirmation message is displayed, and schedule is updated with new shift times |
| 6 | Navigate to the audit log section or page | Audit log page loads displaying recent system activities |
| 7 | Search or filter for the modification entry related to the edited schedule | Audit log entry is found and displayed showing the schedule modification with complete details |
| 8 | Verify the audit log entry contains the username of the logged-in manager and timestamp of the modification | Log entry displays correct username, accurate timestamp, old values, new values, and modification type |

**Postconditions:**
- Employee schedule is updated with new shift times
- Audit log contains complete record of the modification
- Original schedule data is preserved in audit history
- System remains in stable state ready for additional modifications

---

### Test Case: Send notification after schedule change
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as Scheduling Manager
- User has role-based access to modify employee schedules
- At least one employee schedule exists in the system
- Employee has valid contact information (email or app notification settings) configured
- Notification service is operational and connected
- Employee is set to receive schedule change notifications

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the employee schedules page and select an existing employee schedule | Schedule details are displayed for the selected employee |
| 2 | Click the 'Edit' button to enter edit mode | Schedule enters edit mode with editable fields available |
| 3 | Modify the schedule by changing shift times or other schedule attributes that affect the employee | Modified values are accepted and displayed in the input fields |
| 4 | Click the 'Save' button to save the schedule changes | Changes are saved successfully, confirmation message is displayed, and notification is triggered to the affected employee |
| 5 | Navigate to the notifications management section or notification status page | Notifications page loads displaying recent notification activities |
| 6 | Search or filter for the notification sent to the affected employee regarding the schedule change | Notification record is found and displayed in the notifications list |
| 7 | Verify the notification status shows as 'Delivered' or 'Sent' | Notification status is marked as 'Delivered' with timestamp, recipient information, and notification content details visible |
| 8 | Optionally verify the employee received the notification through their email or app | Employee has received the notification with accurate schedule change information |

**Postconditions:**
- Employee schedule is updated with modifications
- Notification is successfully sent and marked as delivered
- Notification record is stored in the system
- Employee is informed of the schedule change
- System is ready to process additional schedule modifications

---

## Story: As Scheduling Manager, I want to receive notifications for schedule changes to keep employees informed
**Story ID:** story-8

### Test Case: Send notification on schedule creation
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as Scheduling Manager
- Notification service is configured and operational
- At least one employee exists in the system with valid contact information
- Email and/or app notification channels are enabled
- Employee has valid email address and/or app access

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule management interface | Schedule management page is displayed with options to create new schedules |
| 2 | Click on 'Create New Schedule' button | Schedule creation form is displayed with all required fields |
| 3 | Fill in schedule details including employee name, date, time, and shift information | All schedule fields are populated with valid data |
| 4 | Click 'Save' or 'Create Schedule' button | Schedule is successfully created and saved to the system |
| 5 | Verify notification is triggered in the system logs or notification dashboard | Notification event is logged showing trigger timestamp and recipient details |
| 6 | Check employee's email inbox for notification | Email notification is received containing schedule details, date, time, and shift information |
| 7 | Check employee's app for push notification or in-app message | App notification is received with schedule creation details and relevant information |
| 8 | Verify notification content includes all relevant schedule information | Notification displays employee name, schedule date, shift time, location, and any additional notes |

**Postconditions:**
- New schedule is created and stored in the database
- Notification is successfully delivered to employee via configured channels
- Notification delivery status is recorded as 'Sent' or 'Delivered'
- Employee is informed of their new schedule assignment

---

### Test Case: Track and resend failed notifications
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- User is logged in as Scheduling Manager
- Notification service is configured
- At least one schedule with notification exists in the system
- Manager has access to notification status dashboard
- System has capability to simulate or trigger notification failures

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the notification status dashboard or monitoring page | Notification tracking interface is displayed showing list of sent notifications |
| 2 | Simulate a notification failure by disabling email service or using invalid employee email address | Notification service encounters delivery failure condition |
| 3 | Create or modify a schedule to trigger notification | System attempts to send notification but encounters failure |
| 4 | Check the notification status dashboard for the failed notification | Notification status is displayed as 'Failed' with failure reason and timestamp |
| 5 | Verify failure details include error message and affected employee information | Dashboard shows specific error details such as 'Email delivery failed', 'Invalid email address', or 'Service unavailable' |
| 6 | Resolve the issue causing failure (e.g., correct email address, re-enable service) | Underlying issue is corrected and notification channel is operational |
| 7 | Select the failed notification from the list | Failed notification is highlighted and resend option is available |
| 8 | Click 'Resend Notification' or 'Retry' button | System initiates resend process and displays confirmation message |
| 9 | Monitor notification status for the resent notification | Notification status updates to 'Sending' then 'Sent' or 'Delivered' |
| 10 | Verify employee receives the resent notification via configured channel | Employee successfully receives notification via email or app with correct schedule information |
| 11 | Check notification history to confirm resend attempt is logged | Notification history shows both original failed attempt and successful resend with timestamps |

**Postconditions:**
- Failed notification is tracked and logged in the system
- Notification is successfully resent and delivered to employee
- Notification status is updated to 'Delivered' or 'Sent'
- Complete audit trail of notification attempts is maintained
- Employee receives schedule information despite initial failure

---

