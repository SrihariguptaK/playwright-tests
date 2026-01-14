# Manual Test Cases

## Story: As Schedule Manager, I want the system to validate schedules to detect conflicts to ensure compliance and accuracy
**Story ID:** story-5

### Test Case: Detect overlapping shifts for an employee
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as Schedule Manager with valid credentials
- Schedule management system is accessible
- At least one employee exists in the system with valid employee ID
- Labor rules and validation engine are configured and active
- User has permissions to create and modify schedules

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule creation page and select an employee from the employee list | Employee selection interface is displayed with available employees listed |
| 2 | Create a first shift for the selected employee with start time 09:00 AM and end time 05:00 PM on the same day | First shift is created and displayed in the schedule grid |
| 3 | Create a second shift for the same employee with start time 02:00 PM and end time 10:00 PM on the same day (overlapping with first shift) | Second shift is created and schedule is saved to the system |
| 4 | Click the 'Validate Schedule' button or trigger automatic validation | Validation process initiates and completes within 2 seconds |
| 5 | Observe the validation results displayed on the screen | System flags the overlapping shifts with a clear visual indicator (e.g., red highlight or warning icon) and displays an error message indicating 'Overlapping shifts detected for employee [Employee Name]' |
| 6 | Click on the conflict notification or flagged shifts to view detailed conflict information | Detailed conflict information is displayed showing both shift times and the overlap period |
| 7 | Review the conflict resolution suggestions provided by the system | System displays actionable suggestions such as 'Adjust shift times', 'Reassign second shift to different employee', or 'Remove overlapping shift' with clickable options |

**Postconditions:**
- Overlapping shifts remain flagged in the system until resolved
- Schedule is marked as invalid and cannot be finalized
- Conflict details are logged in the system for audit purposes
- Manager is able to take corrective action based on suggestions

---

### Test Case: Validate minimum rest period between shifts
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in as Schedule Manager with valid credentials
- Schedule management system is accessible
- Minimum rest period rule is configured in the system (e.g., 11 hours between shifts)
- At least one employee exists in the system
- User has permissions to create and modify schedules

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule creation page and select an employee | Schedule creation interface is displayed with selected employee |
| 2 | Create a first shift for the employee with start time 06:00 PM and end time 02:00 AM (next day) | First shift is created and saved successfully |
| 3 | Create a second consecutive shift for the same employee with start time 08:00 AM (same day as shift end) and end time 04:00 PM (only 6 hours rest between shifts) | Second shift is created and schedule is saved to the system |
| 4 | Click the 'Validate Schedule' button to run validation checks | Validation process executes and completes within 2 seconds |
| 5 | Review the validation results displayed on the screen | System reports a rest period violation with message 'Minimum rest period violation: Only 6 hours between shifts. Required: 11 hours' and highlights the affected shifts |
| 6 | Note the suggested resolution options provided by the system | System displays suggestions such as 'Move second shift to start at 01:00 PM or later' or 'Reassign second shift to different employee' |
| 7 | Adjust the second shift start time to 02:00 PM (providing 12 hours rest) | Shift time is updated successfully in the schedule |
| 8 | Click 'Validate Schedule' button again to revalidate the adjusted schedule | Validation process runs successfully |
| 9 | Review the validation results after adjustment | No violations are found, system displays 'Schedule validated successfully' message with green indicator, and schedule is marked as valid |

**Postconditions:**
- Schedule passes all validation checks
- No rest period violations exist in the schedule
- Schedule is eligible for finalization
- Validation results are logged in the system
- Employee has adequate rest period between consecutive shifts

---

## Story: As Schedule Manager, I want to receive notifications about schedule conflicts to take timely corrective actions
**Story ID:** story-8

### Test Case: Receive notification for detected schedule conflict
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in as Schedule Manager with valid credentials
- Notification system is enabled and functioning
- User has permissions to create schedules and view notifications
- At least one employee exists in the system
- Notification preferences are configured for the manager
- Real-time conflict detection is active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule creation page | Schedule creation interface is displayed |
| 2 | Create a schedule with a conflict by assigning overlapping shifts to the same employee (e.g., Shift 1: 09:00 AM - 05:00 PM, Shift 2: 03:00 PM - 11:00 PM on the same day) | Both shifts are created and saved in the system |
| 3 | Wait for the system to automatically detect the conflict (should occur within 1 minute) | System detects the overlapping shift conflict and triggers the notification generation process |
| 4 | Navigate to the notifications section in the UI by clicking the notifications icon or menu item | Notifications page is displayed showing all active notifications |
| 5 | Locate and review the newly generated conflict notification | Notification is displayed with conflict details including: employee name, conflicting shift times, conflict type (overlapping shifts), and timestamp of detection |
| 6 | Click on the notification to view full details | Detailed notification view opens showing complete conflict information and suggested actions such as 'Adjust shift times' or 'Reassign one shift' |
| 7 | Click the 'Acknowledge' button on the notification | Notification status changes to 'Acknowledged', visual indicator (e.g., checkmark) appears, and notification is marked with acknowledgment timestamp |
| 8 | Verify the notification status in the notifications list | Notification shows 'Acknowledged' status with the manager's name and acknowledgment time displayed |

**Postconditions:**
- Notification is marked as acknowledged in the system
- Notification remains visible in the notifications list with acknowledged status
- Acknowledgment is logged with timestamp and user information
- Conflict remains unresolved but manager is aware of the issue
- Notification delivery and acknowledgment are recorded in the system logs

---

### Test Case: Dismiss notification and verify status
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in as Schedule Manager with valid credentials
- At least one active notification exists in the system
- Notification system is functioning properly
- User has permissions to view and manage notifications
- Notification history logging is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the notifications section by clicking the notifications icon in the main navigation | Notifications page is displayed showing list of active notifications |
| 2 | Locate a specific notification from the list and click on it to select | Selected notification is highlighted and notification details panel opens showing full information including conflict type, affected employee, shift details, and suggested actions |
| 3 | Review the notification details displayed in the details panel | All notification information is clearly visible including timestamp, conflict description, and available actions |
| 4 | Click the 'Dismiss' button located in the notification details panel or notification item | Confirmation dialog appears asking 'Are you sure you want to dismiss this notification?' |
| 5 | Confirm the dismissal action by clicking 'Yes' or 'Confirm' in the dialog | Notification is dismissed, confirmation message 'Notification dismissed successfully' appears, and notification is removed from the active notifications list |
| 6 | Verify that the dismissed notification is no longer visible in the active notifications list | Dismissed notification does not appear in the active notifications list, notification count is decremented by one |
| 7 | Navigate to the notification history section or filter notifications by 'Dismissed' status | Notification history page or filtered view is displayed |
| 8 | Search for the dismissed notification in the history using the notification ID or timestamp | Dismissed notification is found in the history with status 'Dismissed', showing dismissal timestamp, manager who dismissed it, and original notification details preserved |
| 9 | Verify the notification log entry contains complete information | Log entry shows notification creation time, dismissal time, manager name, notification type, and all relevant conflict details |

**Postconditions:**
- Notification is removed from active notifications list
- Notification status is permanently set to 'Dismissed'
- Dismissal action is logged with timestamp and user information
- Notification is accessible in notification history for audit purposes
- System maintains complete audit trail of notification lifecycle
- Dismissed notification cannot be re-activated

---

