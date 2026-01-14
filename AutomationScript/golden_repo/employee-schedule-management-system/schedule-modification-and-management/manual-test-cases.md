# Manual Test Cases

## Story: As Scheduling Manager, I want to edit employee schedules to update shift assignments
**Story ID:** story-6

### Test Case: Edit schedule to update employee assignment successfully
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as Scheduling Manager with edit permissions
- At least one schedule exists with assigned shifts
- Multiple employees are available in the system
- No existing conflicts for the target employee
- Audit logging system is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule view from the main dashboard | Schedule view loads successfully displaying all existing schedules and shifts |
| 2 | Select a specific shift from the schedule that needs to be edited | Shift details are displayed including current employee assignment, time, date, and role requirements |
| 3 | Click on the edit button or employee assignment field for the selected shift | Edit mode is activated and employee selection dropdown or input field becomes available |
| 4 | Change the employee assignment by selecting a different valid employee from the available list | New employee is selected, input is accepted without errors, and no validation warnings appear |
| 5 | Review the updated assignment details to ensure accuracy | Updated shift shows new employee assignment with correct shift time and role information |
| 6 | Click the Save button to commit the updated schedule | System processes the update within 2 seconds, displays success confirmation message, schedule is updated in the view, and audit log entry is created with timestamp, manager ID, and change details |

**Postconditions:**
- Schedule is updated with new employee assignment
- Audit log contains entry documenting the change
- Previous employee is unassigned from the shift
- New employee is assigned to the shift
- No schedule conflicts exist
- Confirmation message is displayed to the manager

---

### Test Case: Reject schedule update with conflicting employee assignment
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in as Scheduling Manager with edit permissions
- At least one schedule exists with assigned shifts
- An employee is already assigned to an overlapping shift
- Validation rules for conflict detection are configured
- System conflict detection is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule view and select a shift to edit | Schedule view loads and shift details are displayed for editing |
| 2 | Attempt to assign an employee who is already scheduled for an overlapping time slot | System detects the conflict and displays a validation error message indicating the employee has an overlapping shift assignment with specific time details |
| 3 | Review the error message and conflict details | Error message clearly identifies the conflicting shift, time overlap, and affected employee |
| 4 | Attempt to click the Save button while the conflict exists | Save operation is blocked, error message persists or is re-displayed, and no changes are committed to the schedule |
| 5 | Verify that the original schedule remains unchanged | Original employee assignment is still in place and no audit log entry is created for the failed update attempt |

**Postconditions:**
- Schedule remains unchanged with original employee assignment
- No audit log entry is created for the rejected change
- Validation error message is visible to the manager
- Employee conflict is not created in the system
- Manager can continue editing to resolve the conflict

---

## Story: As Scheduling Manager, I want to process shift swap requests to accommodate employee needs
**Story ID:** story-7

### Test Case: Approve valid shift swap request
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in as Scheduling Manager with swap approval permissions
- Two employees are scheduled for different shifts
- Both employees have compatible roles for each other's shifts
- No scheduling conflicts exist for either employee
- Notification system is operational
- Shift swap request workflow is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Employee A submits a shift swap request with Employee B through the employee portal | Shift swap request is successfully recorded in the system with status 'Pending', request ID is generated, and both employees' shift details are captured |
| 2 | Manager navigates to the shift swap requests queue or dashboard | Shift swap requests page loads displaying all pending requests including the newly submitted swap request with employee names, shift details, and submission timestamp |
| 3 | Manager selects and opens the specific shift swap request to review details | Request details are displayed showing both employees, their current shifts, proposed swap details, shift times, dates, and role requirements |
| 4 | Manager validates the swap feasibility by reviewing employee availability and shift compatibility | System shows validation status indicating no conflicts, compatible roles, and both employees are available for the swapped shifts |
| 5 | Manager clicks the Approve button to approve the shift swap request | Request status is updated to 'Approved' within 2 seconds, confirmation message is displayed to the manager |
| 6 | System automatically updates the schedules for both employees | Employee A is now assigned to Employee B's original shift, Employee B is assigned to Employee A's original shift, schedules reflect the changes immediately |
| 7 | System sends notifications to both affected employees | Both Employee A and Employee B receive notifications confirming the approved shift swap with updated shift details and dates |

**Postconditions:**
- Shift swap request status is 'Approved'
- Schedules are updated with swapped shift assignments
- Both employees have received approval notifications
- Audit trail records the swap approval with manager ID and timestamp
- No scheduling conflicts exist
- Original shifts are reassigned correctly

---

### Test Case: Reject invalid shift swap request
- **ID:** tc-004
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as Scheduling Manager with swap approval permissions
- Two employees are scheduled for shifts
- Shifts have incompatible role requirements or timing conflicts
- Validation rules for shift compatibility are configured
- Notification system is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Employee submits a shift swap request for shifts with incompatible requirements (e.g., different roles, overlapping times, or qualification mismatches) | Shift swap request is recorded in the system with status 'Pending' and request details are captured including the incompatible shift information |
| 2 | Manager navigates to the shift swap requests queue and selects the invalid swap request | Request details are displayed showing both employees and their shift information |
| 3 | Manager reviews the request and attempts to click the Approve button | System validates the swap feasibility and blocks the approval action, displaying a validation error message indicating the specific incompatibility (e.g., 'Employee B does not have required certification for Shift A' or 'Shifts have incompatible time slots') |
| 4 | Manager reviews the validation error details | Error message clearly explains why the swap cannot be approved with specific details about the incompatibility |
| 5 | Manager clicks the Reject button to formally reject the swap request | Request status is updated to 'Rejected' within 2 seconds, rejection is confirmed with a success message to the manager |
| 6 | System sends rejection notifications to the requesting employees | Both employees receive notifications indicating the shift swap request has been rejected with reason for rejection included |
| 7 | Verify that the original schedules remain unchanged | Both employees remain assigned to their original shifts with no modifications to the schedule |

**Postconditions:**
- Shift swap request status is 'Rejected'
- Original schedules remain unchanged for both employees
- Both employees have received rejection notifications with reasons
- Audit trail records the rejection with manager ID and timestamp
- No invalid shift assignments are created
- System maintains schedule integrity

---

## Story: As Scheduling Manager, I want to cancel shifts to handle unforeseen changes
**Story ID:** story-8

### Test Case: Cancel scheduled shift successfully
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as Scheduling Manager with cancellation permissions
- At least one scheduled shift exists in the system
- Shift has at least one employee assigned
- Employee has valid email address and notification preferences enabled
- System notification service is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule management page and locate a scheduled shift | Schedule management page loads successfully with list of scheduled shifts displayed |
| 2 | Select a scheduled shift for cancellation by clicking on it | Shift details are displayed including shift date, time, assigned employees, and location information |
| 3 | Click the 'Cancel Shift' button | Confirmation dialog appears asking to confirm the cancellation action |
| 4 | Review the cancellation details and click 'Confirm' button | Shift is removed from the schedule, success confirmation message is displayed, and cancellation is processed within 2 seconds |
| 5 | Verify the shift no longer appears in the schedule view | Cancelled shift is not visible in the schedule and the time slot shows as available |
| 6 | Check the notification log or verify with affected employees that notifications were sent | Notifications are delivered successfully to all affected employees via their preferred channels (email and/or system alerts) |
| 7 | Verify notification delivery status in the system logs | System logs show 100% notification delivery success for all affected employees |

**Postconditions:**
- Shift is permanently removed from the schedule
- All affected employees have received cancellation notifications
- Schedule is updated and reflects the cancellation
- Notification delivery is logged in the system
- Time slot is available for new scheduling

---

### Test Case: Prevent cancellation without confirmation
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as Scheduling Manager with cancellation permissions
- At least one scheduled shift exists in the system
- Shift has at least one employee assigned

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule management page | Schedule management page loads successfully with list of scheduled shifts displayed |
| 2 | Select a scheduled shift for cancellation by clicking on it | Shift details are displayed with cancellation option available |
| 3 | Click the 'Cancel Shift' button | Confirmation dialog is displayed with options to confirm or dismiss the cancellation, including warning message about the impact |
| 4 | Click 'Cancel', 'Dismiss', or 'X' button on the confirmation dialog without confirming | Confirmation dialog closes and returns to the shift details view |
| 5 | Verify the shift still appears in the schedule | Shift remains scheduled with all original details intact and no changes made |
| 6 | Check that no notifications were sent to employees | No cancellation notifications are sent and notification logs show no new entries for this shift |

**Postconditions:**
- Shift remains in the schedule unchanged
- No notifications sent to employees
- No updates made to the schedule
- Cancellation action is aborted successfully

---

## Story: As Scheduling Manager, I want to receive notifications about schedule changes to stay informed
**Story ID:** story-9

### Test Case: Receive notification on schedule creation
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in as Scheduling Manager
- At least one employee exists in the system with valid email address
- Employee notification preferences are enabled for schedule creation events
- Notification service is operational and configured
- Email service is functional

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule creation page | Schedule creation page loads successfully with all required fields displayed |
| 2 | Fill in all required schedule details including date, time, location, and assign at least one employee | All fields accept input and employee is successfully assigned to the schedule |
| 3 | Click 'Save' or 'Create Schedule' button | Schedule is saved successfully and confirmation message is displayed |
| 4 | Wait up to 1 minute and check the assigned employee's email inbox | Email notification is received by the assigned employee containing schedule details within 1 minute |
| 5 | Check the system alerts/notifications panel for the assigned employee | System alert notification is displayed in the employee's notification panel with schedule creation details |
| 6 | Navigate to the notification logs in the system administration panel | Notification delivery is logged in the system with timestamp, recipient, delivery method, and status |
| 7 | Verify the notification log shows successful delivery without errors | Log entry shows 'Success' status with no error messages for both email and system alert delivery |

**Postconditions:**
- Schedule is created and saved in the system
- Notifications delivered via both email and system alerts
- Notification delivery logged with success status
- 99% notification delivery success rate maintained
- All assigned employees are informed of the new schedule

---

### Test Case: Configure and receive notifications based on preferences
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in as an employee or manager
- User has access to notification preferences settings
- At least one schedule exists that can be modified
- User is assigned to at least one schedule
- Notification service is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to user profile or settings page | User settings page loads successfully with notification preferences section visible |
| 2 | Locate and click on 'Notification Preferences' or 'Notification Settings' | Notification preferences page displays with options for email, system alerts, and event types |
| 3 | Update notification preferences by selecting or deselecting specific channels (e.g., enable email only, disable system alerts) and event types | Preference checkboxes or toggles respond to user input and show updated selections |
| 4 | Click 'Save' or 'Update Preferences' button | Success message is displayed confirming preferences have been saved successfully |
| 5 | As a Scheduling Manager, navigate to an existing schedule assigned to the user and modify it (change time, date, or location) | Schedule modification is saved successfully and confirmation message is displayed |
| 6 | Wait up to 1 minute and check if notifications are sent according to the updated preferences | Notifications are sent only through the channels enabled in preferences (e.g., email only if system alerts were disabled) |
| 7 | Verify that disabled notification channels did not send notifications | No notifications received through disabled channels, confirming preferences are respected |
| 8 | Check notification logs to verify delivery matches user preferences | Notification logs show delivery attempts only for enabled channels with appropriate success status |

**Postconditions:**
- User notification preferences are updated and saved
- Notifications are sent according to updated preferences
- Disabled notification channels do not send notifications
- Notification delivery is logged correctly
- User receives notifications only through preferred channels

---

## Story: As Scheduling Manager, I want to view reports on schedule utilization to optimize workforce planning
**Story ID:** story-10

### Test Case: Generate schedule utilization report with valid parameters
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Scheduling Manager role
- User has authorization to access reporting section
- At least one department exists in the system
- Schedule data exists for the selected date range
- Employee and shift template data is available in the database

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the reporting section from the main menu | Reporting UI is displayed with available report types and parameter selection options |
| 2 | Select 'Schedule Utilization' report type from the dropdown | Schedule utilization report parameters form is displayed |
| 3 | Select a valid date range (e.g., last 30 days) using the date picker | Date range is populated in the form fields and validated as correct format |
| 4 | Select a department from the department dropdown list | Department is selected and displayed in the parameter form |
| 5 | Click the 'Generate Report' button | System processes the request and displays a loading indicator |
| 6 | Wait for report generation to complete | Report is displayed within 5 seconds showing shift coverage statistics, employee scheduled hours, and schedule adherence data with accurate information matching the selected parameters |
| 7 | Verify report contains shift coverage statistics section | Shift coverage statistics are displayed with percentage coverage, total shifts, and filled/unfilled shift counts |
| 8 | Verify report contains employee scheduled hours section | Employee scheduled hours are displayed with individual employee names, total hours, and breakdown by shift type |

**Postconditions:**
- Report is successfully generated and displayed on screen
- Report data matches the selected parameters
- System logs the report generation activity
- Report remains accessible for export or further analysis

---

### Test Case: Export schedule utilization report
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in with Scheduling Manager role
- User has authorization to access reporting section
- User has successfully navigated to the reporting section
- Schedule utilization report has been generated with valid parameters
- Report data is displayed on screen
- User has appropriate file download permissions in browser

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to reporting section and select report parameters (date range and department) | Report parameters are accepted and form is ready for generation |
| 2 | Click 'Generate Report' button | Report is displayed on screen with shift coverage statistics, employee hours, and all relevant data within 5 seconds |
| 3 | Verify export options are available on the report interface | Export buttons for PDF and Excel formats are visible and enabled |
| 4 | Click the 'Export as PDF' button | System initiates PDF generation and download process |
| 5 | Wait for PDF download to complete and open the downloaded PDF file | PDF file is successfully downloaded with a meaningful filename (e.g., ScheduleUtilization_Department_DateRange.pdf) and opens correctly showing all report data including headers, shift coverage statistics, employee hours, and formatting preserved |
| 6 | Verify PDF content matches the on-screen report data | All data in PDF matches the displayed report including numbers, employee names, dates, and statistics with proper formatting and readability |
| 7 | Return to the report interface and click the 'Export as Excel' button | System initiates Excel file generation and download process |
| 8 | Wait for Excel download to complete and open the downloaded Excel file | Excel file is successfully downloaded with a meaningful filename (e.g., ScheduleUtilization_Department_DateRange.xlsx) and opens correctly in spreadsheet application |
| 9 | Verify Excel content matches the on-screen report data | All data in Excel matches the displayed report with proper column headers, data in appropriate cells, numbers formatted correctly, and data is editable/manipulable in Excel |
| 10 | Verify Excel file structure includes separate sheets or sections for different report components | Excel file contains organized data with shift coverage statistics and employee hours clearly separated and labeled |

**Postconditions:**
- PDF file is successfully downloaded and contains accurate report data
- Excel file is successfully downloaded and contains accurate report data
- Both exported files match the on-screen report content
- Files are saved to the user's default download location
- System logs the export activities
- Original report remains displayed on screen for further analysis

---

