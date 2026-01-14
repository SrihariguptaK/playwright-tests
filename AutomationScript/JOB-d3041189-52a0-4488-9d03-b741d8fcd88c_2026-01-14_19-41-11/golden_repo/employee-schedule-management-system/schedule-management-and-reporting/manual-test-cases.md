# Manual Test Cases

## Story: As Scheduling Manager, I want to generate reports on shift coverage and scheduling conflicts to improve workforce planning
**Story ID:** story-8

### Test Case: Generate shift coverage report successfully
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as Scheduling Manager with reporting permissions
- Employee schedules exist in the system for the selected date range
- Reporting module is accessible and functional
- Browser supports PDF download functionality

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the reporting section from the main dashboard menu | Reporting page loads successfully and displays available report options including shift coverage, scheduling conflicts, and other report types |
| 2 | Select 'Shift Coverage Report' from the report type dropdown | Shift coverage report option is selected and date range picker becomes visible |
| 3 | Select a date range (e.g., current week or month) using the date picker | Date range is selected and displayed correctly in the date fields |
| 4 | Click the 'Generate Report' button | System processes the request and generates the report within 5 seconds, displaying shift coverage data including employee names, shift times, coverage percentages, and any gaps |
| 5 | Review the generated report on screen for accuracy and completeness | Report displays accurate shift coverage information with proper formatting, including all scheduled shifts, employee assignments, and coverage statistics for the selected period |
| 6 | Click the 'Export to PDF' button | PDF file is generated and downloaded successfully to the default download location with proper formatting and all report data intact |
| 7 | Open the downloaded PDF file | PDF opens correctly showing the complete shift coverage report with all data, headers, and formatting preserved |

**Postconditions:**
- Shift coverage report is generated and visible in the system
- PDF file is downloaded and saved to local storage
- Report generation activity is logged in the system
- User remains on the reporting page ready to generate additional reports

---

### Test Case: Identify scheduling conflicts in report
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in as Scheduling Manager with reporting permissions
- System contains employee schedules with known scheduling conflicts (e.g., double-booked employees, overlapping shifts, understaffed shifts)
- Reporting module is accessible and functional
- Test data includes at least 2-3 identifiable scheduling conflicts

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the reporting section from the main dashboard menu | Reporting page loads successfully and displays available report options |
| 2 | Select 'Scheduling Conflicts Report' or 'Shift Coverage Report' from the report type dropdown | Report type is selected and configuration options are displayed |
| 3 | Select a date range that includes the period with known scheduling conflicts | Date range is selected and displayed correctly in the date fields |
| 4 | Click the 'Generate Report' button | System processes the request and generates the report within 5 seconds |
| 5 | Review the conflicts section of the generated report | Report clearly lists all scheduling conflicts with detailed information including: conflict type (double-booking, overlap, understaffing), affected employees, dates and times, shift details, and severity level. Conflicts are highlighted or marked distinctly for easy identification |
| 6 | Verify each listed conflict matches the known conflicts in the test data | All known conflicts are accurately identified and listed in the report with correct details and no false positives |
| 7 | Check that the report provides actionable information for resolving conflicts | Each conflict entry includes sufficient detail to enable the manager to take corrective action, such as employee names, contact information, and alternative shift options if available |

**Postconditions:**
- Scheduling conflicts report is generated and displayed
- All conflicts are accurately identified and documented
- Report is available for export or further analysis
- Manager has clear visibility of scheduling issues requiring resolution

---

## Story: As Scheduling Manager, I want to send notifications to employees about schedule changes to improve communication
**Story ID:** story-9

### Test Case: Send notification on schedule creation
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in as Scheduling Manager with schedule creation permissions
- Employee profile exists with valid email address and phone number
- Employee notification preferences are set to receive both email and SMS
- Notification service is configured and operational
- Test email and SMS accounts are accessible for verification

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule management section | Schedule management page loads successfully with options to create, view, and modify schedules |
| 2 | Click the 'Create New Schedule' button | Schedule creation form is displayed with fields for employee selection, date, shift time, position, and location |
| 3 | Select an employee from the dropdown list | Employee is selected and their details are populated in the form |
| 4 | Enter schedule details including date, shift start time, shift end time, and position | All schedule fields are populated with valid data and no validation errors are displayed |
| 5 | Click the 'Save' or 'Create Schedule' button | Schedule is created successfully, confirmation message is displayed, and notification is automatically triggered within 1 minute |
| 6 | Check the employee's email inbox for the schedule notification | Email notification is received successfully containing schedule details including date, shift times, position, location, and any relevant instructions |
| 7 | Check the employee's phone for SMS notification | SMS notification is received successfully containing key schedule information such as date, shift time, and location |
| 8 | Navigate to the notification tracking section in the system | Notification tracking page loads showing a list of sent notifications |
| 9 | Locate the notification entry for the newly created schedule and check its delivery status | Notification entry is displayed showing 'Delivered' or 'Success' status for both email and SMS channels, with timestamp and recipient details |
| 10 | Verify the notification content matches the created schedule details | Email and SMS content accurately reflects the schedule information entered during creation, with no discrepancies |

**Postconditions:**
- New employee schedule is created and saved in the system
- Email notification is successfully delivered to employee
- SMS notification is successfully delivered to employee
- Notification delivery status is tracked and shows successful delivery
- Notification log entry is created in the system

---

### Test Case: Customize notification message and verify
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 12 mins

**Preconditions:**
- User is logged in as Scheduling Manager with notification template management permissions
- Default notification templates exist in the system
- At least one employee schedule exists that can be updated
- Employee has valid contact information and notification preferences enabled
- Notification service is configured and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the notification settings or template management section | Notification settings page loads successfully displaying available notification templates for different event types (creation, update, deletion) |
| 2 | Select the 'Schedule Update' notification template from the list | Template editor opens showing the current template content with editable fields for subject, body, and variables |
| 3 | Modify the notification template message by adding custom text such as 'IMPORTANT: Your schedule has been updated. Please review the changes below.' | Template text is updated in the editor and changes are visible in the preview pane |
| 4 | Verify that template variables (e.g., {employee_name}, {shift_date}, {shift_time}) are properly included | All necessary variables are present and correctly formatted in the template |
| 5 | Click the 'Save Template' button | Template is saved successfully, confirmation message is displayed, and the updated template is now active for future notifications |
| 6 | Navigate to the schedule management section | Schedule management page loads with list of existing schedules |
| 7 | Select an existing employee schedule and click 'Edit' | Schedule editing form opens with current schedule details populated |
| 8 | Modify the schedule by changing the shift time or date | Schedule fields are updated with new values |
| 9 | Click 'Save' to update the schedule | Schedule is updated successfully and notification is automatically triggered using the customized template |
| 10 | Check the employee's email inbox for the schedule update notification | Email notification is received containing the customized message text 'IMPORTANT: Your schedule has been updated. Please review the changes below.' along with the updated schedule details |
| 11 | Verify that all template variables are correctly replaced with actual data | Employee name, shift date, shift time, and other variables are replaced with actual values from the updated schedule, not showing placeholder text |
| 12 | Check the SMS notification if applicable | SMS notification contains the customized message in abbreviated form appropriate for SMS length constraints |

**Postconditions:**
- Notification template is updated and saved in the system
- Customized template is active for future notifications
- Employee receives notification with customized message content
- Schedule update is saved and reflected in the system
- Notification delivery is tracked and logged

---

## Story: As Scheduling Manager, I want to copy existing schedules to new periods to save time in schedule creation
**Story ID:** story-10

### Test Case: Copy schedules from one period to another successfully
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as Scheduling Manager with appropriate permissions
- Source schedule period exists with at least one employee schedule
- Target schedule period exists and is empty or has no conflicting schedules
- System is connected to EmployeeSchedules database
- POST /api/employeeschedules/copy endpoint is available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to schedule management section from the main dashboard | Schedule management page loads successfully displaying available schedule periods |
| 2 | Click on 'Copy Schedule' button or option | Copy UI is displayed with options to select source and target periods |
| 3 | Select the source schedule period from the dropdown list (e.g., 'January 2024') | Source period is selected and highlighted, showing available schedules in that period |
| 4 | Select the target schedule period from the dropdown list (e.g., 'February 2024') | Target period is selected and system begins loading preview of schedules to be copied |
| 5 | Review the preview of schedules to be copied displayed on screen | Schedules are previewed with employee names, shift times, and dates adjusted to target period. No conflict warnings are shown |
| 6 | Click 'Confirm Copy' or 'Save' button to execute the copy operation | System processes the copy request within 5 seconds and displays a success confirmation message |
| 7 | Verify the copied schedules appear in the target period | All schedules from source period are now visible in target period with correct dates and employee assignments |

**Postconditions:**
- Schedules are successfully copied to target period
- Source period schedules remain unchanged
- Target period contains new schedules with adjusted dates
- Success confirmation message is displayed to user
- System logs the copy operation with timestamp and user details

---

### Test Case: Detect conflicts during schedule copy
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in as Scheduling Manager with appropriate permissions
- Source schedule period exists with employee schedules
- Target schedule period already contains schedules that will create overlaps or exceed max hours
- System validation rules for overlaps and max hours are configured
- POST /api/employeeschedules/copy endpoint is available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to schedule management section and click on 'Copy Schedule' option | Copy UI is displayed with source and target period selection options |
| 2 | Select a source schedule period that contains schedules (e.g., 'January 2024') | Source period is selected and available schedules are loaded |
| 3 | Select a target schedule period that already has overlapping schedules or would cause max hours violations (e.g., 'March 2024') | Target period is selected and system begins validation process |
| 4 | Review the preview screen that displays the schedules to be copied | Conflict warnings are displayed in the preview, highlighting specific employees and time slots with overlaps or max hours violations. Warnings include clear descriptions of each conflict |
| 5 | Attempt to click 'Confirm Copy' or 'Save' button without resolving conflicts | Copy operation is blocked and system displays an error message stating 'Cannot copy schedules due to conflicts. Please resolve all conflicts before proceeding.' |
| 6 | Verify that the 'Confirm Copy' button remains disabled or shows validation error | Button is disabled or shows validation error, preventing the copy operation from executing until conflicts are resolved |

**Postconditions:**
- No schedules are copied to target period
- Source period schedules remain unchanged
- Target period schedules remain unchanged
- Conflict warnings remain visible on screen
- User is informed of specific conflicts that need resolution
- System maintains data integrity by preventing invalid schedule copies

---

