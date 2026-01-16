# Manual Test Cases

## Story: As Manager, I want to modify employee schedules to achieve flexible workforce management
**Story ID:** story-3

### Test Case: Modify an assigned shift without conflicts
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Manager is logged into the system with valid credentials
- Manager has role-based access permissions for schedule management
- At least one employee has an assigned shift in the system
- The target shift to be modified exists and is not in the past
- No conflicting shifts exist for the selected time slot

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the employee schedule management page from the main dashboard | Employee schedule management page loads successfully and displays a list of all scheduled shifts with employee names, dates, and shift times |
| 2 | Locate and select a specific shift from the schedule list by clicking on it | Shift details are displayed and an edit option/button becomes available |
| 3 | Click the edit button to open the shift modification form | Edit shift form opens displaying current shift details including date, time, shift template, and employee assignment |
| 4 | Modify the shift details by changing the date and/or shift template to a non-conflicting time slot | Form accepts the changes without displaying any validation errors or conflict warnings |
| 5 | Click the submit/save button to apply the modification | System processes the modification, shift is updated successfully in the database, and a confirmation message is displayed stating 'Shift updated successfully' |
| 6 | Verify the updated shift appears in the schedule list with the new details | Schedule list refreshes and displays the modified shift with updated date and time information |
| 7 | Check that notifications have been sent to the affected employee and relevant managers | System confirms notifications were sent via email and in-app alerts to all affected parties |

**Postconditions:**
- Shift is updated in the EmployeeSchedules database with new details
- Audit log entry is created with manager ID, timestamp, and modification details
- Notifications are sent to the affected employee and managers
- Schedule list reflects the updated shift information
- No scheduling conflicts exist in the system

---

### Test Case: Cancel an assigned shift with reason
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Manager is logged into the system with valid credentials
- Manager has role-based access permissions for schedule management
- At least one employee has an assigned shift that can be cancelled
- The shift to be cancelled is not already cancelled
- Email and in-app notification systems are operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the employee schedule management page | Schedule management page loads and displays all scheduled shifts |
| 2 | Select a scheduled shift to cancel by clicking on it | Shift details are displayed with available actions including a cancel option |
| 3 | Click the cancel shift button | Cancellation form is displayed with a mandatory reason input field and confirmation/cancel buttons |
| 4 | Enter a valid cancellation reason in the reason input field (e.g., 'Employee requested time off') | Text is accepted in the reason field without errors, and the field shows the entered text |
| 5 | Click the confirm cancellation button | System processes the cancellation, shift status is updated to cancelled, and a confirmation message is displayed stating 'Shift cancelled successfully' |
| 6 | Verify the cancelled shift is marked as cancelled in the schedule list | Schedule list updates and the shift is displayed with a cancelled status indicator and the cancellation reason is visible |
| 7 | Check email inbox for the affected employee | Email notification is received by the employee containing shift cancellation details and reason |
| 8 | Check in-app notifications for the affected employee | In-app notification is present in the employee's notification center with cancellation details |
| 9 | Verify notification sent to manager | Manager receives confirmation notification via email and in-app alert confirming the shift cancellation |

**Postconditions:**
- Shift status is updated to cancelled in the EmployeeSchedules database
- Cancellation reason is stored with the shift record
- Audit log entry is created with manager ID, timestamp, cancellation reason, and change details
- Email notifications are delivered to employee and manager
- In-app notifications are delivered to employee and manager
- Cancelled shift is visible in schedule with cancelled status

---

### Test Case: Verify audit logging of schedule modifications
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Manager is logged into the system with valid credentials
- Manager has role-based access permissions for schedule management and audit log access
- At least one scheduled shift exists that can be modified or cancelled
- Audit logging system is enabled and operational
- Manager's user ID and timestamp information are available in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the employee schedule management page | Schedule management page loads successfully displaying all scheduled shifts |
| 2 | Select a scheduled shift and modify its details (change date or time) or cancel it with a reason | Modification or cancellation is processed successfully and confirmation message is displayed |
| 3 | Note the specific details of the modification including the shift ID, old values, new values, and the exact time of modification | Modification details are visible in the confirmation message or schedule view |
| 4 | Navigate to the audit log section or access audit logs for the specific schedule | Audit log interface loads successfully showing a list of recent schedule modifications |
| 5 | Search or filter the audit log for the recently modified shift using shift ID or employee name | Audit log displays the relevant entry for the modified shift |
| 6 | Verify the audit log entry contains the manager's user ID who performed the modification | Log entry displays the correct manager user ID matching the logged-in manager |
| 7 | Verify the audit log entry contains an accurate timestamp of when the modification occurred | Timestamp in the log entry matches the time when the modification was performed (within acceptable system time variance) |
| 8 | Verify the audit log entry contains complete change details including old values and new values | Log entry shows before and after values for all modified fields (e.g., old date/time vs new date/time, or cancellation reason) |
| 9 | Confirm the log entry includes the action type (modification or cancellation) | Log entry clearly indicates whether the action was an edit/modification or a cancellation |
| 10 | Verify log accuracy by comparing all logged details with the actual modification performed | All log details (user ID, timestamp, old values, new values, action type) accurately match the performed modification with 100% accuracy |

**Postconditions:**
- Audit log entry exists in the AuditLogs database
- Log entry contains complete and accurate information about the schedule modification
- Log entry includes manager user ID, timestamp, action type, and change details
- Audit trail maintains 100% coverage for the schedule change
- Log entry is immutable and cannot be altered
- Audit log is accessible for future compliance and reporting purposes

---

## Story: As Employee, I want to view my assigned schedule to achieve awareness of my work shifts
**Story ID:** story-4

### Test Case: View assigned schedule for logged-in employee
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Employee has valid login credentials in the system
- Employee has at least one assigned shift in the EmployeeSchedules database
- System authentication and authorization services are operational
- Employee's schedule data is up-to-date and accurate
- Schedule viewing page loads within 2 seconds performance requirement

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the system login page and enter valid employee credentials (username and password) | Login is successful and employee is authenticated |
| 2 | Verify the employee dashboard is displayed after successful login | Dashboard loads successfully showing employee-specific menu options and navigation elements |
| 3 | Locate and click on the 'My Schedule' navigation link or menu item | 'My Schedule' page loads within 2 seconds displaying the employee's personal schedule interface |
| 4 | Verify the schedule page displays assigned shifts for the current date range (default view) | Schedule page shows all assigned shifts for the employee with dates, times, and shift information clearly visible in list or calendar view |
| 5 | Select or click on a specific shift to view detailed information | Shift details panel or modal opens displaying comprehensive information |
| 6 | Verify shift details include start time information | Start time is displayed accurately in the correct time format (e.g., 9:00 AM) |
| 7 | Verify shift details include end time information | End time is displayed accurately in the correct time format (e.g., 5:00 PM) |
| 8 | Verify shift details include break time information | Break times and duration are displayed correctly (e.g., 12:00 PM - 1:00 PM, 1 hour lunch break) |
| 9 | Verify all displayed shift information matches the actual assigned schedule in the database | All shift times, dates, and break information are 100% accurate and match the EmployeeSchedules data source |
| 10 | Test date range selection by choosing a different date range (e.g., next week or next month) | Schedule updates to display shifts for the selected date range accurately |

**Postconditions:**
- Employee remains logged into the system
- Schedule data is displayed accurately without modifications
- No unauthorized access to other employees' schedules occurred
- System performance met the 2-second load time requirement
- Employee can continue to navigate to other sections of the application

---

### Test Case: Receive notification on schedule change
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Employee has valid login credentials and is registered in the system
- Employee has at least one assigned shift that can be modified
- Manager has permissions to modify employee schedules
- Email notification system is configured and operational
- In-app notification system is enabled
- Employee's email address is registered and valid in the system
- Employee has access to their email inbox and the application

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Manager logs into the system and navigates to employee schedule management page | Manager successfully accesses the schedule management interface |
| 2 | Manager selects the employee's assigned shift and modifies it (changes date, time, or shift template) | Schedule modification is processed successfully and saved to the EmployeeSchedules database |
| 3 | System triggers notification process for the schedule change | Notification system initiates sending notifications to the affected employee |
| 4 | Check the employee's email inbox for schedule change notification | Email notification is received containing the schedule change details including old shift information, new shift information, date of change, and who made the change |
| 5 | Verify the email notification content is accurate and complete | Email contains all relevant details: employee name, old schedule, new schedule, modification date/time, and manager who made the change |
| 6 | Employee logs into the system | Employee successfully logs in and dashboard is displayed |
| 7 | Check the in-app notification center or notification icon | In-app notification is present indicating a schedule change with a notification badge or indicator |
| 8 | Click on the in-app notification to view details | Notification details are displayed showing the schedule change information including old and new shift details |
| 9 | Navigate to 'My Schedule' page from the notification or main menu | 'My Schedule' page loads successfully |
| 10 | Verify the schedule displays the updated shift information | Schedule reflects the latest changes made by the manager with accurate new date, time, and shift details |
| 11 | Confirm the old shift is no longer displayed or is marked as modified | Old shift information is replaced with new shift details, and schedule shows current accurate information |

**Postconditions:**
- Employee's schedule is updated in the system with the latest changes
- Email notification is delivered and stored in employee's email inbox
- In-app notification is marked as delivered in the notification system
- Employee is aware of the schedule change through multiple notification channels
- Notification delivery meets the 95% timely delivery success metric
- Audit log contains record of the notification being sent

---

### Test Case: Export schedule to calendar format
- **ID:** tc-006
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 12 mins

**Preconditions:**
- Employee is logged into the system with valid credentials
- Employee has at least one assigned shift in their schedule
- Employee has navigated to the 'My Schedule' page
- Export functionality is enabled and operational
- Employee's browser allows file downloads
- Employee has a personal calendar application available (e.g., Google Calendar, Outlook, Apple Calendar)

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | On the 'My Schedule' page, locate and click the export schedule button or option | Export options menu or dialog is displayed showing available calendar format options |
| 2 | Review the available export format options (e.g., iCal/ICS, CSV, Google Calendar) | Multiple common calendar format options are displayed and selectable |
| 3 | Select a preferred calendar format (e.g., iCal/ICS format) from the available options | Selected format is highlighted or marked as chosen |
| 4 | Click the confirm export or download button | System processes the export request and initiates file download |
| 5 | Verify the schedule file is downloaded to the local device | File is successfully downloaded with appropriate filename (e.g., 'my_schedule.ics') and appears in the browser's download location |
| 6 | Check the downloaded file size and format | File has a valid size (greater than 0 bytes) and correct file extension matching the selected format |
| 7 | Open the personal calendar application (e.g., Google Calendar, Outlook) | Calendar application launches successfully |
| 8 | Use the calendar application's import function to import the downloaded schedule file | Calendar application recognizes the file format and initiates the import process without errors |
| 9 | Complete the import process in the calendar application | Import completes successfully and confirmation message is displayed in the calendar application |
| 10 | Navigate to the date range where shifts were scheduled in the calendar application | Calendar displays the imported shifts on the correct dates |
| 11 | Verify each imported shift shows correct start time, end time, and shift details | All shift information is correctly imported and displayed including accurate start times, end times, break information, and any additional shift details |
| 12 | Compare the imported calendar entries with the original schedule in the system | All shifts from the employee's schedule are present in the calendar with 100% accuracy and no missing or incorrect entries |

**Postconditions:**
- Schedule file is successfully downloaded to employee's device
- Schedule is imported into employee's personal calendar application
- All shift information is accurately reflected in the personal calendar
- Employee can view their work schedule in their personal calendar alongside personal appointments
- Original schedule in the system remains unchanged
- Export action may be logged in system audit trail

---

## Story: As Manager, I want to generate reports on shift coverage to achieve optimized workforce planning
**Story ID:** story-6

### Test Case: Generate shift coverage report for a date range
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Manager role
- At least one department exists in the system
- Employee schedules exist for the selected date range
- User has permission to access reporting section

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the reporting section from the main dashboard | Reporting page loads successfully and displays available report options including shift coverage, employee hours, and scheduling conflicts |
| 2 | Select 'Shift Coverage Report' from the report type dropdown | Shift coverage report form is displayed with date range and department filter options |
| 3 | Enter start date in the 'From Date' field (e.g., 01/01/2024) | Start date is accepted and displayed in the correct format |
| 4 | Enter end date in the 'To Date' field (e.g., 01/31/2024) | End date is accepted and displayed in the correct format |
| 5 | Select a department from the department filter dropdown | Department is selected and displayed in the filter field |
| 6 | Click the 'Generate Report' button | Report generation begins and a loading indicator is displayed |
| 7 | Wait for report to complete generation | Report is generated within 5 seconds and displays shift coverage data including employee names, shift dates, shift times, total hours, and coverage status for the specified date range and department |
| 8 | Verify the accuracy of displayed data by cross-referencing with known schedule entries | All data in the report matches the actual employee schedules in the system with 100% accuracy |

**Postconditions:**
- Shift coverage report is displayed on screen
- Report data is accurate and matches database records
- Report generation is logged in the system
- User remains on the reporting page

---

### Test Case: Export report to PDF and Excel
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in with Manager role
- A shift coverage report has been successfully generated and is displayed on screen
- User has appropriate file download permissions
- Browser allows file downloads

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Verify that a shift coverage report is currently displayed on the screen | Report is visible with complete data including shift coverage information, employee hours, and any identified conflicts |
| 2 | Locate and click the 'Export to PDF' button in the report toolbar | PDF export process initiates and a download dialog appears or file automatically downloads to the default download location |
| 3 | Navigate to the download location and open the downloaded PDF file | PDF file opens successfully and contains all report data with proper formatting, headers, and footers. Data matches the on-screen report exactly |
| 4 | Return to the report page and locate the 'Export to Excel' button in the report toolbar | Export to Excel button is visible and clickable |
| 5 | Click the 'Export to Excel' button | Excel export process initiates and a download dialog appears or file automatically downloads to the default download location |
| 6 | Navigate to the download location and open the downloaded Excel file | Excel file opens successfully in spreadsheet application and contains all report data in a structured format with proper columns and rows. Data matches the on-screen report exactly and is editable |
| 7 | Verify that both exported files contain the same data as displayed in the on-screen report | PDF and Excel files both contain identical data matching the original report with no data loss or corruption |

**Postconditions:**
- PDF file is successfully downloaded and contains accurate report data
- Excel file is successfully downloaded and contains accurate report data
- Both files are accessible in the download location
- Original report remains displayed on screen
- Export actions are logged in the system

---

### Test Case: Verify report highlights uncovered shifts
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in with Manager role
- Test data includes at least one uncovered shift in the system
- Test data includes at least one scheduling conflict
- Date range for testing encompasses the uncovered shifts and conflicts

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the reporting section from the main dashboard | Reporting page loads successfully and displays available report options |
| 2 | Select 'Shift Coverage Report' and specify a date range that includes known uncovered shifts | Report parameters are accepted and date range is set correctly |
| 3 | Select the department that contains uncovered shifts | Department filter is applied successfully |
| 4 | Click 'Generate Report' button | Report is generated within 5 seconds and displays on screen |
| 5 | Scan the report for visual indicators of uncovered shifts (e.g., highlighted rows, warning icons, or color coding) | Uncovered shifts are clearly highlighted using distinct visual indicators such as red highlighting, warning icons, or bold text that differentiate them from covered shifts |
| 6 | Review the details of each highlighted uncovered shift | Each uncovered shift displays complete information including shift date, shift time, required position, and clear indication that no employee is assigned |
| 7 | Locate the scheduling conflicts section or indicators in the report | Scheduling conflicts are clearly identified with visual indicators such as yellow highlighting, conflict icons, or specific conflict markers |
| 8 | Review the details of identified scheduling conflicts | Each conflict displays detailed information including the conflicting shifts, affected employees, dates, times, and the nature of the conflict (e.g., double-booking, overlapping shifts) |
| 9 | Verify the count of uncovered shifts and conflicts matches the actual data in the system | The number of uncovered shifts and conflicts displayed in the report matches the actual count in the database with 100% accuracy |

**Postconditions:**
- Report accurately displays all uncovered shifts with clear highlighting
- All scheduling conflicts are identified and highlighted
- Report data is accurate and verifiable
- User can easily distinguish between covered shifts, uncovered shifts, and conflicts
- Report remains available for export or further review

---

## Story: As Scheduler, I want to receive notifications on schedule changes to achieve timely awareness
**Story ID:** story-8

### Test Case: Receive notification on schedule modification
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in with Scheduler role
- At least one employee exists in the system with an assigned schedule
- Email notification service is configured and operational
- In-app notification service is enabled
- Employee has valid email address in their profile
- Employee has email and in-app notifications enabled in preferences

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the employee scheduling page | Scheduling page loads successfully and displays list of employees and their current schedules |
| 2 | Select an employee from the schedule list | Employee's current schedule details are displayed including shift dates, times, and assigned positions |
| 3 | Click the 'Edit Schedule' button for the selected employee | Schedule editing form opens with current schedule information pre-populated |
| 4 | Modify the schedule by changing the shift time from the original time to a new time (e.g., from 9:00 AM - 5:00 PM to 10:00 AM - 6:00 PM) | New shift time is entered successfully in the form fields |
| 5 | Click 'Save' or 'Update Schedule' button to confirm the modification | Schedule is updated successfully in the system and a confirmation message is displayed. Notification trigger event is initiated |
| 6 | Log in to the affected employee's email account and check the inbox | Email notification about the schedule change is received within 2 minutes. Email subject line clearly indicates a schedule modification |
| 7 | Open and review the email notification content | Email contains accurate schedule details including employee name, previous shift time (9:00 AM - 5:00 PM), new shift time (10:00 AM - 6:00 PM), shift date, department, and the name of the scheduler who made the change |
| 8 | Log in to the application as the affected employee and navigate to the notifications section or check the notification bell icon | In-app notification indicator shows at least one unread notification |
| 9 | Click on the notification bell icon or open the notifications panel | In-app notification about the schedule change is displayed in the notification list with a timestamp |
| 10 | Click on the schedule change notification to view full details | Notification expands or opens to show complete schedule change information including employee name, previous shift time, new shift time, shift date, department, and scheduler name. All details match the email notification and actual schedule change |
| 11 | Verify the accuracy of all notification content against the actual schedule modification made | All information in both email and in-app notifications is 100% accurate and matches the schedule change made in step 4-5 |

**Postconditions:**
- Employee schedule is successfully updated in the system
- Email notification is delivered to employee's email address
- In-app notification is visible in employee's notification center
- Notification delivery status is logged in the system
- Both notifications contain accurate and complete schedule change information
- Notification is marked as unread until employee views it

---

### Test Case: Configure notification preferences
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 12 mins

**Preconditions:**
- User is logged in to the system
- User has access to account settings or preferences section
- Notification preferences feature is enabled in the system
- User currently has default notification settings applied

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the user profile or account settings page | Account settings page loads successfully and displays navigation menu or tabs for various settings options |
| 2 | Locate and click on 'Notification Settings' or 'Notification Preferences' menu item | Notification settings page is displayed showing all available notification options including email notifications toggle, in-app notifications toggle, and notification types (schedule creation, modification, cancellation) |
| 3 | Review the current state of email notification toggle (note whether it is enabled or disabled) | Current email notification preference is clearly displayed with an ON/OFF toggle or checkbox |
| 4 | Click the email notification toggle to change its state (if enabled, disable it; if disabled, enable it) | Toggle switches to the opposite state with visual feedback (e.g., color change, position change) |
| 5 | Review the current state of in-app notification toggle | Current in-app notification preference is clearly displayed with an ON/OFF toggle or checkbox |
| 6 | Click the in-app notification toggle to change its state | Toggle switches to the opposite state with visual feedback |
| 7 | Click the 'Save' or 'Update Preferences' button to save the changes | Preferences are saved successfully and a confirmation message is displayed (e.g., 'Notification preferences updated successfully') |
| 8 | Refresh the page or navigate away and return to the notification settings page | Previously saved notification preferences are retained and displayed correctly, confirming that changes were persisted to the database |
| 9 | As a Scheduler user, modify the current user's schedule to trigger a schedule change event | Schedule is modified successfully in the system and notification trigger event is initiated |
| 10 | If email notifications were ENABLED in step 4, check the user's email inbox. If DISABLED, verify no email is received | Email notification is received only if email notifications were enabled in preferences. No email is received if disabled. Delivery matches the saved preference setting |
| 11 | If in-app notifications were ENABLED in step 6, check the notification center in the application. If DISABLED, verify no in-app notification appears | In-app notification appears only if in-app notifications were enabled in preferences. No in-app notification appears if disabled. Delivery matches the saved preference setting |
| 12 | Verify that notifications are sent strictly according to the configured preferences | Notification delivery behavior is 100% consistent with the saved preferences. Only enabled notification channels receive notifications, and disabled channels receive none |

**Postconditions:**
- User notification preferences are saved in the database
- Email notification setting reflects user's choice
- In-app notification setting reflects user's choice
- Future notifications are sent only according to saved preferences
- Preference changes are logged in the system
- User remains on the notification settings page or is redirected to a confirmation page

---

## Story: As Employee, I want to receive notifications about my schedule changes to achieve timely updates
**Story ID:** story-10

### Test Case: Receive notification on schedule creation
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Employee account is active and registered in the system
- Employee has a valid email address configured in their profile
- Employee is logged into the application or has access to their email
- Manager has appropriate permissions to create schedules
- Notification service is operational and configured correctly

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Manager logs into the system and navigates to the schedule management section | Schedule management interface is displayed with options to create new shifts |
| 2 | Manager selects the employee from the employee list and assigns a new shift with specific date, time, and location details | Shift assignment form is completed with all required fields populated |
| 3 | Manager saves the newly created shift assignment | Schedule is successfully created and saved in the system with confirmation message displayed |
| 4 | System triggers notification service to send notifications to the employee | Notification service processes the request and queues email and in-app notifications |
| 5 | Employee checks their registered email inbox | Email notification is received containing the shift details including date, time, location, and shift type |
| 6 | Employee logs into the application and checks the in-app notification center | In-app notification is displayed with the same shift details as the email, marked as unread |
| 7 | Employee clicks on the in-app notification to view full details | Notification expands to show complete shift information with accurate details matching the created schedule |
| 8 | Employee navigates to the notification history section in their profile | Notification history page is displayed showing all past notifications |
| 9 | Employee locates the schedule creation notification in the history list | The notification is listed with accurate timestamp, shift details, and notification type clearly indicated as 'Schedule Created' |

**Postconditions:**
- Schedule is created and visible in the employee's schedule view
- Notification is marked as delivered in the system logs
- Notification appears in employee's notification history
- Email notification is stored in employee's email inbox
- Notification delivery is logged for monitoring purposes

---

### Test Case: Receive notification on schedule cancellation
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Employee has an existing shift assigned in the system
- Employee account is active with valid email address configured
- Employee has access to the application and email
- Manager has appropriate permissions to cancel schedules
- Notification service is operational and configured correctly
- The assigned shift is in future date and not yet completed

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Manager logs into the system and navigates to the schedule management section | Schedule management interface is displayed with list of existing schedules |
| 2 | Manager locates the employee's assigned shift that needs to be cancelled | The specific shift is displayed with all details including employee name, date, time, and location |
| 3 | Manager selects the cancel option for the assigned shift and confirms the cancellation action | Cancellation confirmation dialog appears requesting final confirmation |
| 4 | Manager confirms the cancellation by clicking the confirm button | Schedule is successfully cancelled in the system with status updated to 'Cancelled' and confirmation message displayed |
| 5 | System triggers notification service to send cancellation notifications to the employee | Notification service processes the cancellation event and queues email and in-app notifications |
| 6 | Employee checks their registered email inbox | Email notification is received with subject line clearly indicating schedule cancellation |
| 7 | Employee opens the cancellation email notification | Email content clearly states that the shift has been cancelled, includes original shift details (date, time, location), and provides cancellation timestamp |
| 8 | Employee logs into the application and checks the in-app notification center | In-app notification is displayed with cancellation alert, marked with appropriate icon or color indicating cancellation |
| 9 | Employee clicks on the in-app cancellation notification | Notification expands showing complete cancellation details with clear indication that the shift is no longer active and has been removed from the schedule |
| 10 | Employee verifies the cancelled shift in their schedule view | The shift either shows as cancelled with strikethrough or is removed from the active schedule, confirming the cancellation |

**Postconditions:**
- Schedule is cancelled and marked as inactive in the system
- Cancellation notification is delivered via both email and in-app channels
- Notification is logged in the employee's notification history
- Cancelled shift is removed or marked as cancelled in employee's schedule view
- Notification delivery is logged and monitored for audit purposes
- Employee is aware of the schedule cancellation

---

