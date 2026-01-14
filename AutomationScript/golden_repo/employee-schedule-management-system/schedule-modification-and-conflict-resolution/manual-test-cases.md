# Manual Test Cases

## Story: As Scheduler, I want to modify employee schedules to achieve flexible shift management
**Story ID:** story-4

### Test Case: Validate successful modification of employee schedule
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with Scheduler role
- At least one employee with an existing schedule is available in the system
- Employee has valid contact information for notifications
- System notification service is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to employee schedule modification page by selecting an employee from the schedule list | Schedule modification page loads successfully and displays current schedule details including shift times, dates, and employee information |
| 2 | Change shift start time from current value to a new valid time and change shift end time accordingly | Modified shift times are displayed in the input fields without errors |
| 3 | Click the Submit or Save button to save the schedule changes | System validates the changes for conflicts, displays success message, and saves the modified schedule to the database |
| 4 | Verify notification sent to employee by checking the notification logs or employee's notification inbox | Employee receives schedule change notification via configured channels (email/in-app) with updated shift details |

**Postconditions:**
- Employee schedule is updated with new shift times in the database
- Notification is successfully delivered to the employee
- Schedule modification is logged in audit trail
- No scheduling conflicts exist

---

### Test Case: Verify shift swap request and approval workflow
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Two employees (Employee A and Employee B) are logged into the system
- Both employees have assigned shifts that are eligible for swapping
- Scheduler user has approval permissions for shift swaps
- Notification system is configured and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Employee A navigates to their schedule and initiates a shift swap request by selecting their shift and choosing Employee B as the swap partner | Swap request form is displayed with Employee A's shift details and Employee B as the selected swap partner |
| 2 | Employee A submits the shift swap request | Swap request is created with 'Pending Approval' status and appears in the Scheduler's approval queue |
| 3 | Scheduler logs in and navigates to the shift swap approval section | Pending swap request from Employee A is visible with all relevant details (employees involved, shift details, request date) |
| 4 | Scheduler reviews the swap request details and clicks the Approve button | System validates the swap for conflicts, executes the swap, and updates both Employee A's and Employee B's schedules accordingly |
| 5 | Verify notifications sent to both employees by checking notification logs | Both Employee A and Employee B receive confirmation notifications of the approved shift swap with updated schedule details |

**Postconditions:**
- Shift swap is completed and both employee schedules are updated
- Swap request status is changed to 'Approved'
- Both employees have received swap confirmation notifications
- Audit log contains complete record of the swap transaction

---

### Test Case: Validate audit logging of schedule modifications
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in with Scheduler role
- Audit logging system is enabled and operational
- At least one employee schedule exists in the system
- User has permissions to access audit logs

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to employee schedule modification page and select an employee schedule | Schedule details are displayed for modification |
| 2 | Modify the employee schedule by changing shift date or time and submit the changes | Modification is validated, saved successfully, and confirmation message is displayed |
| 3 | Navigate to the audit logs section and filter logs for the specific employee schedule that was modified | Audit log entry is displayed showing the modification details including: timestamp, user who made the change, original values, new values, and action type |
| 4 | Verify audit log integrity by checking that all required fields are populated and the timestamp matches the modification time | Audit logs are complete with all required information, unaltered, and accurately reflect the schedule modification that was performed |

**Postconditions:**
- Schedule modification is permanently recorded in audit logs
- Audit log entry contains complete and accurate information
- Audit log is immutable and cannot be modified
- Audit trail maintains compliance requirements

---

## Story: As Scheduler, I want to receive notifications for schedule changes to stay informed
**Story ID:** story-6

### Test Case: Validate notification sent on schedule creation
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in with Scheduler role
- Employee exists in the system with valid email address
- Notification service is operational and configured
- Employee has default notification preferences enabled for schedule creation
- System time is synchronized for accurate delivery time tracking

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule creation page and select an employee | Schedule creation form is displayed with employee information populated |
| 2 | Fill in all required schedule details including shift date, start time, end time, and any additional information | All schedule fields are populated with valid data |
| 3 | Click the Save or Create button to create the new employee schedule | Schedule is validated, saved successfully to the database, and confirmation message is displayed |
| 4 | Navigate to the notification delivery logs section and search for the notification event related to the newly created schedule | Notification event is logged with status 'Sent', timestamp, recipient details, and delivery channels used |
| 5 | Verify user receives notification via email by checking the employee's email inbox | Employee receives email notification containing the new schedule details within 1 minute of schedule creation |
| 6 | Verify user receives in-app notification by checking the employee's in-app notification center | Employee receives in-app notification with new schedule details displayed in their notification inbox within 1 minute |

**Postconditions:**
- New schedule is created and saved in the system
- Notification is delivered via both email and in-app channels
- Notification delivery is logged with successful status
- Notification delivery time is within 1 minute SLA

---

### Test Case: Verify user can configure notification preferences
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged into the system (Scheduler or Employee role)
- User profile exists with default notification settings
- Notification preferences feature is enabled in the system
- At least one notification channel option is available (email, in-app)

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to user profile settings by clicking on the user profile icon or menu | User profile page loads successfully |
| 2 | Locate and click on the notification preferences section or tab | Notification preferences section is visible displaying current notification settings with options for email and in-app notifications |
| 3 | Update notification channels by toggling email notifications off and keeping in-app notifications on | Notification channel selections are updated in the UI reflecting the new choices |
| 4 | Click the Save or Update button to save the notification preferences | Preferences are saved successfully, confirmation message is displayed, and the page reflects the updated settings |
| 5 | Trigger a notification event by creating or modifying a schedule that would normally send notifications to this user | Schedule change is saved and notification event is triggered |
| 6 | Verify notification is sent according to updated preferences by checking that in-app notification is received but email notification is not sent | User receives in-app notification only, no email notification is sent, and notification logs confirm delivery according to user preferences |

**Postconditions:**
- User notification preferences are updated and saved in the database
- Future notifications respect the updated preferences
- Notification delivery follows the configured channels only
- User preferences are persisted across sessions

---

## Story: As Scheduler, I want to validate schedule conflicts to achieve error-free scheduling
**Story ID:** story-7

### Test Case: Validate detection of overlapping shifts
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Scheduler role
- At least one employee exists in the system
- User has permission to create and modify schedules
- Schedule management interface is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule management page | Schedule management page loads successfully with employee list and calendar view |
| 2 | Select an employee from the employee list | Employee is selected and highlighted in the interface |
| 3 | Assign a shift to the selected employee for a specific time (e.g., Monday 9:00 AM - 5:00 PM) | Shift assignment form accepts the input and displays the shift details |
| 4 | Click 'Save' button to save the shift | Shift is saved successfully, confirmation message is displayed, and shift appears on the schedule calendar |
| 5 | Attempt to assign another overlapping shift to the same employee (e.g., Monday 3:00 PM - 11:00 PM) | System detects the overlap and displays a conflict alert with details of the conflicting shifts |
| 6 | Verify that the 'Save' button is disabled or clicking it does not save the conflicting schedule | System blocks the save operation and prevents the conflicting schedule from being saved |
| 7 | Resolve the conflict by adjusting the second shift time to non-overlapping hours (e.g., Monday 6:00 PM - 11:00 PM) | Conflict alert disappears and shift details are updated in the form |
| 8 | Click 'Save' button to save the adjusted shift | System validates the schedule, finds no conflicts, and saves the shift successfully with confirmation message |

**Postconditions:**
- Two non-overlapping shifts are saved for the employee
- No conflicting schedules exist in the system
- Schedule calendar displays both shifts correctly

---

### Test Case: Verify conflict alert displays detailed information
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in with Scheduler role
- At least one employee exists in the system with an existing shift assigned
- Existing shift is scheduled (e.g., Tuesday 8:00 AM - 4:00 PM)
- User has permission to modify schedules

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule management page | Schedule management page loads with existing schedules visible |
| 2 | Select the employee who already has a shift assigned for Tuesday 8:00 AM - 4:00 PM | Employee is selected and their existing shift is visible on the calendar |
| 3 | Attempt to assign an overlapping shift to the same employee (e.g., Tuesday 2:00 PM - 10:00 PM) | System triggers conflict detection and displays a conflict alert modal or notification |
| 4 | Review the conflict alert details | Alert displays detailed information including: employee name, existing shift time (Tuesday 8:00 AM - 4:00 PM), new conflicting shift time (Tuesday 2:00 PM - 10:00 PM), and overlap period (2:00 PM - 4:00 PM) |
| 5 | Verify that the alert provides clear guidance on resolving the conflict | Alert includes suggestions such as adjusting shift times or selecting a different time slot |
| 6 | Click 'Dismiss' or 'Close' button on the conflict alert | Alert closes and returns user to the schedule assignment form without saving the conflicting shift |
| 7 | Adjust the schedule to resolve the conflict by changing the shift time to non-overlapping hours (e.g., Tuesday 5:00 PM - 10:00 PM) | Shift details are updated in the form and no conflict alert appears |
| 8 | Click 'Save' button to save the adjusted schedule | Schedule is saved successfully with confirmation message and both shifts appear on the calendar without conflicts |

**Postconditions:**
- Conflict alert has been dismissed
- Adjusted schedule is saved without conflicts
- Employee has two non-overlapping shifts on Tuesday

---

## Story: As Scheduler, I want to generate reports on employee schedules to analyze workforce allocation
**Story ID:** story-10

### Test Case: Validate generation of schedule report with filters
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in with Scheduler or Manager role
- Multiple employee schedules exist in the system for different date ranges
- At least 10 schedule records are available for testing
- User has permission to access the reporting module

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the reporting module from the main menu or dashboard | Reporting module page loads successfully displaying report selection UI with available report types |
| 2 | Select 'Employee Schedule Report' from the report type dropdown or menu | Employee Schedule Report option is selected and filter criteria section is displayed |
| 3 | Select a date range filter (e.g., Start Date: 01/01/2024, End Date: 01/31/2024) | Date range is applied and displayed in the filter section |
| 4 | Select an employee filter from the employee dropdown (e.g., select specific employee or department) | Employee filter is applied and displayed in the active filters section |
| 5 | Verify that additional filter options are available (e.g., shift type, location) | Additional filter options are visible and selectable |
| 6 | Click 'Generate Report' button | System processes the request and displays a loading indicator |
| 7 | Wait for report generation to complete | Report is generated and displayed within 5 seconds showing schedule data matching the selected filters |
| 8 | Verify that the report contains correct data including employee names, shift times, dates, and shift types | Report displays accurate data matching the applied filters with all relevant columns populated |
| 9 | Verify that the report includes both summary and detailed views | Report shows summary statistics at the top and detailed schedule entries below |

**Postconditions:**
- Schedule report is successfully generated and displayed
- Report data matches the selected filter criteria
- Report is ready for export or further analysis

---

### Test Case: Verify export of report in PDF and Excel formats
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Scheduler or Manager role
- User has successfully generated a schedule report
- Report is currently displayed on screen
- User has permission to export reports
- Browser allows file downloads

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the reporting module and generate a schedule report with any valid filter criteria | Schedule report is generated and displayed successfully with export options visible |
| 2 | Locate the export options section (typically toolbar or action buttons) | Export options are visible showing PDF and Excel format buttons or dropdown |
| 3 | Click 'Export as PDF' button | System initiates PDF generation and browser download dialog appears or file downloads automatically |
| 4 | Open the downloaded PDF file using a PDF reader | PDF file opens successfully, displays the report with correct formatting, all data is visible and readable, headers and footers are properly formatted |
| 5 | Verify that the PDF contains all report data including summary and detailed views | PDF contains complete report data matching the on-screen report with proper pagination |
| 6 | Return to the report display page and click 'Export as Excel' button | System initiates Excel generation and browser download dialog appears or file downloads automatically |
| 7 | Open the downloaded Excel file using Microsoft Excel or compatible spreadsheet application | Excel file opens successfully with data properly formatted in cells and columns |
| 8 | Verify that the Excel file contains all report data with proper column headers and data types | Excel file contains complete report data with headers in the first row, dates formatted correctly, and all columns are properly sized and readable |
| 9 | Verify that data in Excel is editable and can be used for further analysis | Excel data is editable, formulas can be applied, and data can be sorted and filtered |

**Postconditions:**
- PDF report file is successfully downloaded and viewable
- Excel report file is successfully downloaded and viewable
- Both exported files contain accurate and complete report data
- Files are saved in the user's download directory

---

### Test Case: Validate scheduling of automated reports
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 12 mins

**Preconditions:**
- User is logged in with Scheduler or Manager role
- User has permission to schedule automated reports
- Email or notification system is configured
- At least one employee schedule exists in the system
- System time is correctly configured

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the reporting module | Reporting module page loads successfully |
| 2 | Click on 'Schedule Automated Report' or 'Schedule Report' button | Automated report scheduling interface is displayed with configuration options |
| 3 | Select 'Employee Schedule Report' as the report type | Report type is selected and additional configuration fields appear |
| 4 | Configure report criteria including date range (e.g., 'Last 7 days'), employee filter (e.g., 'All employees'), and format (e.g., 'PDF') | All criteria are selected and displayed in the configuration form |
| 5 | Set the schedule frequency (e.g., 'Daily', 'Weekly', or specific time) | Schedule frequency is selected and time picker is displayed |
| 6 | Set the schedule time to a near-future time for testing (e.g., 2 minutes from current time) | Schedule time is set and displayed in the form |
| 7 | Configure delivery method (e.g., email address or system notification) | Delivery method is configured and recipient information is entered |
| 8 | Click 'Save Schedule' or 'Create Scheduled Report' button | System validates the configuration and displays confirmation message that the scheduled report is saved |
| 9 | Verify that the scheduled report appears in the list of scheduled reports with correct details | Scheduled report is listed showing report type, criteria, frequency, next run time, and delivery method |
| 10 | Wait for the scheduled time to arrive (monitor for the configured time) | System automatically triggers report generation at the scheduled time |
| 11 | Check the configured delivery location (email inbox or notification center) | Report is generated automatically and delivered to the specified location |
| 12 | Verify report delivery or availability by opening the report | Report is accessible, contains correct data based on the configured criteria, and is in the specified format (PDF) |
| 13 | Navigate back to scheduled reports list and verify the 'Last Run' timestamp is updated | Scheduled report entry shows updated 'Last Run' timestamp and 'Next Run' time is calculated for the next occurrence |

**Postconditions:**
- Automated report schedule is successfully created and saved
- Report is generated automatically at the scheduled time
- Report is delivered or made available as configured
- Scheduled report remains active for future executions

---

