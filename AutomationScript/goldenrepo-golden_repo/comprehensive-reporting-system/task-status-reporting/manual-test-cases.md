# Manual Test Cases

## Story: As Project Manager, I want to view real-time task status reports to track project progress and identify delays
**Story ID:** story-3

### Test Case: View real-time task status report with filters
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Project Manager role
- Task management system contains active tasks with various statuses
- At least one task is overdue and one task is blocked
- User has authorization to access task status reporting module

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to task status reporting module from the main dashboard | Task status report UI is displayed with default view showing all tasks, filter options are visible including project, assignee, and status dropdowns |
| 2 | Select a specific project from the project filter dropdown | Project filter is applied, report refreshes within 3 seconds showing only tasks belonging to the selected project |
| 3 | Select a specific assignee from the assignee filter dropdown | Assignee filter is applied in addition to project filter, report refreshes within 3 seconds showing only tasks assigned to the selected user within the selected project |
| 4 | Verify the display of task statuses in the report | All filtered tasks are displayed with accurate real-time status information including task name, assignee, due date, current status, and progress indicators |
| 5 | Verify visual alerts for overdue tasks | Overdue tasks are highlighted with distinct visual indicators (red color, warning icon, or similar) making them easily identifiable |
| 6 | Verify visual alerts for blocked tasks | Blocked tasks are highlighted with distinct visual indicators (amber color, blocked icon, or similar) clearly differentiating them from other tasks |

**Postconditions:**
- Task status report displays filtered results accurately
- Overdue and blocked tasks are visually highlighted
- Report data reflects real-time task statuses
- Filters remain applied for subsequent interactions

---

### Test Case: Export task status report to PDF and Excel
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in with Project Manager role
- Task status reporting module is accessible
- Task data is available in the system
- User has export permissions
- Browser allows file downloads

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to task status reporting module and apply desired filters (project and assignee) | Task status report is displayed with filtered data showing relevant tasks with accurate status information |
| 2 | Click on the 'Export to PDF' button | PDF file generation process initiates, download prompt appears, and PDF file is downloaded to the default download location |
| 3 | Open the downloaded PDF file | PDF opens successfully displaying the task status report with all filtered data, visual formatting is preserved, overdue and blocked tasks are highlighted, all columns and data are accurate and match the on-screen report |
| 4 | Return to the task status report and click on the 'Export to Excel' button | Excel file generation process initiates, download prompt appears, and Excel file (.xlsx or .xls) is downloaded to the default download location |
| 5 | Open the downloaded Excel file | Excel file opens successfully with task status report data in tabular format, all columns are properly formatted, data is accurate and matches the on-screen report, overdue and blocked tasks are identifiable through formatting or separate columns |
| 6 | Verify data accuracy in both exported files against the on-screen report | Both PDF and Excel exports contain 100% accurate data matching the filtered report displayed on screen, including task names, assignees, due dates, statuses, and visual indicators for overdue/blocked tasks |

**Postconditions:**
- PDF file is successfully downloaded and contains accurate report data
- Excel file is successfully downloaded and contains accurate report data
- Both exported files are accessible and readable
- Original report view remains unchanged on screen

---

### Test Case: Subscribe to task status report notifications
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 12 mins

**Preconditions:**
- User is logged in with Project Manager role
- Task status reporting module is accessible
- User has a valid email address configured in the system
- Notification service is operational
- User has subscription management permissions

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to task status reporting module | Task status report UI is displayed with subscription options visible |
| 2 | Click on 'Subscription Settings' or 'Subscribe to Reports' button | Subscription configuration UI is displayed showing options for frequency (daily, weekly, monthly), report filters, delivery format (PDF, Excel), and email preferences |
| 3 | Select subscription frequency as 'Daily' | Daily frequency option is selected and highlighted |
| 4 | Configure report filters by selecting specific project and status criteria | Selected filters are applied to the subscription configuration, preview shows what data will be included in scheduled reports |
| 5 | Select delivery format as 'PDF and Excel' | Both PDF and Excel format options are selected for report delivery |
| 6 | Enter or verify email address for report delivery | Email address field displays the correct email address where reports will be sent |
| 7 | Click 'Save' or 'Subscribe' button | Subscription is saved successfully, confirmation message is displayed stating 'Subscription saved successfully' or similar, subscription appears in the list of active subscriptions |
| 8 | Wait for the scheduled report delivery time (simulate or wait for actual delivery based on test environment) | Email notification is received at the configured email address at the scheduled time |
| 9 | Open the received email notification | Email contains task status report as attachments in both PDF and Excel formats, email body includes summary information and links to access the full report online |
| 10 | Download and verify the attached report files | Both PDF and Excel attachments open successfully, contain accurate task status data matching the configured filters, and display overdue/blocked task highlights |

**Postconditions:**
- Subscription is active and saved in the system
- User receives scheduled email notifications with report attachments
- Subscription can be viewed and managed in subscription settings
- Report data in notifications is accurate and up-to-date

---

## Story: As Project Manager, I want to receive notifications for overdue tasks to enable timely interventions
**Story ID:** story-7

### Test Case: Receive notification for overdue task
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in with Project Manager role
- Task management system is operational
- Notification service is enabled and functional
- User has a valid email address configured
- User has permissions to receive overdue task notifications
- System time is synchronized and accurate

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Create a new task with a due date set to a past date (e.g., yesterday) | Task is created successfully with past due date, task appears in the task list, system automatically marks the task status as 'overdue' based on the past due date |
| 2 | Wait for the notification processing cycle (maximum 1 minute as per performance requirements) | System detects the overdue task through real-time monitoring, notification generation process is triggered |
| 3 | Check email inbox for overdue task notification | Email notification is received within 1 minute of task becoming overdue, email subject clearly indicates overdue task alert, email body contains task details including task name, due date, assignee, and current status |
| 4 | Check in-app notifications panel or notification center | In-app notification is displayed in the notification center, notification shows overdue task information with visual indicator (red badge or similar), notification timestamp is accurate |
| 5 | Click on the task details link provided in the email notification | Browser opens and navigates directly to the task details page, user is authenticated automatically or redirected to login if session expired, task details page displays complete information about the overdue task |
| 6 | Click on the in-app notification | Application navigates to the task details page, task details are displayed with all relevant information including task name, description, assignee, due date, current status, and overdue indicator |
| 7 | Verify the accuracy of task information in the notification against actual task data | All task details in the notification match the actual task data in the system with 100% accuracy, due date comparison is correct, overdue status is accurately reflected |

**Postconditions:**
- Overdue task notification is successfully delivered via email and in-app
- Notification links provide direct access to task details
- Task remains marked as overdue in the system
- Notification is logged in the notification history
- Project Manager can take corrective action based on the notification

---

### Test Case: Manage notification subscription preferences
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 15 mins

**Preconditions:**
- User is logged in with Project Manager role
- Notification system is operational
- User has access to notification settings
- At least one overdue task exists or can be created for testing
- User has valid email address configured

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to user profile or settings menu | Settings menu is displayed with options including notification preferences or subscription settings |
| 2 | Click on 'Notification Settings' or 'Subscription Preferences' | Notification subscription UI is displayed showing various notification types including overdue task notifications, each notification type has toggle or checkbox controls for email and in-app notifications |
| 3 | Locate the 'Overdue Task Notifications' section | Overdue task notification preferences are displayed with separate controls for email notifications and in-app notifications, current subscription status is clearly indicated (enabled or disabled) |
| 4 | Disable email notifications for overdue tasks by unchecking or toggling off the email option | Email notification toggle changes to disabled state, visual indicator shows email notifications are turned off |
| 5 | Keep in-app notifications enabled for overdue tasks | In-app notification toggle remains in enabled state |
| 6 | Click 'Save' or 'Update Preferences' button | Preferences are saved successfully, confirmation message is displayed stating 'Notification preferences updated successfully' or similar, page reflects the updated settings |
| 7 | Create a new task with past due date or wait for an existing task to become overdue | Task is marked as overdue by the system |
| 8 | Wait for notification processing (up to 1 minute) | System processes the overdue task detection |
| 9 | Check email inbox for overdue task notification | No email notification is received for the overdue task, confirming that email notifications are successfully disabled |
| 10 | Check in-app notification center | In-app notification for the overdue task is displayed, confirming that in-app notifications remain enabled and functional |
| 11 | Return to notification subscription settings and enable email notifications for overdue tasks | Email notification toggle changes to enabled state, settings are saved successfully |
| 12 | Create another task with past due date or modify an existing task to become overdue | Task is marked as overdue |
| 13 | Wait for notification processing and verify both email and in-app notifications are received | Both email notification and in-app notification are received for the overdue task, confirming that re-enabling email notifications works correctly and notification behavior matches the updated preferences |

**Postconditions:**
- Notification subscription preferences are saved correctly
- Email notifications are suppressed when disabled
- In-app notifications continue to function when enabled
- Re-enabling notifications restores full notification functionality
- User has control over notification delivery channels

---

## Story: As Project Manager, I want to export task status reports to Excel for detailed analysis
**Story ID:** story-11

### Test Case: Export task status report to Excel
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as Project Manager with authorized access
- Task status report data exists in the system with at least 10 records
- User has permissions to export reports
- Browser supports file downloads
- System API endpoint POST /api/reports/taskstatus/export is available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the task status reports section | Task status reports page is displayed with available report options |
| 2 | Select filters or parameters for the task status report (date range, project, status) | Selected filters are applied and highlighted in the UI |
| 3 | Click on 'Generate Report' button | System processes the request and displays the task status report with columns including task name, status, assignee, due date, priority, and completion percentage |
| 4 | Verify the report data is displayed correctly on screen | Report is displayed with accurate data matching the selected filters, all columns are visible and properly aligned |
| 5 | Locate and click on 'Export to Excel' button | Export process initiates, progress indicator or loading spinner is displayed |
| 6 | Wait for export processing to complete | Export completes within 10 seconds, success message is displayed, and Excel file download begins automatically |
| 7 | Check the downloaded file location and verify file name format (e.g., TaskStatusReport_YYYY-MM-DD.xlsx) | Excel file is downloaded successfully to the default download folder with proper naming convention including timestamp |
| 8 | Open the downloaded Excel file using Microsoft Excel or compatible spreadsheet application | Excel file opens without errors or corruption warnings |
| 9 | Verify the Excel file structure: check that all columns from the report are present (task name, status, assignee, due date, priority, completion percentage) | All columns are present in the Excel file with proper headers in the first row |
| 10 | Verify data accuracy by comparing at least 5 sample records from the Excel file with the original report displayed on screen | Data in Excel file matches exactly with the data displayed in the original report |
| 11 | Check formatting: verify column widths are appropriate, headers are bold, dates are formatted correctly, and percentages display with % symbol | Excel file maintains proper formatting with readable column widths, bold headers, correct date format (MM/DD/YYYY or system default), and percentage values formatted with % symbol |
| 12 | Verify that all rows from the report are exported (check row count excluding header) | Total number of data rows in Excel matches the record count shown in the original report |

**Postconditions:**
- Excel file is successfully downloaded and saved to local system
- Original report remains displayed on screen unchanged
- Export action is logged in system audit trail
- User can perform additional exports or navigate away from the page
- Downloaded Excel file can be opened, edited, and shared offline

---

