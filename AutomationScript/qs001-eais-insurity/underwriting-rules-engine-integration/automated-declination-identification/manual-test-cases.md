# Manual Test Cases

## Story: As Underwriting Manager, I want to receive automatic declination notifications to achieve faster decision-making and workload management
**Story ID:** story-25

### Test Case: Validate automatic declination marking and notification
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User has valid underwriting manager credentials
- Rules engine is configured with declination criteria
- Notification service is operational
- Manager dashboard is accessible
- Test application data is prepared that meets declination criteria

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Submit an application that meets declination criteria (e.g., credit score below threshold, debt-to-income ratio exceeds limit) | Application is successfully submitted to the rules engine for evaluation |
| 2 | Wait for rules engine to process the application (maximum 2 seconds) | Rules engine evaluates the application against declination criteria |
| 3 | Verify the application status in the system database or via GET /api/declinations endpoint | System marks the application status as 'Declined' with appropriate declination code |
| 4 | Check the underwriting manager's notification inbox/email/dashboard alerts | Notification is received by the underwriting manager promptly (within real-time threshold) containing application ID and declination summary |
| 5 | Log in as underwriting manager and navigate to the declined applications dashboard | Manager dashboard loads successfully and displays the declined applications section |
| 6 | Locate the recently declined application in the dashboard list | Declined application is listed in the dashboard with application ID, applicant name, declination date, and timestamp |
| 7 | Click on the declined application to view detailed declination reasons | Detailed view displays complete declination reasons (e.g., 'Credit score 580 below minimum 620', 'DTI ratio 48% exceeds maximum 43%') with audit trail information |
| 8 | Verify declination reason is logged in the audit system | Audit log contains entry with application ID, declination timestamp, specific reasons, and rules engine decision details |

**Postconditions:**
- Application remains in declined status
- Declination notification is recorded in notification history
- Audit log contains complete declination record
- Manager dashboard reflects the declined application
- System is ready for next application processing

---

## Story: As Underwriting Manager, I want to review and override automatic declinations to achieve flexibility in underwriting decisions
**Story ID:** story-26

### Test Case: Verify declination override process
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User has valid underwriting manager credentials with override permissions
- At least one application exists in declined status
- Override functionality is enabled in the system
- Audit logging service is operational
- Notification service is configured for stakeholder alerts
- Manager is logged into the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the declined applications dashboard as underwriting manager | Dashboard displays list of all declined applications with relevant details (application ID, applicant name, declination date, reasons) |
| 2 | Select a declined application from the list to review for potential override | Application details page opens showing complete declination information, applicant data, and declination reasons |
| 3 | Click on the 'Override Declination' button or option | Override UI is displayed with a mandatory reason input field, confirmation message, and submit/cancel buttons |
| 4 | Enter a valid override reason in the text field (e.g., 'Applicant provided additional income documentation showing sufficient capacity') | Override reason text is accepted and displayed in the input field with character count if applicable |
| 5 | Click the 'Submit Override' button to confirm the override action | System processes the override request via POST /api/declinations/override endpoint within 2 seconds |
| 6 | Verify the application status has been updated in the system | Application status changes from 'Declined' to 'Under Review' or 'Override Approved' immediately, and success confirmation message is displayed |
| 7 | Check the audit log for the override action | Audit log contains new entry with override timestamp, manager username, manager ID, original declination reason, override reason, and application ID |
| 8 | Verify notifications are sent to relevant stakeholders (underwriting team, loan officers, applicant contact if configured) | Notifications are successfully sent to all configured stakeholders containing application ID, override action, and manager name |
| 9 | Check stakeholder notification inboxes/emails to confirm receipt | All relevant stakeholders receive notifications with accurate override information and application details |
| 10 | Return to declined applications dashboard and verify the overridden application is no longer listed | Overridden application is removed from declined applications list or marked with 'Overridden' status indicator |

**Postconditions:**
- Application status is updated to reflect override
- Complete audit trail exists for the override action
- All stakeholders have been notified of the override
- Application is available for continued underwriting processing
- Override reason is permanently stored and accessible
- Manager remains logged in and can perform additional actions

---

## Story: As Underwriting Manager, I want to generate reports on referrals, questions, and declinations to achieve data-driven decision making
**Story ID:** story-30

### Test Case: Validate report generation with filters
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Underwriting Manager role
- Reporting module is accessible and functional
- Test data exists in the system: at least 20 referrals, 15 questions, and 10 declinations with varying dates and statuses
- User has permissions to access GET /api/reports/underwriting endpoint
- Browser is compatible and up-to-date

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the reporting module from the main dashboard | Reporting module page loads successfully with available report types displayed |
| 2 | Select 'Referrals' as the report type from the dropdown menu | Referrals report type is selected and filter options become available |
| 3 | Apply date range filter: Set start date to 30 days ago and end date to today | Date range filter is applied and displayed in the filter summary section |
| 4 | Apply status filter: Select 'Pending' status from the status dropdown | Status filter is applied and displayed in the filter summary section |
| 5 | Apply user filter: Select a specific underwriter from the user dropdown | User filter is applied and displayed in the filter summary section |
| 6 | Click 'Generate Report' button | Report generation starts, loading indicator appears, and report completes within 10 seconds |
| 7 | Review the generated report data in the display area | Report displays only referrals matching all applied filters: date range (last 30 days), status (Pending), and selected user. Data includes referral ID, date, status, assigned user, and relevant details |
| 8 | Verify report accuracy by cross-checking sample records against the database | All displayed records match the filter criteria with 100% accuracy |
| 9 | Change report type to 'Questions' and apply date range filter only | Questions report is generated showing all questions within the specified date range |
| 10 | Change report type to 'Declinations' and apply status filter only | Declinations report is generated showing all declinations with the selected status |

**Postconditions:**
- Report data is displayed on screen and matches all applied filter criteria
- System logs the report generation activity
- User remains on the reporting module page
- Filters remain applied for subsequent operations

---

### Test Case: Export report to PDF and Excel
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in with Underwriting Manager role
- A report has been successfully generated with applied filters
- Report data is displayed on screen
- User has download permissions enabled in browser
- Sufficient disk space available for file downloads

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Locate the 'Export' button or dropdown on the report display page | Export options are visible with PDF and Excel format choices available |
| 2 | Click 'Export to PDF' option | PDF file download initiates immediately, download progress indicator appears |
| 3 | Wait for PDF download to complete and locate the downloaded file | PDF file downloads successfully to the default download folder with naming convention: ReportType_DateRange_Timestamp.pdf |
| 4 | Open the downloaded PDF file using a PDF reader | PDF file opens without errors, displays report title, filter criteria, generation date/time, and all report data in formatted tables with proper headers and pagination |
| 5 | Verify PDF content matches the on-screen report data | All data in PDF exactly matches the displayed report including row counts, values, and formatting |
| 6 | Return to the report display page and click 'Export to Excel' option | Excel file download initiates immediately, download progress indicator appears |
| 7 | Wait for Excel download to complete and locate the downloaded file | Excel file downloads successfully to the default download folder with naming convention: ReportType_DateRange_Timestamp.xlsx |
| 8 | Open the downloaded Excel file using Microsoft Excel or compatible spreadsheet application | Excel file opens without errors or corruption warnings, displays report data in structured spreadsheet format |
| 9 | Verify Excel content structure: Check headers, data rows, and formatting | Excel file contains: Sheet name matching report type, header row with column names, all data rows matching the report, proper date formatting, and filter criteria in a summary section |
| 10 | Verify Excel data accuracy by comparing row count and sample values with on-screen report | All data in Excel exactly matches the displayed report with correct values and no missing records |
| 11 | Test Excel functionality by sorting a column and applying a filter | Excel file is fully functional, allows sorting, filtering, and data manipulation without errors |

**Postconditions:**
- Two files are downloaded: one PDF and one Excel file
- Both files contain accurate report data matching the generated report
- Files are accessible and functional without errors
- Download activity is logged in the system
- User remains on the reporting module page

---

### Test Case: Schedule recurring report
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in with Underwriting Manager role
- A report has been successfully generated with desired filters applied
- Email delivery system is configured and operational
- User has a valid email address in the system
- Scheduling service is running and accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Locate and click the 'Schedule Report' button on the report display page | Schedule Report dialog or form opens displaying scheduling options |
| 2 | Enter a descriptive name for the scheduled report: 'Weekly Pending Referrals Report' | Report name is entered and displayed in the name field |
| 3 | Select recurrence frequency: Choose 'Weekly' from the frequency dropdown | Weekly frequency is selected and additional weekly options appear (day of week selection) |
| 4 | Select day of week: Choose 'Monday' for report generation | Monday is selected as the scheduled day |
| 5 | Select time for report generation: Set time to 8:00 AM | Time is set to 8:00 AM and displayed in the schedule summary |
| 6 | Select report format for delivery: Check both 'PDF' and 'Excel' checkboxes | Both PDF and Excel formats are selected for automated delivery |
| 7 | Enter delivery email address: Verify or enter manager's email address | Email address is populated and validated (format check shows valid) |
| 8 | Add additional recipients: Enter two additional email addresses separated by commas | Additional email addresses are accepted and displayed in the recipients list |
| 9 | Review the schedule summary displaying all configured settings | Summary shows: Report name, type, filters, frequency (Weekly - Monday 8:00 AM), formats (PDF, Excel), and recipient list |
| 10 | Click 'Save Schedule' or 'Confirm' button | Schedule is saved successfully, confirmation message appears: 'Scheduled report created successfully. Next run: [Date and Time]' |
| 11 | Navigate to 'Scheduled Reports' section or list | Scheduled Reports page displays with the newly created schedule visible in the list |
| 12 | Verify the scheduled report entry shows correct details: name, frequency, next run date, status (Active) | All schedule details are correctly displayed and status shows 'Active' |
| 13 | Wait for the scheduled time or trigger a test run if available | At scheduled time, report generation is triggered automatically |
| 14 | Check email inbox of all recipients at or shortly after the scheduled time | Email is received by all recipients within 5 minutes of scheduled time containing: Subject line with report name and date, email body with summary, and both PDF and Excel attachments |
| 15 | Open both attachments from the email | Both PDF and Excel files open successfully, contain report data matching the configured filters, and show the correct generation date |
| 16 | Verify the scheduled report status is updated in the system | Scheduled report entry shows 'Last Run' timestamp updated to the execution time and 'Next Run' updated to the following scheduled occurrence |

**Postconditions:**
- Scheduled report is created and active in the system
- Schedule is stored in the database with all configuration details
- Report is generated and delivered automatically at the scheduled time
- Email with report attachments is successfully delivered to all recipients
- System logs the schedule creation and execution activities
- Next scheduled run is calculated and displayed

---

