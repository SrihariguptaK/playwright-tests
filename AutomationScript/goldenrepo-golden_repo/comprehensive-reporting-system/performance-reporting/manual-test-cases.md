# Manual Test Cases

## Story: As Team Lead, I want to generate performance reports to evaluate team productivity against KPIs
**Story ID:** story-4

### Test Case: Generate performance report with selected KPIs
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as Team Lead with valid credentials
- User has authorization to access performance reporting module
- Performance data exists in the system for the selected time period
- At least one KPI is configured in the system
- Task and attendance databases are accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to performance reporting module from the main dashboard | Performance report UI is displayed with options to select KPIs, time periods, and generate report button visible |
| 2 | Select one or more KPIs from the available KPI dropdown list | Selected KPIs are highlighted and displayed in the selection area |
| 3 | Select time period by choosing start date and end date from date picker | Selected time period is displayed and accepted by the system with no validation errors |
| 4 | Click on 'Generate Report' button | System processes the request and displays loading indicator |
| 5 | Wait for report generation to complete | Performance report is displayed within 5 seconds showing selected KPIs, trend analysis with visual graphs, and benchmark analysis comparing against historical data |
| 6 | Review the generated report for accuracy of KPI metrics | Report displays accurate performance metrics, trend lines showing performance over time, and benchmark comparisons with clear visualizations |

**Postconditions:**
- Performance report is successfully generated and displayed
- Report data matches the selected KPIs and time period
- System logs the report generation activity
- Report is available for export or scheduling

---

### Test Case: Export performance report to PDF and Excel
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in as Team Lead with valid credentials
- User has authorization to access performance reporting module
- Performance report has been successfully generated and is displayed on screen
- Browser has permission to download files
- Sufficient storage space available on local machine

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Generate performance report by selecting KPIs and time period, then clicking 'Generate Report' | Performance report is displayed with all KPI metrics, trends, and benchmark analysis visible |
| 2 | Locate and click on 'Export to PDF' button in the report toolbar | System initiates PDF generation and download process with progress indicator shown |
| 3 | Wait for PDF download to complete and open the downloaded PDF file | PDF file is downloaded successfully with filename format 'Performance_Report_[Date].pdf', file opens correctly showing all report data including KPIs, charts, trends, and benchmarks with proper formatting |
| 4 | Return to the performance report screen and click on 'Export to Excel' button | System initiates Excel file generation and download process with progress indicator shown |
| 5 | Wait for Excel download to complete and open the downloaded Excel file | Excel file is downloaded successfully with filename format 'Performance_Report_[Date].xlsx', file opens correctly in Excel or compatible application showing all report data in structured format with separate sheets for different data sections if applicable |
| 6 | Verify data accuracy in both exported files against the on-screen report | Both PDF and Excel exports contain identical data to the on-screen report with all KPIs, metrics, trends, and benchmarks accurately represented |

**Postconditions:**
- PDF file is successfully downloaded and contains complete report data
- Excel file is successfully downloaded and contains complete report data
- Both files are accessible and readable
- Export activity is logged in the system
- Original report remains displayed on screen

---

### Test Case: Schedule automated performance report delivery
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in as Team Lead with valid credentials
- User has authorization to schedule automated reports
- Performance reporting module is accessible
- Email service is configured and operational
- At least one valid recipient email address is available
- KPIs are configured in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to performance reporting module and locate 'Schedule Report' or 'Automated Delivery' option | Scheduling options button or link is visible and clickable |
| 2 | Click on 'Schedule Report' or 'Automated Delivery' button | Scheduling UI is displayed showing fields for report configuration, frequency selection, time selection, recipient list, and format options |
| 3 | Select KPIs to include in the scheduled report from the available KPI list | Selected KPIs are highlighted and added to the schedule configuration |
| 4 | Select report frequency (Daily, Weekly, Monthly) from the frequency dropdown | Selected frequency is displayed and additional relevant options appear (e.g., day of week for weekly, date for monthly) |
| 5 | Set the delivery time using time picker | Selected time is displayed in the schedule configuration |
| 6 | Enter recipient email addresses in the recipients field, separating multiple addresses with commas or semicolons | Email addresses are validated and displayed as tags or list items, invalid emails show error messages |
| 7 | Select report format (PDF, Excel, or both) from format options | Selected format(s) are highlighted and included in the schedule configuration |
| 8 | Click 'Save Schedule' or 'Activate Schedule' button | System validates all inputs, displays success message 'Schedule saved successfully', and shows the schedule in the list of active schedules with all configuration details |
| 9 | Wait for the scheduled time to arrive or trigger a test delivery if available | System sends report emails at the scheduled time |
| 10 | Check recipient email inbox(es) for the scheduled report | Email is received with subject line containing 'Performance Report', email body contains report summary or link, and correct report file(s) in selected format(s) are attached with accurate data |
| 11 | Open the attached report file(s) from the email | Report attachments open correctly showing complete performance data with selected KPIs, trends, and benchmarks for the configured time period |

**Postconditions:**
- Automated report schedule is saved and active in the system
- Schedule appears in the list of active schedules
- Recipients receive scheduled reports at configured times
- Schedule can be edited or deleted by authorized users
- System logs all scheduled report deliveries

---

## Story: As Team Lead, I want to benchmark team performance against historical data to identify improvement opportunities
**Story ID:** story-8

### Test Case: Generate benchmarking report comparing current and historical KPIs
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in as Team Lead with valid credentials
- User has authorization to access benchmarking features
- Historical performance data exists in the database for comparison
- Current performance data is available in the system
- At least one KPI is configured for benchmarking
- Performance and historical databases are accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to performance reporting module from the main dashboard | Performance report UI is displayed with standard reporting options and benchmarking option visible |
| 2 | Locate and click on 'Benchmarking' option or tab within the performance reporting interface | Benchmarking interface is displayed showing options to select KPIs, current time period, and historical comparison period |
| 3 | Select one or more KPIs from the available KPI dropdown list for benchmarking analysis | Selected KPIs are highlighted and displayed in the selection area with checkmarks or tags |
| 4 | Select current time period by choosing start date and end date for current performance data | Current time period is displayed and accepted with no validation errors |
| 5 | Select historical comparison period by choosing the historical time range or selecting predefined periods (e.g., same period last year, previous quarter) | Historical period is displayed and accepted, system validates that historical data exists for the selected period |
| 6 | Click on 'Generate Benchmarking Report' button | System processes the request, displays loading indicator, and begins retrieving current and historical KPI data |
| 7 | Wait for benchmarking report generation to complete | Benchmarking report is displayed within 5 seconds showing side-by-side comparison of current vs historical KPIs |
| 8 | Review the comparative data section of the report | Report displays accurate comparative data with current KPI values, historical KPI values, variance percentages, and performance indicators (improvement/decline) clearly marked |
| 9 | Review the visualizations section of the report | Report displays clear visualizations including trend lines showing performance over time, bar charts comparing current vs historical performance, performance gap indicators, and color-coded visual cues for improvements (green) and declines (red) |
| 10 | Verify data completeness and accuracy by cross-referencing key metrics | All selected KPIs are present in the report with accurate calculations, percentages, and trend directions matching the underlying data |

**Postconditions:**
- Benchmarking report is successfully generated and displayed
- Report contains accurate comparative analysis of current vs historical data
- Visualizations clearly show trends and performance gaps
- System logs the benchmarking report generation activity
- Report is available for export or scheduling

---

### Test Case: Export benchmarking report
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as Team Lead with valid credentials
- User has authorization to export benchmarking reports
- Benchmarking report has been successfully generated and is displayed on screen
- Browser has permission to download files
- Sufficient storage space available on local machine

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Generate benchmarking report by selecting benchmarking option, KPIs, current and historical periods, then clicking 'Generate Benchmarking Report' | Benchmarking report is displayed showing comparative data, visualizations, trends, and performance gaps |
| 2 | Locate the export options in the report toolbar and click on 'Export to PDF' button | System initiates PDF generation process with progress indicator or loading message displayed |
| 3 | Wait for PDF generation and download to complete | PDF file is downloaded successfully with filename format 'Benchmarking_Report_[Date].pdf', browser shows download completion notification |
| 4 | Open the downloaded PDF file using PDF reader application | PDF file opens correctly displaying complete benchmarking report with all comparative data, KPI comparisons, trend visualizations, performance gap charts, and proper formatting maintained including headers, footers, and page breaks |
| 5 | Verify that all visual elements are rendered correctly in the PDF | All charts, graphs, trend lines, and visual indicators are clearly visible and properly formatted in the PDF with legends and labels intact |
| 6 | Return to the benchmarking report screen in the application and click on 'Export to Excel' button | System initiates Excel file generation process with progress indicator or loading message displayed |
| 7 | Wait for Excel generation and download to complete | Excel file is downloaded successfully with filename format 'Benchmarking_Report_[Date].xlsx', browser shows download completion notification |
| 8 | Open the downloaded Excel file using Excel or compatible spreadsheet application | Excel file opens correctly displaying benchmarking report data in structured format with separate sheets or sections for summary data, detailed comparisons, and raw data if applicable |
| 9 | Verify data structure and accuracy in the Excel file | Excel file contains all comparative data in tabular format with columns for current KPIs, historical KPIs, variance, percentage change, and trend indicators; charts and graphs are embedded or data is formatted for easy chart creation |
| 10 | Compare data in both exported files against the on-screen benchmarking report | Both PDF and Excel exports contain identical data to the on-screen report with all KPIs, comparative metrics, trends, and performance gaps accurately represented without data loss |

**Postconditions:**
- PDF file is successfully downloaded and contains complete benchmarking report
- Excel file is successfully downloaded and contains complete benchmarking data
- Both files are accessible, readable, and properly formatted
- Export activity is logged in the system
- Original benchmarking report remains displayed on screen
- Files can be shared with stakeholders for review

---

### Test Case: Schedule automated benchmarking report delivery
- **ID:** tc-006
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- User is logged in as Team Lead with valid credentials
- User has authorization to schedule automated benchmarking reports
- Performance reporting module with benchmarking features is accessible
- Email service is configured and operational
- At least one valid recipient email address is available
- Historical data exists in the system for benchmarking
- KPIs are configured for benchmarking

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to performance reporting module and access the benchmarking section | Benchmarking interface is displayed with options for report generation and scheduling |
| 2 | Locate and click on 'Schedule Benchmarking Report' or 'Automated Delivery' button | Scheduling UI is displayed showing fields for benchmarking configuration, KPI selection, comparison period settings, frequency selection, time selection, recipient list, and format options |
| 3 | Select KPIs to include in the scheduled benchmarking report from the available KPI list | Selected KPIs are highlighted and added to the schedule configuration with checkmarks or tags |
| 4 | Configure comparison settings by selecting how historical data should be compared (e.g., same period previous year, rolling comparison, quarter-over-quarter) | Comparison settings are displayed and saved in the schedule configuration |
| 5 | Select report frequency (Daily, Weekly, Monthly, Quarterly) from the frequency dropdown | Selected frequency is displayed and additional relevant options appear based on frequency choice |
| 6 | Set the delivery time using time picker or time input field | Selected time is displayed in the schedule configuration in proper format (e.g., 09:00 AM) |
| 7 | Enter recipient email addresses in the recipients field, adding multiple addresses separated by commas or using add button for each recipient | Email addresses are validated in real-time, valid emails are displayed as tags or list items, invalid emails trigger error messages with specific validation feedback |
| 8 | Select report format (PDF, Excel, or both) from format options checkboxes or radio buttons | Selected format(s) are highlighted or checked and included in the schedule configuration summary |
| 9 | Review the schedule summary showing all configured settings | Schedule summary displays all settings including KPIs, comparison method, frequency, time, recipients, and format in a clear, readable format |
| 10 | Click 'Save Schedule' or 'Activate Schedule' button to finalize the automated delivery setup | System validates all inputs, displays success message 'Benchmarking report schedule saved successfully', and shows the schedule in the list of active schedules with status 'Active' and next delivery date/time displayed |
| 11 | Navigate to the scheduled reports list or dashboard to verify the new schedule appears | New benchmarking report schedule is listed with all configuration details visible including schedule name, frequency, next run time, and recipients count |
| 12 | Wait for the scheduled time to arrive or use 'Send Test Report' function if available | System triggers report generation and email delivery at the scheduled time or immediately for test |
| 13 | Check recipient email inbox(es) for the scheduled benchmarking report | Email is received with subject line containing 'Benchmarking Report' or similar identifier, email includes report generation date and time period covered |
| 14 | Review the email body content | Email body contains executive summary of key benchmarking insights, highlights of significant performance changes, and clear indication of attached report file(s) |
| 15 | Verify that correct report file(s) are attached to the email in the selected format(s) | Report attachments are present in the specified format(s) (PDF and/or Excel) with appropriate file names and file sizes indicating complete reports |
| 16 | Open and review the attached benchmarking report file(s) | Report attachments open correctly showing complete benchmarking data with selected KPIs, current vs historical comparisons, trend visualizations, performance gap analysis, and accurate data for the configured time periods |

**Postconditions:**
- Automated benchmarking report schedule is saved and active in the system
- Schedule appears in the list of active schedules with correct configuration
- Recipients receive scheduled benchmarking reports at configured times with correct attachments
- Schedule can be viewed, edited, paused, or deleted by authorized users
- System logs all scheduled benchmarking report deliveries with timestamps and recipient information
- Email delivery status is tracked and available for review

---

## Story: As Team Lead, I want to schedule automated performance report delivery to keep stakeholders informed
**Story ID:** story-12

### Test Case: Create and save performance report schedule
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as Team Lead with scheduling permissions
- Performance report data is available in the system
- At least one valid recipient email address is available
- User has access to performance report scheduling feature

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the performance reports section from the main dashboard | Performance reports page is displayed with available options |
| 2 | Click on 'Schedule Report' or 'Automated Delivery' button | Scheduling interface is displayed with configuration options including schedule frequency, time, recipients, and report parameters |
| 3 | Select report type as 'Performance Report' from the dropdown menu | Performance Report is selected and relevant configuration fields are enabled |
| 4 | Define schedule frequency (e.g., Daily, Weekly, Monthly) and select specific time (e.g., 9:00 AM) | Schedule frequency and time are accepted and displayed in the configuration form |
| 5 | Enter or select recipient email addresses in the recipients field (e.g., stakeholder1@company.com, stakeholder2@company.com) | Recipient email addresses are validated and added to the recipients list |
| 6 | Configure additional report parameters such as date range, metrics to include, and report format (PDF/Excel) | All parameters are accepted and displayed correctly in the form |
| 7 | Click 'Save Schedule' or 'Create Schedule' button | System validates all inputs and displays a success message 'Schedule saved successfully' with schedule ID |
| 8 | Verify the newly created schedule appears in the list of scheduled reports | Schedule is listed with correct details including frequency, next execution time, and recipients count |

**Postconditions:**
- Performance report schedule is saved in the system
- Schedule is active and ready for automated execution
- Schedule appears in the scheduled reports list
- Audit log entry is created for schedule creation

---

### Test Case: Verify automated performance report delivery
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- A performance report schedule has been created and saved
- Schedule is configured with valid recipients
- Schedule execution time is set to a near-future time for testing
- Email server is configured and operational
- Test recipient email accounts are accessible for verification

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Note the scheduled report generation time from the scheduled reports list | Next execution time is clearly displayed (e.g., 'Next run: 2024-01-15 09:00 AM') |
| 2 | Wait for the scheduled report generation time to arrive and pass (allow 2-3 minutes buffer for processing) | System time reaches and passes the scheduled execution time |
| 3 | Navigate to the scheduled reports execution logs or history section | Execution log shows the recent report generation with status 'Success' or 'Completed' and timestamp |
| 4 | Access the recipient email inbox (stakeholder1@company.com) | Email inbox is accessible and displays received emails |
| 5 | Locate the performance report email by subject line and sender | Performance report email is received with correct subject line (e.g., 'Scheduled Performance Report - [Date]') from the system sender |
| 6 | Open the performance report email and verify email body content | Email contains professional formatting, introduction text, and report summary or attachment reference |
| 7 | Download and open the attached performance report file | Report file opens successfully in the specified format (PDF/Excel) without errors |
| 8 | Review report content including metrics, data values, charts, and date range | Report data is accurate, complete, matches the configured parameters, and includes all expected performance metrics |
| 9 | Verify all configured recipients received the report by checking additional recipient inboxes | All recipients (stakeholder2@company.com, etc.) have received identical performance report emails |
| 10 | Return to the system and verify the execution log shows successful delivery to all recipients | Execution log displays 'Delivered to X recipients' with success status and no error messages |

**Postconditions:**
- Performance report is successfully generated and delivered
- All configured recipients received the report email
- Execution is logged with success status
- Next scheduled execution time is updated in the system
- Report data remains accurate and accessible

---

