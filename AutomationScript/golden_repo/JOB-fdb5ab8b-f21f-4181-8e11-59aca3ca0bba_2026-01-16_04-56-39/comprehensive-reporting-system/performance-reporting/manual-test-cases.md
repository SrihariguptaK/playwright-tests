# Manual Test Cases

## Story: As Team Lead, I want to generate performance reports to evaluate team productivity
**Story ID:** story-4

### Test Case: Validate performance report generation with KPI filters
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Team Lead role credentials
- Performance management system has data available for the selected time period
- User has necessary permissions to access performance reporting module
- At least one team and employee exist in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to performance reporting module from the main dashboard | Performance report UI is displayed with options for KPI selection, filters, and time period selection |
| 2 | Select desired KPIs from the available KPI dropdown list | Selected KPIs are highlighted and added to the report configuration |
| 3 | Select team from the team filter dropdown | Team filter is applied and displayed in the filter summary section |
| 4 | Select time period (start date and end date) using the date picker | Time period is set and displayed correctly in the filter summary, filters accepted without errors |
| 5 | Click on 'Generate Report' button to request report generation | System processes the request and displays a loading indicator |
| 6 | Wait for report generation to complete | Performance report is generated and displayed with selected KPIs, charts, and metrics matching the applied filters |
| 7 | Verify that the report contains accurate data for the selected team and time period | Report displays correct KPI values, team information, and time period data with visual charts |

**Postconditions:**
- Performance report is displayed on screen
- Report data matches the selected filters and KPIs
- System logs the report generation activity
- User remains on the performance reporting page

---

### Test Case: Verify export functionality for performance reports
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in with Team Lead role credentials
- Performance reporting module is accessible
- A performance report has been generated with filters applied
- Browser allows file downloads
- User has write permissions to the download directory

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to performance reporting module and select KPIs, team, and time period filters | Filters are applied successfully |
| 2 | Click 'Generate Report' button to generate performance report with filters | Performance report is displayed on screen with charts and data matching the selected filters |
| 3 | Verify that the report contains visual charts and performance metrics | Report shows complete data with charts, KPIs, and metrics |
| 4 | Click on 'Export to PDF' button | System initiates PDF export process and displays download progress |
| 5 | Wait for PDF download to complete and open the downloaded PDF file | PDF file is downloaded successfully with charts and data matching the on-screen report, including all visual elements |
| 6 | Return to the performance report screen and click on 'Export to Excel' button | System initiates Excel export process and displays download progress |
| 7 | Wait for Excel download to complete and open the downloaded Excel file | Excel file is downloaded with accurate data, all KPIs, metrics, and data points matching the report |
| 8 | Verify data accuracy in both exported files against the on-screen report | Both PDF and Excel exports contain identical data to the on-screen report with 100% accuracy |

**Postconditions:**
- PDF file is saved in the downloads folder with embedded charts
- Excel file is saved in the downloads folder with accurate data
- Both exported files contain complete report data
- User remains on the performance reporting page
- Export activity is logged in the system

---

### Test Case: Ensure unauthorized users cannot access performance reports
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- System has role-based access control configured
- A non-team lead user account exists in the system
- Performance reporting module is active
- API endpoint /api/reports/performance is protected with authentication

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Login to the system using non-team lead user credentials (e.g., regular employee role) | User is successfully logged in and redirected to the appropriate dashboard for their role |
| 2 | Attempt to navigate to the performance reporting module from the main menu or dashboard | Performance reporting module option is not visible in the navigation menu or is disabled |
| 3 | Attempt to access the performance reporting module by directly entering the URL in the browser | Access to performance reporting module is denied with an appropriate error message (e.g., 'Access Denied' or '403 Forbidden') |
| 4 | Open browser developer tools and attempt to access the API endpoint GET /api/reports/performance directly | API returns 403 Forbidden response with error message indicating insufficient permissions |
| 5 | Verify that no performance data is returned in the API response | No sensitive performance data is exposed, only an access forbidden response is received |
| 6 | Logout and login with Team Lead credentials, then access the performance reporting module | Performance reporting module is accessible and displays correctly for authorized Team Lead user |

**Postconditions:**
- Unauthorized access attempt is logged in the security audit log
- No performance data was exposed to unauthorized user
- System security remains intact
- User session remains active but without access to restricted module

---

## Story: As Team Lead, I want performance reports to include visual charts for easier data interpretation
**Story ID:** story-8

### Test Case: Validate visual chart rendering in performance reports
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- User is logged in with Team Lead role credentials
- Performance reporting module is accessible
- Performance data is available in the system for the selected period
- Chart rendering library is loaded and functional
- Multiple chart types (bar, line, pie) are available for selection

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the performance reporting module from the dashboard | Performance reporting interface is displayed with options for KPI selection and chart type customization |
| 2 | Select desired KPIs from the KPI dropdown menu (e.g., productivity rate, task completion rate) | Selected KPIs are highlighted and added to the report configuration panel |
| 3 | Select chart types for each KPI (e.g., bar chart for productivity, line chart for trends) | Chart types are assigned to corresponding KPIs and displayed in the configuration summary |
| 4 | Select team and time period filters for the report | Filters are applied and displayed in the filter summary section |
| 5 | Click 'Generate Report' button to generate performance report with selected KPIs and chart types | System processes the request and displays loading indicator |
| 6 | Wait for report generation and chart rendering to complete (should be within 10 seconds) | Report displays with accurate visual charts representing the selected KPIs, charts render within 10 seconds |
| 7 | Verify that each chart accurately represents the corresponding KPI data | Charts display correct data points, labels, legends, and values matching the KPI metrics |
| 8 | Change chart types for one or more KPIs using the customization options | Chart type selection is updated in the interface |
| 9 | Click 'Regenerate Report' or 'Update Charts' button to customize chart types and regenerate report | System processes the customization request |
| 10 | Wait for charts to update with new chart types | Charts update according to customization, displaying the same data in the newly selected chart format within 10 seconds |
| 11 | Verify data consistency between original and updated charts | Data values remain consistent across different chart type representations |

**Postconditions:**
- Performance report is displayed with customized visual charts
- Charts accurately represent KPI data
- Chart rendering completed within performance SLA (10 seconds)
- Report remains available for export
- Chart customization settings are saved for the current session

---

### Test Case: Verify export of performance reports with embedded charts
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in with Team Lead role credentials
- Performance report with visual charts has been generated
- Charts are fully rendered on screen
- Browser allows file downloads
- User has write permissions to the download directory
- PDF and Excel export functionality is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to performance reporting module and select KPIs and chart types | Report configuration interface is displayed with selected options |
| 2 | Click 'Generate Report' button to generate performance report with charts | System generates and displays the performance report with visual charts (bar, line, or pie charts as selected) |
| 3 | Verify that all charts are fully rendered and visible on screen | Report is displayed with all charts rendered correctly, showing KPI data visually |
| 4 | Note the chart types, data points, and visual elements displayed in the on-screen report | All chart details are clearly visible and documented for comparison |
| 5 | Click on 'Export to PDF' button | System initiates PDF export process with embedded charts and displays download progress |
| 6 | Wait for PDF download to complete and open the downloaded PDF file | PDF file downloads successfully and opens without errors |
| 7 | Verify that the PDF includes all embedded charts with correct visual representation | PDF includes embedded charts matching the on-screen report, all visual elements (colors, labels, data points) are preserved |
| 8 | Return to the performance report screen and click on 'Export to Excel' button | System initiates Excel export process with embedded charts and displays download progress |
| 9 | Wait for Excel download to complete and open the downloaded Excel file | Excel file downloads successfully and opens without errors |
| 10 | Verify that the Excel file includes embedded charts as chart objects | Excel file includes embedded charts as visual objects, charts are interactive and maintain data accuracy |
| 11 | Compare charts in both exported files against the on-screen report | Charts in PDF and Excel exports match the on-screen report in terms of data accuracy, visual representation, and formatting |

**Postconditions:**
- PDF file is saved with embedded visual charts
- Excel file is saved with embedded chart objects
- Both exported files contain accurate chart representations
- Chart data integrity is maintained across all formats
- Export activity is logged in the system
- User remains on the performance reporting page

---

