# Manual Test Cases

## Story: As Scheduler, I want to view and manage scheduling conflicts through an intuitive interface to resolve issues efficiently
**Story ID:** story-13

### Test Case: Verify conflict list display and filtering
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User has Scheduler role with appropriate permissions
- User is logged into the scheduling system
- At least 10 active conflicts exist in the system with varying dates, resources, and severity levels
- Conflict database is accessible and populated with test data

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the conflict management interface from the main dashboard | Conflict management interface loads within 3 seconds and displays a list of all active conflicts with columns for date, resource, severity, and status |
| 2 | Verify the initial conflict list contains all active conflicts | All active conflicts are displayed in the list with complete information visible for each conflict entry |
| 3 | Apply date filter by selecting a specific date range (e.g., last 7 days) | Conflict list updates dynamically to show only conflicts within the selected date range |
| 4 | Apply resource filter by selecting a specific resource from the dropdown | Conflict list further filters to show only conflicts associated with the selected resource while maintaining the date filter |
| 5 | Click on the severity column header to sort conflicts by severity | Conflict list is sorted in descending order by severity (High to Low) with visual indication of sort direction |
| 6 | Click on the severity column header again to reverse sort order | Conflict list is sorted in ascending order by severity (Low to High) with updated sort direction indicator |
| 7 | Clear all applied filters | Conflict list returns to displaying all active conflicts in the original default order |

**Postconditions:**
- User remains on the conflict management interface
- All filters are cleared and ready for next use
- No data has been modified in the system

---

### Test Case: Test editing and resolving conflicts
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User has Scheduler role with edit permissions
- User is logged into the scheduling system
- User is on the conflict management interface
- At least one active conflict exists that can be resolved through schedule editing
- Conflict details include editable schedule information

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Select a specific conflict from the active conflicts list by clicking on it | Conflict details panel opens displaying complete information including conflicting resources, time slots, affected schedules, and severity level |
| 2 | Review the conflict details to understand the scheduling issue | All relevant conflict information is clearly displayed including the nature of the conflict and affected parties |
| 3 | Click the 'Edit Schedule' button within the conflict details panel | Schedule editing interface opens with the conflicting schedule loaded and editable fields enabled |
| 4 | Modify the schedule by changing the time slot or resource to resolve the conflict | Changes are accepted in the editing interface with validation confirming the new schedule does not create additional conflicts |
| 5 | Click the 'Save Changes' button to commit the schedule modification | System displays a success message confirming changes are saved, and the conflict status updates to 'Resolved' |
| 6 | Return to the active conflicts list view | The resolved conflict is no longer present in the active conflicts list |
| 7 | Navigate to the resolved conflicts section or history | The recently resolved conflict appears in the resolved list with timestamp, resolution method, and user who resolved it |

**Postconditions:**
- Conflict is marked as resolved in the database
- Schedule changes are persisted in the scheduling system
- Conflict is removed from active conflicts list
- Resolution is logged in the audit trail with user details and timestamp

---

### Test Case: Ensure real-time conflict status updates
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- User has Scheduler role with appropriate permissions
- User is logged into the scheduling system on one browser session
- A second user session is available (different browser or incognito mode)
- At least one active conflict exists in the system
- Real-time update mechanism is enabled and functioning
- Both sessions are viewing the conflict management interface

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | In the first session, note the current list of active conflicts and their count | Active conflicts list is displayed with a specific number of conflicts visible |
| 2 | In the second session, select and resolve one of the active conflicts by editing the schedule and saving changes | In the second session, the conflict is successfully resolved and removed from the active list |
| 3 | In the first session, observe the conflict list without manually refreshing the page | The conflict list automatically updates in real-time, showing the resolved conflict status change or removal from the active list within 3 seconds |
| 4 | Manually refresh the conflict list in the first session by clicking the refresh button | The refreshed list confirms the resolved conflict no longer appears in the active conflicts, and the conflict count is reduced by one |
| 5 | Click on the 'Resolution History' or 'Audit Trail' link from the conflict management interface | Resolution history page opens displaying a chronological list of resolved conflicts |
| 6 | Locate the recently resolved conflict in the resolution history | The conflict appears in the history with accurate details including resolution timestamp, user who resolved it, original conflict details, and resolution method applied |
| 7 | Verify the audit trail entry for completeness | Audit trail shows complete information including before and after states, all changes made, and full user attribution |

**Postconditions:**
- Real-time update functionality is confirmed working
- Resolution history accurately reflects all resolved conflicts
- Audit trail contains complete records of conflict resolution activities
- Both user sessions show consistent data

---

## Story: As Scheduler, I want the system to provide detailed conflict reports to analyze scheduling issues and improve planning
**Story ID:** story-17

### Test Case: Validate generation of conflict reports with filters
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User has Scheduler role with reporting permissions
- User is logged into the scheduling system
- Conflict reporting module is accessible
- Historical conflict data exists spanning multiple date ranges, resources, and severity levels
- Database contains at least 50 conflict records for meaningful reporting

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the conflict reporting module from the main menu or dashboard | Conflict reporting UI loads successfully displaying report generation options, filter controls, and parameter selection fields |
| 2 | Verify all filter options are available and functional | Filter controls for date range, resource, and severity are visible and interactive with appropriate input fields and dropdowns |
| 3 | Select a date range filter by choosing start date and end date (e.g., last 30 days) | Date range is accepted and displayed in the filter summary section |
| 4 | Select a specific resource from the resource filter dropdown | Selected resource is applied to the filter criteria and shown in the active filters display |
| 5 | Select a severity level filter (e.g., High severity conflicts only) | Severity filter is applied and visible in the filter summary |
| 6 | Click the 'Generate Report' button to create the conflict report | Report generation begins with a loading indicator, and the report is generated and displayed within 5 seconds |
| 7 | Review the generated report content for accuracy | Report displays conflict data matching the applied filters including conflict frequency, types, resolution times, and summary statistics with correct data values |
| 8 | Verify report includes visual elements such as charts or graphs | Report contains appropriate visualizations (charts, graphs, tables) that accurately represent the conflict data |

**Postconditions:**
- Report is successfully generated and displayed
- Filter selections remain active for potential report regeneration
- No data has been modified in the system
- Report generation is logged in system audit trail

---

### Test Case: Verify report export functionality
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User has Scheduler role with reporting and export permissions
- User is logged into the scheduling system
- User is on the conflict reporting module
- A conflict report has been generated and is currently displayed
- User's browser allows file downloads
- System has PDF and Excel export capabilities enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Generate a conflict report with specific filters applied (date range, resource, severity) | Conflict report is displayed on screen with complete data including charts, tables, and summary statistics |
| 2 | Verify the report content is complete and accurate before export | Report shows all expected data fields, visualizations are rendered correctly, and data matches filter criteria |
| 3 | Click the 'Export as PDF' button from the report toolbar | PDF export process initiates with a download progress indicator |
| 4 | Wait for PDF file download to complete and open the downloaded PDF file | PDF file downloads successfully and opens displaying the conflict report with proper formatting, all data tables, charts, headers, footers, and page numbers intact |
| 5 | Verify PDF content matches the on-screen report | PDF contains identical data to the screen report with professional formatting, readable fonts, and properly scaled visualizations |
| 6 | Return to the report interface and click the 'Export as Excel' button | Excel export process initiates with a download progress indicator |
| 7 | Wait for Excel file download to complete and open the downloaded Excel file | Excel file downloads successfully and opens in spreadsheet application with data organized in appropriate sheets and columns |
| 8 | Verify Excel file contains accurate and complete data | Excel file contains all report data in structured format with proper column headers, data types preserved, formulas if applicable, and data matches the original report exactly |
| 9 | Check Excel file for data manipulation capabilities | Data in Excel is editable and can be sorted, filtered, and analyzed using standard Excel functions |

**Postconditions:**
- PDF and Excel files are successfully downloaded to user's device
- Both exported files contain accurate and complete report data
- Original report remains displayed on screen unchanged
- Export actions are logged in system audit trail

---

### Test Case: Test automated report scheduling and delivery
- **ID:** tc-006
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 15 mins

**Preconditions:**
- User has Scheduler role with report scheduling permissions
- User is logged into the scheduling system
- User is on the conflict reporting module
- Email delivery system is configured and operational
- User has a valid email address registered in the system
- System time is synchronized and accurate
- Automated scheduling service is running

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the 'Schedule Automated Report' section within the conflict reporting module | Report scheduling interface is displayed with options for frequency, filters, format, and delivery settings |
| 2 | Configure report parameters by selecting date range filter (e.g., previous week), resource filter, and severity level | Selected parameters are displayed in the scheduling configuration with all filters properly set |
| 3 | Set the report frequency to a near-term schedule for testing (e.g., 5 minutes from current time or next available schedule slot) | Schedule time is accepted and displayed in the configuration summary |
| 4 | Select report format as PDF for email delivery | PDF format is selected and shown in the delivery settings |
| 5 | Enter or confirm the email address for report delivery | Email address is validated and accepted by the system |
| 6 | Click 'Save Schedule' or 'Create Scheduled Report' button | System displays confirmation message that the automated report schedule has been saved successfully with schedule details shown |
| 7 | Verify the scheduled report appears in the list of active scheduled reports | Scheduled report is listed with correct parameters, next run time, and status showing as 'Active' |
| 8 | Wait for the scheduled report delivery time to arrive | System processes the scheduled report at the designated time |
| 9 | Check the registered email inbox for the scheduled report | Email is received on time (within 2 minutes of scheduled time) with subject line indicating it is an automated conflict report |
| 10 | Open the email and verify it contains the report attachment | Email contains PDF attachment with appropriate filename including date/time stamp |
| 11 | Download and open the PDF attachment from the email | PDF opens successfully and displays the conflict report with data matching the scheduled parameters |
| 12 | Verify report content matches the scheduled filter parameters (date range, resource, severity) | Report data accurately reflects the filters specified during scheduling, with correct date range, resource filtering, and severity levels included |
| 13 | Check the scheduled report status in the system | Scheduled report shows last run time, successful delivery status, and next scheduled run time if recurring |

**Postconditions:**
- Automated report schedule is saved and active in the system
- Report was successfully generated and delivered via email
- Email contains accurate report data matching scheduled parameters
- Schedule remains active for future executions if set as recurring
- Delivery is logged in system audit trail with timestamp and recipient

---

