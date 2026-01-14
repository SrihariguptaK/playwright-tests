# Manual Test Cases

## Story: As Scheduler, I want to view visual indicators of scheduling conflicts on my calendar to quickly identify issues
**Story ID:** story-13

### Test Case: Verify visual conflict indicators on calendar
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as Scheduler
- Calendar view is accessible
- Scheduling system is operational
- At least two resources are available for booking

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the scheduling calendar view | Calendar view loads successfully displaying current bookings |
| 2 | Create a booking for Resource A from 10:00 AM to 12:00 PM on a specific date | Booking is created and displayed on the calendar without any conflict indicator |
| 3 | Create a second booking for Resource A from 11:00 AM to 1:00 PM on the same date (overlapping time) | Conflict indicator (icon or highlight) appears on both conflicting calendar entries |
| 4 | Click on the conflict indicator on the first booking | Detailed conflict information is displayed showing the overlapping booking details, time conflict, and affected resource |
| 5 | Close the conflict details popup or panel | Conflict details close and calendar view remains visible with conflict indicators still present |
| 6 | Modify the second booking to change the time from 1:00 PM to 3:00 PM (no overlap) | Booking is updated successfully |
| 7 | Observe the calendar entries for both bookings | Conflict indicators are removed from both calendar entries as the conflict is resolved |

**Postconditions:**
- No conflict indicators are displayed on the calendar
- Both bookings exist without time overlap
- Calendar displays accurate booking information

---

### Test Case: Test real-time update of conflict indicators
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in as Scheduler
- Calendar view is open and active
- Scheduling system is operational
- At least one existing booking is present on the calendar
- System clock is synchronized for accurate timing measurement

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Note the current time and observe an existing booking on the calendar (e.g., Resource B from 2:00 PM to 4:00 PM) | Existing booking is visible without conflict indicator |
| 2 | Create a new booking for Resource B from 3:00 PM to 5:00 PM (creating an overlap) | New booking is created |
| 3 | Measure the time from booking creation to conflict indicator appearance | Conflict indicator appears on both conflicting bookings within 1 second of creating the conflicting booking |
| 4 | Verify that both bookings now display conflict indicators | Both the original booking (2:00 PM - 4:00 PM) and new booking (3:00 PM - 5:00 PM) show conflict indicators |
| 5 | Note the current time and modify the new booking to change the time from 4:00 PM to 6:00 PM (removing overlap) | Booking is updated successfully |
| 6 | Measure the time from booking modification to conflict indicator removal | Conflict indicators disappear from both bookings within 1 second of resolving the conflict |
| 7 | Verify that no conflict indicators remain on either booking | Calendar displays both bookings without any conflict indicators |

**Postconditions:**
- No conflicts exist between bookings
- Real-time update performance meets the 1-second requirement
- Calendar accurately reflects current booking status

---

### Test Case: Check conflict indicators on mobile interface
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User has valid Scheduler credentials
- Mobile device (smartphone or tablet) is available
- Mobile browser or application is installed and updated
- Network connectivity is stable
- Scheduling system is accessible via mobile interface

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open the scheduling application on a mobile device and log in as Scheduler | Login is successful and mobile interface loads properly |
| 2 | Navigate to the calendar view on the mobile interface | Calendar view is displayed in mobile-optimized format |
| 3 | Create a booking for Resource C from 9:00 AM to 11:00 AM on a specific date | Booking is created and visible on the mobile calendar |
| 4 | Create a conflicting booking for Resource C from 10:00 AM to 12:00 PM on the same date | Conflict indicators appear on both bookings and are clearly visible on the mobile screen |
| 5 | Tap on the conflict indicator on the first booking | Conflict details panel or popup opens displaying detailed conflict information in mobile-friendly format |
| 6 | Review the conflict details including overlapping times, affected resource, and booking information | All conflict information is readable and properly formatted for mobile display |
| 7 | Close the conflict details and tap on the conflict indicator on the second booking | Conflict details for the second booking are displayed with the same level of detail and accessibility |
| 8 | Verify touch responsiveness and visual clarity of conflict indicators | Conflict indicators are easily tappable, visually distinct, and do not overlap with other UI elements |

**Postconditions:**
- Mobile calendar displays conflict indicators correctly
- Conflict details are accessible on mobile interface
- User remains logged in on mobile device

---

## Story: As Scheduler, I want to generate reports summarizing scheduling conflicts to analyze patterns and improve scheduling practices
**Story ID:** story-15

### Test Case: Generate conflict summary report with valid parameters
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in as Scheduler with report access permissions
- Conflict data exists in the system for the selected date range
- Reporting module is accessible and operational
- Database contains at least 5 conflict records for testing

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the reporting section from the main menu or dashboard | Reporting section loads successfully and displays available report types |
| 2 | Select 'Conflict Reports' or 'Scheduling Conflicts' option | Conflict report UI is displayed with parameter input fields including date range, filters, and sorting options |
| 3 | Enter a valid start date (e.g., first day of current month) in the 'From Date' field | Date is accepted and displayed in the correct format |
| 4 | Enter a valid end date (e.g., last day of current month) in the 'To Date' field | Date is accepted and displayed in the correct format |
| 5 | Select filter options such as conflict type or affected resources if available | Filter selections are accepted and displayed |
| 6 | Note the current time and click the 'Generate Report' button | System begins processing the report request and displays a loading indicator |
| 7 | Measure the time from clicking 'Generate Report' to report display | Report is generated and displayed within 5 seconds |
| 8 | Review the generated report for conflict summary data including frequency metrics | Report displays accurate data including total conflicts, conflict types, affected resources, date/time information, and resolution status |
| 9 | Verify that the report includes metrics on conflict frequency by day, week, or month | Frequency metrics are displayed with appropriate charts or tables |
| 10 | Verify that conflict types are categorized and counted in the report | Report shows breakdown of conflicts by type with counts and percentages |

**Postconditions:**
- Report is successfully generated and displayed
- Report data matches the selected parameters
- System performance meets the 5-second SLA
- User remains on the report view page

---

### Test Case: Export report in PDF and Excel formats
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in as Scheduler with report export permissions
- A conflict report has been successfully generated and is displayed on screen
- Browser allows file downloads
- Sufficient disk space is available for downloads

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the conflict reports section and generate a report with valid parameters (date range: last 30 days) | Conflict report is generated and displayed successfully with conflict data |
| 2 | Verify that the report contains data including conflict summaries, metrics, and details | Report displays complete information with tables, charts, and summary statistics |
| 3 | Locate and click the 'Export' or 'Download' button/dropdown menu | Export options menu is displayed showing available formats (PDF and Excel) |
| 4 | Select 'Export as PDF' option from the menu | System initiates PDF generation and download process |
| 5 | Wait for the PDF file to download and verify the download completion | PDF file downloads successfully to the default download location with a meaningful filename (e.g., 'Conflict_Report_YYYY-MM-DD.pdf') |
| 6 | Open the downloaded PDF file using a PDF reader | PDF opens successfully and displays the complete report with all data, formatting, charts, and tables intact |
| 7 | Return to the report view in the application and click the 'Export' button again | Export options menu is displayed again |
| 8 | Select 'Export as Excel' or 'Export as XLSX' option from the menu | System initiates Excel file generation and download process |
| 9 | Wait for the Excel file to download and verify the download completion | Excel file downloads successfully to the default download location with a meaningful filename (e.g., 'Conflict_Report_YYYY-MM-DD.xlsx') |
| 10 | Open the downloaded Excel file using spreadsheet software (Excel, Google Sheets, etc.) | Excel file opens successfully and displays the complete report data in spreadsheet format with proper columns, rows, and data formatting |
| 11 | Verify that the Excel file contains all report data including metrics, conflict details, and summary information | All data from the report is present and properly structured in the Excel file with headers and formatted cells |

**Postconditions:**
- Both PDF and Excel files are successfully downloaded
- Downloaded files contain accurate and complete report data
- Files are accessible and properly formatted
- User remains logged in and on the report page

---

### Test Case: Handle invalid report parameters gracefully
- **ID:** tc-006
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- User is logged in as Scheduler
- Conflict reports section is accessible
- Reporting UI is displayed with parameter input fields

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the conflict reports section | Report UI is displayed with empty or default parameter fields |
| 2 | Enter an end date that is earlier than the start date (e.g., Start: 2024-01-31, End: 2024-01-01) | System detects the invalid date range |
| 3 | Attempt to generate the report by clicking 'Generate Report' button | Validation error message is displayed indicating 'End date must be after start date' or similar message, and report generation is blocked |
| 4 | Verify that the error message is clearly visible and user-friendly | Error message is displayed in red or highlighted format near the date fields with clear instructions |
| 5 | Clear the date fields and enter a future date range (e.g., dates beyond current date) | Dates are entered in the fields |
| 6 | Attempt to generate the report | Validation error is displayed indicating 'Cannot generate reports for future dates' or the report generates with no data and appropriate message |
| 7 | Clear the date fields and leave the start date empty while entering only an end date | End date is entered, start date remains empty |
| 8 | Attempt to generate the report | Validation error is displayed indicating 'Start date is required' and report generation is blocked |
| 9 | Enter a valid start date but leave the end date empty | Start date is entered, end date remains empty |
| 10 | Attempt to generate the report | Validation error is displayed indicating 'End date is required' and report generation is blocked |
| 11 | Enter an excessively large date range (e.g., 10 years) if system has range limits | Dates are entered in the fields |
| 12 | Attempt to generate the report | Validation error or warning is displayed if date range exceeds system limits, or report generates with performance warning |
| 13 | Correct all validation errors by entering a valid date range (e.g., last 30 days) | Valid dates are accepted and no validation errors are displayed |
| 14 | Click 'Generate Report' button | Report is generated successfully within 5 seconds with accurate conflict data for the specified valid date range |

**Postconditions:**
- System properly validates all report parameters
- Invalid inputs are rejected with clear error messages
- Report generation only proceeds with valid parameters
- User can successfully generate report after correcting errors

---

