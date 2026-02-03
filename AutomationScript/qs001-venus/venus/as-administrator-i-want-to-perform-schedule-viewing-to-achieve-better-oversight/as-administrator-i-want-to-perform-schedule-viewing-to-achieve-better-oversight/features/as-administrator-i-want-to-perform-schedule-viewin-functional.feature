@functional @smoke
Feature: As Administrator, I want to perform schedule viewing to achieve better oversight. - Functional Tests
  As a user
  I want to test functional tests
  So that I can ensure quality and reliability

  Background:
    Given the system is ready for testing
    And the test environment is properly configured

  @high @tc-func-001
  Scenario: TC-FUNC-001 - Verify administrator can view employee schedules in calendar format
    Given user is logged in with Administrator role and valid session token
    And at least 10 employee schedules exist in the EmployeeSchedules table
    And user is on the dashboard or home page
    And browser supports calendar view rendering (Chrome, Firefox, Safari, Edge)
    When navigate to the schedule viewing page by clicking 'Schedules' in the main navigation menu
    Then schedule viewing page loads successfully with calendar interface displayed showing current month view
    And observe the calendar layout and employee schedule entries
    Then calendar displays all employee schedules with employee names, shift times, and shift types clearly visible in date cells
    And click on a specific schedule entry in the calendar
    Then schedule details popup or panel appears showing full information including employee name, shift type, start time, end time, and location
    And navigate between months using previous/next month arrows
    Then calendar updates to show schedules for the selected month with smooth transition and correct data loading
    And user remains on the schedule viewing page with calendar displayed
    And no data modifications have occurred in the EmployeeSchedules table
    And user session remains active and authenticated
    And page state is ready for additional filtering or export actions

  @high @tc-func-002
  Scenario: TC-FUNC-002 - Verify administrator can filter schedules by specific employee
    Given user is logged in as Administrator with valid permissions
    And schedule viewing page is already loaded and displaying calendar view
    And at least 5 different employees have schedules in the system
    And employee filter dropdown is visible and populated with employee names
    When locate and click on the 'Filter by Employee' dropdown in the filter panel
    Then dropdown expands showing a list of all employees with schedules, sorted alphabetically by last name
    And select a specific employee 'John Smith' from the dropdown list
    Then dropdown closes and 'John Smith' is displayed as the selected filter value
    And click the 'Apply Filter' button
    Then calendar refreshes and displays only schedules assigned to John Smith, with a filter badge showing '1 filter applied' near the top
    And verify the filtered results by checking multiple dates in the calendar
    Then only John Smith's schedule entries are visible across all dates, no other employee schedules are shown
    And click the 'Clear Filters' button or remove the employee filter
    Then calendar returns to showing all employee schedules, filter badge disappears, and dropdown resets to 'All Employees'
    And filter state is cleared and all schedules are visible again
    And no permanent changes made to schedule data
    And user remains on schedule viewing page
    And filter controls are reset to default state

  @high @tc-func-003
  Scenario: TC-FUNC-003 - Verify administrator can filter schedules by shift type
    Given user is logged in as Administrator
    And schedule viewing page is loaded with calendar displayed
    And multiple shift types exist in the system (Morning, Evening, Night, Weekend)
    And at least 3 schedules exist for each shift type
    When click on the 'Filter by Shift Type' dropdown in the filter panel
    Then dropdown opens displaying all available shift types: Morning, Evening, Night, Weekend with checkboxes
    And select 'Morning' shift type by clicking its checkbox
    Then morning checkbox is checked and highlighted
    And click 'Apply Filter' button
    Then calendar updates to show only Morning shift schedules, with visual indicator showing 'Filtered by: Morning Shift'
    And verify schedule entries display only Morning shifts by checking shift time ranges
    Then all visible schedule entries show shift times between 6:00 AM and 2:00 PM, confirming Morning shift filter is working
    And only Morning shift schedules are displayed in the calendar
    And filter state is maintained if user navigates between months
    And original schedule data remains unchanged in database
    And user can apply additional filters or clear current filter

  @high @tc-func-004
  Scenario: TC-FUNC-004 - Verify administrator can print schedules successfully
    Given user is logged in as Administrator
    And schedule viewing page is displayed with at least 5 schedules visible
    And browser print functionality is enabled
    And user has a printer configured or can print to PDF
    When apply desired filters (optional) to show specific schedules to print
    Then calendar displays the filtered schedules that will be printed
    And click the 'Print Schedule' button in the toolbar
    Then browser print dialog opens showing print preview of the schedule in a print-friendly format
    And review the print preview to ensure schedules are formatted correctly
    Then print preview shows calendar layout with clear employee names, dates, shift times, and shift types without navigation elements or buttons
    And select printer or 'Save as PDF' option and click 'Print' button in dialog
    Then print job is sent successfully or PDF is generated and saved, with success message 'Schedule printed successfully' displayed
    And printed document or PDF contains accurate schedule information
    And user returns to schedule viewing page after print dialog closes
    And no changes made to schedule data
    And print action is logged in system audit trail

  @high @tc-func-005
  Scenario: TC-FUNC-005 - Verify administrator can export schedules to CSV format
    Given user is logged in as Administrator with export permissions
    And schedule viewing page is loaded with schedules displayed
    And at least 10 employee schedules are available for export
    And browser allows file downloads
    When click the 'Export' button in the toolbar
    Then export options dropdown appears showing 'Export as CSV' and 'Export as PDF' options
    And select 'Export as CSV' from the dropdown
    Then export process initiates with a loading indicator showing 'Preparing CSV export...'
    And wait for the export to complete
    Then cSV file 'employee_schedules_YYYY-MM-DD.csv' automatically downloads to the default downloads folder, and success message 'Schedule exported successfully' appears
    And open the downloaded CSV file in Excel or text editor
    Then cSV file opens correctly with headers: Employee Name, Date, Shift Type, Start Time, End Time, Location and all schedule data is present and properly formatted
    And verify data accuracy by comparing 5 random entries with the calendar view
    Then all checked entries match exactly between the CSV file and the calendar display
    And cSV file is saved in user's downloads folder with correct filename format
    And file contains all visible schedule data with proper formatting
    And user remains on schedule viewing page
    And export action is logged with timestamp and user ID in audit trail

  @high @tc-func-006
  Scenario: TC-FUNC-006 - Verify administrator can export schedules to PDF format
    Given user is logged in as Administrator
    And schedule viewing page is displayed with calendar view
    And at least 15 schedules are visible in the current view
    And browser supports PDF downloads
    When apply filters to show specific date range (e.g., current week)
    Then calendar updates to show only schedules for the selected week
    And click 'Export' button and select 'Export as PDF' option
    Then pDF generation process starts with progress indicator showing 'Generating PDF...'
    And wait for PDF generation to complete
    Then pDF file 'employee_schedules_YYYY-MM-DD.pdf' downloads automatically and success notification 'PDF exported successfully' appears in green banner
    And open the downloaded PDF file
    Then pDF opens showing professionally formatted schedule with company header, calendar layout, employee names, shift details, and page numbers
    And verify PDF contains all filtered schedules and is properly paginated
    Then all schedules from the filtered view are present, layout is clean and readable, and multi-page PDFs have proper page breaks
    And pDF file is saved with correct naming convention and timestamp
    And pDF contains accurate schedule data matching the filtered view
    And user remains on schedule viewing page with filters still applied
    And export action is recorded in system logs

