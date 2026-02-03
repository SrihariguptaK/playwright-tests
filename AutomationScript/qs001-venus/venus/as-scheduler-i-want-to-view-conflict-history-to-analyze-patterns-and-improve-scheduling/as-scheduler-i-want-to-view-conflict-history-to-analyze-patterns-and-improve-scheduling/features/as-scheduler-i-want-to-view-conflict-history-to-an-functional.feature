@functional @smoke
Feature: As Scheduler, I want to view conflict history to analyze patterns and improve scheduling - Functional Tests
  As a user
  I want to test functional tests
  So that I can ensure quality and reliability

  Background:
    Given the system is ready for testing
    And the test environment is properly configured

  @high @tc-func-001
  Scenario: TC-FUNC-001 - Verify successful retrieval and display of conflict history with all relevant details
    Given user is logged in with Scheduler role and valid authentication token
    And conflict history database contains at least 20 historical conflict records
    And user has permission to access conflict history page
    And browser is on the main dashboard page
    When click on 'Conflict History' menu item in the left navigation panel
    Then conflict history page loads within 3 seconds and displays a table with columns: Conflict ID, Date, Time, Type, Resources Involved, Status, and Actions
    And verify the conflict list displays with pagination showing 10 records per page
    Then table shows 10 conflict records with pagination controls at the bottom showing 'Page 1 of 2' and Next/Previous buttons
    And click on any conflict row to view detailed information
    Then conflict detail modal opens displaying full conflict information including: conflict description, affected schedules, resolution status, timestamp, and involved parties
    And close the detail modal by clicking the 'X' button in top-right corner
    Then modal closes smoothly and user returns to the conflict history list view
    And user remains on conflict history page with list view displayed
    And no data is modified in the conflict history database
    And page state is maintained for further interactions

  @high @tc-func-002
  Scenario: TC-FUNC-002 - Verify filtering conflict history by date range returns accurate results
    Given user is logged in as Scheduler on the conflict history page
    And conflict history contains records spanning from January 1, 2024 to December 31, 2024
    And date range filter controls are visible at the top of the page
    And at least 5 conflicts exist within the date range March 1-31, 2024
    When click on the 'Start Date' calendar input field in the filter section
    Then calendar date picker opens showing current month and year
    And select March 1, 2024 from the calendar picker
    Then start Date field displays '03/01/2024' and calendar closes
    And click on the 'End Date' calendar input field
    Then calendar date picker opens for end date selection
    And select March 31, 2024 from the calendar picker
    Then end Date field displays '03/31/2024' and calendar closes
    And click the 'Apply Filter' button with blue background
    Then loading spinner appears briefly, then table refreshes showing only conflicts between March 1-31, 2024. Filter summary displays 'Showing conflicts from 03/01/2024 to 03/31/2024' above the table
    And verify each displayed conflict has a date within the selected range
    Then all visible conflict records show dates between March 1 and March 31, 2024. No records outside this range are displayed
    And filter remains applied with selected date range visible in filter controls
    And conflict count badge updates to reflect filtered results
    And export and other actions operate only on filtered dataset
    And filter can be cleared or modified for subsequent searches

  @high @tc-func-003
  Scenario: TC-FUNC-003 - Verify filtering conflict history by conflict type displays only matching records
    Given user is logged in as Scheduler on the conflict history page
    And conflict history contains multiple conflict types: Resource Overlap, Time Conflict, Location Conflict, and Capacity Exceeded
    And at least 3 conflicts of type 'Resource Overlap' exist in the database
    And conflict type dropdown filter is visible and enabled
    When click on the 'Conflict Type' dropdown filter in the filter section
    Then dropdown expands showing all available conflict types: All Types, Resource Overlap, Time Conflict, Location Conflict, Capacity Exceeded
    And select 'Resource Overlap' from the dropdown options
    Then dropdown closes and displays 'Resource Overlap' as selected value
    And click the 'Apply Filter' button
    Then table refreshes and displays only conflicts with type 'Resource Overlap'. Filter badge shows 'Type: Resource Overlap' above the table
    And verify the 'Type' column in the table shows only 'Resource Overlap' for all displayed records
    Then all visible records in the Type column display 'Resource Overlap' with no other conflict types present
    And click the 'Clear Filters' button with gray outline
    Then all filters reset, dropdown shows 'All Types', and table displays all conflict records regardless of type
    And filters are cleared and system returns to unfiltered state
    And all conflict types are visible in the table
    And filter controls are reset to default values
    And user can apply new filters immediately

  @medium @tc-func-004
  Scenario: TC-FUNC-004 - Verify sorting conflict history by date in ascending and descending order
    Given user is logged in as Scheduler on the conflict history page
    And conflict history table displays at least 10 records with varying dates
    And table is currently unsorted or sorted by Conflict ID
    And date column header is clickable with sort icon visible
    When click on the 'Date' column header in the conflict history table
    Then table re-sorts with conflicts displayed in ascending date order (oldest first). Up arrow icon appears next to 'Date' column header
    And verify the first record shows the oldest conflict date and last record shows the most recent date
    Then dates are arranged chronologically from oldest to newest when reading top to bottom
    And click on the 'Date' column header again
    Then table re-sorts with conflicts displayed in descending date order (newest first). Down arrow icon appears next to 'Date' column header
    And verify the first record shows the most recent conflict date and last record shows the oldest date
    Then dates are arranged in reverse chronological order from newest to oldest when reading top to bottom
    And table remains sorted by date in descending order
    And sort preference is maintained during pagination
    And other columns remain sortable
    And sort state persists until user changes it or refreshes page

  @high @tc-func-005
  Scenario: TC-FUNC-005 - Verify exporting conflict history generates downloadable file with correct data
    Given user is logged in as Scheduler on the conflict history page
    And conflict history table displays at least 5 filtered conflict records
    And date range filter is applied showing conflicts from March 1-31, 2024
    And export button is visible and enabled in the top-right corner of the page
    When click the 'Export' button with download icon in the top-right corner
    Then export options modal opens displaying format options: CSV, Excel (.xlsx), and PDF
    And select 'CSV' format option by clicking the radio button
    Then cSV option is selected with radio button filled, and 'Download' button becomes enabled
    And click the 'Download' button in the export modal
    Then success message 'Export started. Your file will download shortly.' appears. Modal closes and file download begins within 2 seconds
    And open the downloaded CSV file named 'conflict_history_YYYY-MM-DD.csv' in a spreadsheet application
    Then cSV file opens successfully containing all filtered conflict records with columns: Conflict ID, Date, Time, Type, Resources Involved, Status, Description
    And verify the CSV contains only the filtered conflicts from March 1-31, 2024 and matches the count shown in the UI
    Then cSV file contains exactly the same number of records as displayed in the filtered table, all with dates between March 1-31, 2024
    And cSV file is successfully downloaded to user's default download folder
    And user remains on conflict history page with filters still applied
    And export action is logged in system audit trail
    And no data is modified in the conflict history database

  @high @tc-func-006
  Scenario: TC-FUNC-006 - Verify combining multiple filters (date range and conflict type) returns accurate intersection of results
    Given user is logged in as Scheduler on the conflict history page
    And conflict history contains at least 15 records with various types and dates
    And at least 3 'Time Conflict' type conflicts exist between April 1-30, 2024
    And both date range and conflict type filters are available and functional
    When set Start Date to '04/01/2024' and End Date to '04/30/2024' in the date range filter
    Then both date fields display the selected dates correctly
    And select 'Time Conflict' from the Conflict Type dropdown
    Then dropdown displays 'Time Conflict' as selected value
    And click the 'Apply Filter' button
    Then table refreshes showing only conflicts that are BOTH type 'Time Conflict' AND dated between April 1-30, 2024. Filter summary shows 'Type: Time Conflict | Date: 04/01/2024 - 04/30/2024'
    And verify each displayed record matches both filter criteria
    Then all visible records show 'Time Conflict' in Type column and dates between April 1-30, 2024 in Date column. No records violating either criterion are displayed
    And note the total count of filtered results displayed above the table
    Then count badge shows accurate number like 'Showing 3 of 15 conflicts' matching the filtered results
    And both filters remain active and visible in the UI
    And filtered dataset is used for any export or analysis actions
    And pagination reflects only the filtered results
    And filters can be individually removed or modified

