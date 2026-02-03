@edge-cases @boundary
Feature: As Scheduler, I want to view conflict history to analyze patterns and improve scheduling - Edge Case Tests
  As a user
  I want to test edge case tests
  So that I can ensure quality and reliability

  Background:
    Given the system is ready for testing
    And the test environment is properly configured

  @medium @tc-edge-001
  Scenario: TC-EDGE-001 - Verify system handles conflict history with maximum allowed records (10,000+ conflicts)
    Given user is logged in as Scheduler on the conflict history page
    And conflict history database contains 10,000+ conflict records
    And no filters are applied initially
    And pagination is set to display 10 records per page
    When navigate to the conflict history page
    Then page loads within 3 seconds showing first 10 conflicts. Pagination shows 'Page 1 of 1000' and displays total count 'Showing 10 of 10,000+ conflicts'
    And click the 'Last Page' button in pagination controls
    Then system navigates to the last page within 3 seconds, displaying the final 10 records. Page indicator shows 'Page 1000 of 1000'
    And attempt to export all 10,000+ conflicts by clicking Export and selecting CSV format
    Then warning message appears: 'Large dataset detected (10,000+ records). Export may take several minutes. Continue?' with Yes/No options
    And click 'Yes' to proceed with export
    Then progress indicator appears showing 'Preparing export... 25%... 50%... 75%... 100%'. File downloads successfully within 60 seconds containing all 10,000+ records
    And verify the exported CSV file opens and contains the correct number of records
    Then cSV file opens successfully with 10,000+ rows (plus header row). File size is appropriate and data is not truncated
    And system performance remains stable with large dataset
    And memory usage stays within acceptable limits
    And user can continue to interact with the page after export
    And large export is logged in system performance logs

  @medium @tc-edge-002
  Scenario: TC-EDGE-002 - Verify system handles conflict history with zero records in database
    Given user is logged in as Scheduler on the conflict history page
    And conflict history database contains zero conflict records (new system or all conflicts deleted)
    And user has valid permissions to view conflict history
    And aPI endpoint returns empty array for conflict history
    When navigate to the conflict history page by clicking 'Conflict History' in navigation menu
    Then page loads successfully within 3 seconds showing empty state illustration with message 'No conflict history available yet'
    And verify helpful guidance text is displayed
    Then subtext appears stating 'Conflicts will appear here once scheduling conflicts are detected. Check back later or review your scheduling settings.'
    And verify filter controls are disabled or hidden
    Then date range and conflict type filters are either grayed out/disabled or hidden with tooltip 'No data available to filter'
    And verify export button is disabled
    Then export button is grayed out and shows tooltip 'No data available to export' when hovered
    And verify pagination controls are not displayed
    Then no pagination controls are visible. Count shows 'Showing 0 conflicts'
    And user understands why no data is displayed
    And page remains functional and does not show errors
    And user can navigate away to other pages normally
    And when conflicts are added, page will display them on next visit

  @medium @tc-edge-003
  Scenario: TC-EDGE-003 - Verify system handles conflict records with special characters and Unicode in descriptions
    Given user is logged in as Scheduler on the conflict history page
    And conflict history contains records with special characters: <script>, &, ', ", emojis (🔥, 📅), Unicode (中文, العربية), and newlines
    And at least 3 conflicts have descriptions containing these special characters
    And character encoding is set to UTF-8
    When navigate to the conflict history page and locate conflicts with special characters in descriptions
    Then page loads successfully and displays conflicts. Special characters are properly rendered without breaking the UI layout
    And click on a conflict record containing HTML-like tags '<script>alert("test")</script>' in the description
    Then detail modal opens and displays the text as plain text, not executed as HTML/JavaScript. Tags are escaped and shown as literal text: '&lt;script&gt;alert(&quot;test&quot;)&lt;/script&gt;'
    And verify a conflict with emoji characters (🔥📅) displays correctly in both table and detail view
    Then emojis render properly in both table cell and detail modal without causing layout issues or character corruption
    And export conflict history containing special characters to CSV format
    Then cSV file downloads successfully. When opened, special characters are preserved correctly: emojis display, Unicode text is readable, and HTML tags are escaped
    And search/filter for a conflict using Unicode characters (e.g., search for '中文')
    Then search successfully finds and displays conflicts containing the Unicode search term. Results are accurate and character encoding is maintained
    And all special characters are properly escaped and displayed
    And no XSS vulnerabilities are exposed
    And data integrity is maintained in exports
    And unicode and emoji support is confirmed functional

  @high @tc-edge-004
  Scenario: TC-EDGE-004 - Verify system handles rapid consecutive filter applications without race conditions
    Given user is logged in as Scheduler on the conflict history page
    And conflict history contains at least 50 records
    And network latency is simulated at 500ms for API responses
    And multiple filter options are available
    When apply date range filter for March 2024 and immediately click 'Apply Filter'
    Then loading spinner appears and API request is initiated for March 2024 data
    And before the first request completes, change date range to April 2024 and click 'Apply Filter' again
    Then first request is cancelled or ignored. New loading spinner appears for April 2024 request. Previous request does not interfere
    And before the second request completes, change conflict type to 'Resource Overlap' and click 'Apply Filter' a third time
    Then second request is cancelled. Third request proceeds with both April 2024 date range AND Resource Overlap type filter
    And wait for the final request to complete
    Then table displays results matching the LAST applied filters only (April 2024 + Resource Overlap). No mixed results from previous requests appear. Count and data are consistent
    And verify only one set of results is displayed with no duplicate or conflicting data
    Then table shows coherent results matching April 2024 Resource Overlap conflicts. No race condition artifacts like duplicate rows or mixed filter results
    And only the most recent filter request results are displayed
    And no memory leaks from cancelled requests
    And system remains responsive for further interactions
    And request cancellation is logged appropriately

  @medium @tc-edge-005
  Scenario: TC-EDGE-005 - Verify system handles conflict history page at 200% browser zoom level
    Given user is logged in as Scheduler on the conflict history page
    And conflict history displays at least 10 records
    And browser zoom is initially set to 100%
    And page is designed to be responsive
    When set browser zoom level to 200% using Ctrl/Cmd + Plus key or browser zoom controls
    Then page content scales up to 200% zoom. All text becomes larger and more readable
    And verify the conflict history table remains functional and readable
    Then table columns adjust appropriately. Horizontal scrollbar appears if needed. All text is readable without overlapping. Column headers and data cells maintain proper alignment
    And verify filter controls are accessible and usable at 200% zoom
    Then date pickers, dropdowns, and buttons are large enough to click easily. No UI elements are cut off or hidden. Filter section may stack vertically if needed for space
    And apply a filter and verify the results display correctly at 200% zoom
    Then filtered results appear properly. Loading states, success messages, and result counts are all visible and readable
    And open a conflict detail modal and verify it displays correctly at 200% zoom
    Then modal scales appropriately, remains centered on screen, and all content is accessible. Scrollbar appears within modal if content exceeds viewport. Close button remains accessible
    And page remains fully functional at 200% zoom
    And user can zoom back to 100% without issues
    And no layout breaks or content loss occurs
    And responsive design handles zoom levels appropriately

  @low @tc-edge-006
  Scenario: TC-EDGE-006 - Verify system handles conflict history with date range spanning multiple years (5+ years)
    Given user is logged in as Scheduler on the conflict history page
    And conflict history database contains records from January 2019 to December 2024 (5+ years)
    And at least 1000 conflicts exist across this time period
    And date range filter allows selecting wide date ranges
    When set Start Date to January 1, 2019 in the date range filter
    Then start Date field displays '01/01/2019'
    And set End Date to December 31, 2024 in the date range filter
    Then end Date field displays '12/31/2024'. System accepts the 5+ year date range without validation errors
    And click 'Apply Filter' button
    Then loading indicator appears. System processes the large date range query. Results load within 5 seconds showing conflicts from the entire 5-year period
    And verify pagination shows the total count of conflicts across all years
    Then pagination displays accurate total like 'Showing 10 of 1,247 conflicts' spanning from 2019 to 2024
    And attempt to export the 5-year conflict history
    Then export warning appears: 'You are exporting 1,247 conflicts spanning 5 years. This may take a few minutes.' Export completes successfully with all records included
    And verify the exported file contains conflicts from both the earliest (2019) and latest (2024) dates
    Then exported CSV contains records with dates ranging from January 2019 to December 2024, confirming complete date range coverage
    And system handles multi-year queries without performance degradation
    And all conflicts within the date range are accessible
    And export includes complete historical data
    And user can narrow the date range for more focused analysis

