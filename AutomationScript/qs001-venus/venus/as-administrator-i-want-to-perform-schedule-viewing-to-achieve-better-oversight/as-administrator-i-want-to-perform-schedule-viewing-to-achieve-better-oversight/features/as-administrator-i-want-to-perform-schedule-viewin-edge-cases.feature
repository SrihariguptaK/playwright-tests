@edge-cases @boundary
Feature: As Administrator, I want to perform schedule viewing to achieve better oversight. - Edge Case Tests
  As a user
  I want to test edge case tests
  So that I can ensure quality and reliability

  Background:
    Given the system is ready for testing
    And the test environment is properly configured

  @high @tc-edge-001
  Scenario: TC-EDGE-001 - Verify system handles viewing schedules with maximum data load (1000 schedules)
    Given user is logged in as Administrator
    And database contains exactly 1000 employee schedules across multiple months
    And system performance requirements specify handling up to 1000 schedule views
    And browser has sufficient memory and resources
    When navigate to schedule viewing page
    Then page loads within 3 seconds despite large dataset
    And observe initial calendar rendering with current month view
    Then calendar displays schedules for current month without lag or freezing, showing appropriate number of schedules per day
    And navigate through multiple months rapidly using next/previous buttons
    Then each month loads within 1-2 seconds, calendar remains responsive, no browser freezing occurs
    And apply filter to show all 1000 schedules in a list or expanded view
    Then system implements pagination or virtual scrolling, showing 50-100 schedules per page with smooth scrolling
    And attempt to export all 1000 schedules to CSV
    Then export completes within 10 seconds, CSV file contains all 1000 records with correct data
    And system performance remains within acceptable limits
    And all 1000 schedules are accessible and viewable
    And no data loss or corruption occurs
    And browser memory usage remains stable

  @medium @tc-edge-002
  Scenario: TC-EDGE-002 - Verify system handles empty schedule database
    Given user is logged in as Administrator
    And employeeSchedules table in database is completely empty (0 records)
    And no filters are applied
    And user navigates to schedule viewing page
    When navigate to schedule viewing page
    Then page loads successfully showing empty calendar interface
    And observe the empty state display
    Then calendar shows empty state with helpful message 'No schedules available. Create your first schedule to get started.' and a 'Create Schedule' button (if in scope)
    And attempt to apply filters on empty data
    Then filter dropdowns are either disabled or show 'No options available' with appropriate messaging
    And attempt to export empty schedule data
    Then export buttons are disabled or show warning 'No schedules to export'
    And attempt to print empty schedule
    Then print button is disabled or prints a page with 'No schedules available' message
    And no errors or crashes occur with empty data
    And user interface remains functional and informative
    And user is guided on next steps (creating schedules)
    And empty state is handled gracefully across all features

  @medium @tc-edge-003
  Scenario: TC-EDGE-003 - Verify schedule viewing with special characters and Unicode in employee names
    Given user is logged in as Administrator
    And database contains employee schedules with names including special characters: O'Brien, José García, 李明, Müller, Владимир
    And schedule viewing page is accessible
    And browser supports Unicode character rendering
    When navigate to schedule viewing page
    Then page loads and displays all schedules including those with special characters
    And verify employee names with special characters are displayed correctly in calendar
    Then all names render correctly: O'Brien shows apostrophe, José García shows accent marks, 李明 shows Chinese characters, Müller shows umlaut, Владимир shows Cyrillic
    And filter schedules by employee with special characters (e.g., select 'José García')
    Then filter works correctly and displays only José García's schedules
    And export schedules to CSV including special character names
    Then cSV file exports with UTF-8 encoding, all special characters are preserved and display correctly when opened
    And export to PDF and verify special characters
    Then pDF displays all special characters correctly with proper font rendering
    And all special characters and Unicode names are preserved across all operations
    And no character encoding errors occur
    And exported files maintain data integrity
    And system handles international characters properly

  @medium @tc-edge-004
  Scenario: TC-EDGE-004 - Verify schedule viewing across different time zones
    Given user is logged in as Administrator
    And schedules exist with shift times in different time zones
    And user's browser is set to a specific time zone (e.g., EST)
    And system stores schedule times in UTC format
    When navigate to schedule viewing page
    Then page loads and displays schedules with times converted to user's local time zone
    And verify a schedule that spans midnight in UTC but not in local time
    Then schedule displays correctly in local time zone without splitting across days incorrectly
    And change browser time zone settings to a different zone (e.g., PST)
    Then after page refresh, all schedule times are recalculated and displayed in the new time zone
    And export schedules to CSV and check time zone handling
    Then cSV includes time zone information or clearly indicates times are in user's local time zone
    And all times are displayed consistently in user's time zone
    And no schedules are lost or duplicated due to time zone conversion
    And time zone handling is documented in exports
    And system maintains data integrity across time zones

  @high @tc-edge-005
  Scenario: TC-EDGE-005 - Verify simultaneous schedule viewing by multiple administrators
    Given multiple administrator users (5+) are logged in simultaneously
    And all administrators navigate to schedule viewing page at the same time
    And database contains 500+ schedules
    And system supports concurrent user sessions
    When have all 5 administrators navigate to schedule viewing page simultaneously
    Then all users successfully load the schedule viewing page within acceptable time (under 5 seconds)
    And each administrator applies different filters simultaneously
    Then each user's filters work independently without affecting other users' views
    And multiple administrators initiate exports at the same time
    Then all export requests are processed successfully, each user receives their own export file without errors
    And monitor system performance during concurrent access
    Then system remains responsive, no timeouts occur, API response times stay under 2 seconds
    And all users successfully viewed and interacted with schedules
    And no data conflicts or race conditions occurred
    And system performance remained within acceptable parameters
    And each user's session remained independent and secure

  @low @tc-edge-006
  Scenario: TC-EDGE-006 - Verify schedule viewing with extremely long employee names and shift descriptions
    Given user is logged in as Administrator
    And database contains schedules with employee names at maximum character limit (e.g., 255 characters)
    And shift type descriptions are also at maximum length
    And schedule viewing page is accessible
    When navigate to schedule viewing page
    Then page loads successfully
    And observe how extremely long employee names are displayed in calendar cells
    Then long names are truncated with ellipsis (...) and full name appears in tooltip on hover
    And click on a schedule entry with long name to view details
    Then detail popup shows full employee name with proper text wrapping, no text overflow outside container
    And filter by employee with extremely long name
    Then dropdown shows truncated name with ellipsis, filter works correctly when selected
    And export schedules with long names to CSV
    Then cSV contains full employee names without truncation, properly escaped if names contain commas or quotes
    And export to PDF and verify layout
    Then pDF handles long names with appropriate text wrapping, layout remains readable and professional
    And uI remains functional and readable with long text
    And no layout breaking or text overflow occurs
    And full data is preserved in exports
    And user experience remains acceptable

