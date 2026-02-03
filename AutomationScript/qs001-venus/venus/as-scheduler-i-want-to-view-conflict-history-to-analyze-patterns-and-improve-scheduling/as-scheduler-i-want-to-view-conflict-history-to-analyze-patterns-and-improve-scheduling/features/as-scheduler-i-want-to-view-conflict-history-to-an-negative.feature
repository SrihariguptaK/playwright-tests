@negative @error-handling
Feature: As Scheduler, I want to view conflict history to analyze patterns and improve scheduling - Negative Tests
  As a user
  I want to test negative tests
  So that I can ensure quality and reliability

  Background:
    Given the system is ready for testing
    And the test environment is properly configured

  @high @tc-nega-001
  Scenario: TC-NEGA-001 - Verify system handles invalid date range where start date is after end date
    Given user is logged in as Scheduler on the conflict history page
    And date range filter controls are visible and enabled
    And no filters are currently applied
    And validation rules are active for date range inputs
    When click on the 'Start Date' field and select June 30, 2024
    Then start Date field displays '06/30/2024'
    And click on the 'End Date' field and select June 1, 2024 (earlier than start date)
    Then end Date field displays '06/01/2024'
    And click the 'Apply Filter' button
    Then error message appears in red text below the date fields stating 'End date must be after start date' and filter is not applied
    And verify the conflict history table remains unchanged
    Then table continues to display all conflicts without filtering. No loading spinner appears and no API call is made
    And verify the 'Apply Filter' button remains enabled for correction
    Then apply Filter button is still clickable and date fields remain editable for user to correct the error
    And no filter is applied to the conflict history
    And error message remains visible until user corrects the date range
    And system does not make invalid API requests
    And user can correct the dates and retry filtering

  @high @tc-nega-002
  Scenario: TC-NEGA-002 - Verify system handles unauthorized access attempt to conflict history page
    Given user is logged in with 'Viewer' role that does not have conflict history access permissions
    And user is on the main dashboard page
    And authorization middleware is active and enforcing permissions
    And conflict history page requires 'Scheduler' or 'Admin' role
    When attempt to navigate to conflict history page by typing '/conflict-history' in the browser URL bar
    Then page redirects to an 'Access Denied' error page with message 'You do not have permission to view conflict history. Contact your administrator for access.'
    And verify the conflict history page content is not displayed
    Then no conflict data, filters, or export options are visible. Only the error message and a 'Return to Dashboard' button are shown
    And check browser console for any error logs
    Then console shows 403 Forbidden error with message 'Insufficient permissions for resource /api/conflicts/history'
    And click the 'Return to Dashboard' button
    Then user is redirected back to the main dashboard page they have permission to access
    And user remains logged in but cannot access conflict history
    And no conflict data is exposed to unauthorized user
    And security event is logged in audit trail showing unauthorized access attempt
    And user session remains valid for accessing permitted pages

  @medium @tc-nega-003
  Scenario: TC-NEGA-003 - Verify system handles export attempt when no conflicts match the applied filters
    Given user is logged in as Scheduler on the conflict history page
    And filters are applied that result in zero matching conflicts
    And table displays 'No conflicts found matching your criteria' message
    And export button is visible in the UI
    When apply date range filter for January 1-5, 2020 (a period with no conflicts)
    Then table shows empty state with message 'No conflicts found matching your criteria' and displays 'Showing 0 of 150 conflicts'
    And click the 'Export' button in the top-right corner
    Then export modal opens but displays warning message 'No data available to export. Please adjust your filters to include conflicts.'
    And verify the format selection options are disabled or grayed out
    Then cSV, Excel, and PDF radio buttons are disabled and 'Download' button is grayed out and not clickable
    And click the 'Close' button on the export modal
    Then modal closes and user returns to the empty conflict history table with filters still applied
    And no file is downloaded or generated
    And user remains on conflict history page with filters applied
    And user can modify filters to get results
    And no unnecessary API calls are made for empty export

  @high @tc-nega-004
  Scenario: TC-NEGA-004 - Verify system handles API timeout when retrieving conflict history
    Given user is logged in as Scheduler on the conflict history page
    And network conditions are simulated to cause API timeout (response time > 30 seconds)
    And aPI endpoint GET /api/conflicts/history is configured to timeout
    And user has valid authentication token
    When navigate to the conflict history page by clicking 'Conflict History' in the navigation menu
    Then page loads with loading spinner displayed in the table area showing 'Loading conflict history...'
    And wait for 30 seconds while the API request times out
    Then after timeout period, loading spinner disappears and error message appears: 'Unable to load conflict history. The request timed out. Please try again.'
    And verify a 'Retry' button is displayed below the error message
    Then 'Retry' button with refresh icon is visible and clickable
    And check that no partial or corrupted data is displayed in the table
    Then table area shows only the error message and retry button, with no conflict records or table headers visible
    And click the 'Retry' button to attempt reloading
    Then loading spinner appears again and new API request is initiated to GET /api/conflicts/history
    And user can retry loading the conflict history
    And no corrupted or partial data is cached
    And error is logged in system error logs with timestamp and user details
    And user session remains active and authenticated

  @high @tc-nega-005
  Scenario: TC-NEGA-005 - Verify system handles SQL injection attempt in filter input fields
    Given user is logged in as Scheduler on the conflict history page
    And search or text filter field is available for filtering conflicts
    And input validation and SQL injection prevention measures are active
    And backend uses parameterized queries
    When locate the search/filter text input field for conflict description or resource name
    Then text input field is visible and enabled for user input
    And enter SQL injection string: "' OR '1'='1'; DROP TABLE conflicts; --" in the search field
    Then input is accepted in the field and displays the entered text
    And click the 'Apply Filter' or 'Search' button
    Then system treats the input as literal search text, not SQL code. Either returns no results or results matching the literal string. No database error occurs
    And verify the conflicts table is still functional and database is intact
    Then table loads normally when filters are cleared. No database tables are dropped or modified. System logs show sanitized query was executed
    And check system security logs for injection attempt detection
    Then security log contains entry flagging potential SQL injection attempt with user ID, timestamp, and input string
    And database remains intact with no tables dropped or modified
    And conflict history data is unchanged and accessible
    And security incident is logged for review
    And user account may be flagged for security review depending on policy

  @high @tc-nega-006
  Scenario: TC-NEGA-006 - Verify system handles session expiration during conflict history interaction
    Given user is logged in as Scheduler on the conflict history page
    And user session is set to expire in 1 minute
    And conflict history page is loaded with data displayed
    And session timeout middleware is active
    When wait for user session to expire (simulate by clearing auth token or waiting for timeout)
    Then session expires after configured timeout period
    And attempt to apply a filter by selecting a date range and clicking 'Apply Filter'
    Then aPI request returns 401 Unauthorized error. Modal or notification appears stating 'Your session has expired. Please log in again to continue.'
    And verify user is redirected to login page after clicking 'OK' on the session expiration message
    Then user is redirected to login page with return URL parameter set to /conflict-history for post-login redirect
    And verify no conflict data remains visible on the page
    Then all conflict data is cleared from the UI and no sensitive information is accessible without authentication
    And user is logged out and on the login page
    And no authenticated API calls can be made
    And user must re-authenticate to access conflict history
    And after successful login, user can be redirected back to conflict history page

