@negative @error-handling
Feature: As Scheduler, I want to receive notifications for recurring conflicts to proactively manage scheduling - Negative Tests
  As a user
  I want to test negative tests
  So that I can ensure quality and reliability

  Background:
    Given the system is ready for testing
    And the test environment is properly configured

  @high @tc-nega-001
  Scenario: TC-NEGA-001 - Verify system handles unauthorized access to recurring conflict notifications gracefully
    Given user is not logged in (no authentication token present)
    And browser has cleared all cookies and session storage
    And aPI endpoint GET /api/conflicts/recurring is active
    And system has recurring conflicts in database
    When attempt to send GET request to /api/conflicts/recurring without authentication token in header
    Then aPI responds with HTTP status code 401 Unauthorized
    And examine the error response body
    Then response contains JSON with error message: 'Authentication required. Please log in to access recurring conflict notifications' and errorCode: 'AUTH_REQUIRED'
    And attempt to access notification preferences page by directly entering URL /settings/notifications without being logged in
    Then system redirects to login page with message 'Please log in to access notification settings' and returnUrl parameter set to /settings/notifications
    And try to access notification panel UI component without valid session
    Then notification bell icon is either hidden or disabled, clicking it shows tooltip 'Login required to view notifications'
    And no sensitive conflict data is exposed to unauthenticated user
    And failed authentication attempt is logged in security audit log
    And user remains on login page or public area of application
    And no session or token is created

  @high @tc-nega-002
  Scenario: TC-NEGA-002 - Verify system handles expired authentication token when accessing recurring conflicts
    Given user was previously logged in with valid authentication token
    And authentication token has expired (past expiration timestamp)
    And user is on the Scheduling Dashboard page
    And browser still has expired token in local storage
    When click on the notification bell icon to view recurring conflict notifications
    Then system attempts to fetch notifications using expired token
    And observe the API response and UI behavior
    Then aPI returns HTTP status code 401 Unauthorized with message 'Session expired. Please log in again', and UI displays modal dialog with message 'Your session has expired for security reasons'
    And click 'Login Again' button in the modal dialog
    Then user is redirected to login page, expired token is cleared from local storage, and returnUrl is set to current page
    And after redirect, verify that no notification data was cached or displayed
    Then no recurring conflict data is visible, notification panel is empty, and no sensitive information remains in browser memory or DOM
    And expired token is removed from local storage and session
    And user is logged out and redirected to login page
    And security event is logged with details of expired token access attempt
    And no recurring conflict data is accessible until re-authentication

  @medium @tc-nega-003
  Scenario: TC-NEGA-003 - Verify system handles insufficient historical data for recurring conflict detection
    Given user is logged in as Scheduler
    And historical conflict database contains only 1 instance of a specific conflict pattern (below threshold of 3 required for recurring classification)
    And user has notifications enabled
    And system is configured to require minimum 3 occurrences to classify as recurring
    When trigger the same conflict pattern for the 2nd time (still below threshold of 3)
    Then system detects the conflict but does not classify it as recurring, no recurring conflict notification is generated
    And check the notification panel for recurring conflict alerts
    Then notification panel shows standard conflict notification (not recurring), with message 'Scheduling conflict detected' without recurring pattern information
    And send GET request to /api/conflicts/recurring
    Then aPI returns HTTP status code 200 OK with empty array [] or message 'No recurring conflicts detected yet' since threshold is not met
    And trigger the same conflict pattern for the 3rd time (meeting threshold)
    Then system now classifies it as recurring and generates recurring conflict notification with message 'Recurring pattern detected: This conflict has occurred 3 times'
    And system correctly applies threshold logic for recurring classification
    And no false positive recurring conflict notifications are sent
    And conflict data is stored in historical database for future pattern analysis
    And user receives appropriate notification type based on occurrence count

  @medium @tc-nega-004
  Scenario: TC-NEGA-004 - Verify system handles invalid notification preference values gracefully
    Given user is logged in as Scheduler
    And user is on the Notification Preferences page
    And browser developer tools are open to manipulate form data
    And current preferences are set to valid default values
    When using browser developer tools, modify the notification frequency dropdown value to an invalid option 'InvalidFrequency' before submitting
    Then form validation detects invalid value before submission
    And click 'Save Preferences' button with the manipulated invalid value
    Then client-side validation displays error message 'Invalid notification frequency selected. Please choose a valid option: Immediate, Daily Digest, or Weekly Digest' in red text below the dropdown
    And bypass client-side validation and send POST request directly to API with payload containing invalid frequency value
    Then aPI responds with HTTP status code 400 Bad Request and error message 'Invalid notification frequency value. Accepted values: immediate, daily, weekly'
    And verify that preferences were not saved by refreshing the page
    Then notification preferences page loads with previous valid settings intact, invalid values were rejected and not persisted to database
    And check system logs for validation error
    Then validation error is logged with timestamp, user ID, attempted invalid value, and rejection reason
    And user preferences remain unchanged with previous valid values
    And no invalid data is stored in the database
    And validation error is logged for security monitoring
    And user remains on Notification Preferences page with error message displayed

  @high @tc-nega-005
  Scenario: TC-NEGA-005 - Verify system handles API timeout when fetching recurring conflicts
    Given user is logged in as Scheduler
    And network conditions are simulated to cause API timeout (using browser dev tools or proxy)
    And aPI endpoint GET /api/conflicts/recurring is configured with 5-second timeout
    And user is on Scheduling Dashboard attempting to view notifications
    When enable network throttling in browser developer tools to simulate slow connection (e.g., 50 Kbps)
    Then network throttling is active as shown in developer tools network tab
    And click on notification bell icon to fetch recurring conflict notifications
    Then loading spinner appears in notification panel indicating data is being fetched
    And wait for API request to exceed 5-second timeout threshold
    Then after 5 seconds, loading spinner disappears and error message displays: 'Unable to load notifications. Request timed out. Please try again.'
    And observe the notification panel UI
    Then panel shows 'Retry' button and 'Close' button, no partial or corrupted data is displayed, previous notifications (if any) remain visible
    And click 'Retry' button to attempt fetching notifications again
    Then new API request is initiated, loading spinner appears again, and system attempts to fetch data with fresh timeout window
    And no application crash or freeze occurs due to timeout
    And user can retry the operation without refreshing the page
    And timeout error is logged in system error logs with request details
    And user remains logged in and can continue using other features

  @high @tc-nega-006
  Scenario: TC-NEGA-006 - Verify system prevents SQL injection attempts in recurring conflict queries
    Given user is logged in as Scheduler
    And system has search or filter functionality for recurring conflicts
    And database contains recurring conflict records
    And application uses parameterized queries for database access
    When navigate to recurring conflicts search page or filter interface
    Then search interface loads with input field for filtering conflicts by resource name or other criteria
    And enter SQL injection payload in search field: "' OR '1'='1" and submit search
    Then system sanitizes input and treats entire string as literal search term, no SQL injection occurs
    And observe search results
    Then either no results found (if no resource matches the literal string) or only legitimate results matching the sanitized search term, no unauthorized data exposure
    And attempt another injection payload: "'; DROP TABLE conflicts; --" in the search field
    Then input is sanitized, parameterized query prevents execution of DROP command, search executes safely without database modification
    And check database integrity and system logs
    Then database tables remain intact, no data loss, security log records the injection attempt with user ID, timestamp, and attempted payload
    And database remains secure and unmodified
    And all conflict data is intact and accessible
    And security incident is logged for review
    And user account may be flagged for suspicious activity depending on security policy

