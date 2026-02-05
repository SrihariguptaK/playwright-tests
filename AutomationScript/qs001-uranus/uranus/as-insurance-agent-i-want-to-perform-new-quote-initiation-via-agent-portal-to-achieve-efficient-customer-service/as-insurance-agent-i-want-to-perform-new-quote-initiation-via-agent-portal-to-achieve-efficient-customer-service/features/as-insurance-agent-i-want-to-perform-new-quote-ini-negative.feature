@negative @error-handling
Feature: As Insurance Agent, I want to perform new quote initiation via agent portal to achieve efficient customer service - Negative Tests
  As a user
  I want to test negative tests
  So that I can ensure quality and reliability

  Background:
    Given the system is ready for testing
    And the test environment is properly configured

  @high @tc-nega-001
  Scenario: TC-NEGA-001 - Verify form submission is blocked when mandatory fields are empty
    Given agent is logged into Agent Portal with valid session
    And quote initiation form is displayed and loaded
    And all form fields are empty/default state
    And client-side and server-side validation are active
    When without entering any data, click 'Submit Quote' button directly
    Then form submission is prevented, red error banner appears at top stating 'Please complete all mandatory fields', all mandatory fields are highlighted with red borders
    And scroll through form to view all validation messages
    Then each mandatory field displays specific error message: 'Customer Name is required', 'Policy Type is required', 'Coverage Amount is required', 'Effective Date is required', 'Contact Email is required', 'Phone is required'
    And fill only Customer Name 'John Doe' and leave all other mandatory fields empty, then click 'Submit Quote'
    Then submission still blocked, error banner persists, only Customer Name field shows green validation, remaining mandatory fields still show red borders and error messages
    And check browser network tab for any API calls
    Then no POST request to '/api/agent/quotes' endpoint is made, validation is handled client-side before submission attempt
    And no quote record is created in database
    And form remains in edit mode with entered data preserved
    And agent session remains active
    And no partial or invalid data is persisted

  @high @tc-nega-002
  Scenario: TC-NEGA-002 - Verify system rejects quote submission with SQL injection attempts in text fields
    Given agent is logged into Agent Portal
    And quote initiation form is displayed
    And input sanitization is implemented on backend
    And security logging is enabled
    When enter SQL injection string in Customer Name field: "Robert'; DROP TABLE quotes;--" and fill other mandatory fields with valid data
    Then field accepts input but sanitizes it, no SQL syntax is executed
    And click 'Submit Quote' button
    Then either: (1) Form validation rejects special characters with error 'Customer Name contains invalid characters' OR (2) Submission succeeds but backend sanitizes input, storing safe text only
    And if submission succeeded, search for the created quote and verify stored data
    Then customer Name is stored as sanitized text without SQL syntax, quotes table still exists and is not dropped, database integrity is maintained
    And check security logs for the submission
    Then security event is logged indicating potential SQL injection attempt with agent ID, timestamp, and input string
    And database tables remain intact and undamaged
    And no SQL injection is executed
    And security incident is logged for review
    And application continues to function normally

  @high @tc-nega-003
  Scenario: TC-NEGA-003 - Verify unauthorized access to quote initiation form is prevented
    Given agent Portal application is running
    And user has account with 'Customer' role (not 'Agent' role)
    And role-based access control is implemented
    And oAuth2 authentication is active
    When log in with customer credentials 'customer@email.com' and valid password
    Then login succeeds, customer dashboard is displayed without 'New Quote' option in navigation
    And manually navigate to quote initiation URL by typing '/agent/quotes/new' in browser address bar
    Then access is denied, HTTP 403 Forbidden error page is displayed with message 'You do not have permission to access this resource'
    And attempt to access quote API directly by opening browser console and executing: fetch('/api/agent/quotes', {method: 'POST', body: JSON.stringify({customer: 'Test'})})
    Then aPI returns 403 Forbidden status, response body contains error message 'Insufficient permissions', no quote is created
    And check application logs for access attempt
    Then security log entry created showing unauthorized access attempt with user ID, role, attempted resource, and timestamp
    And no quote is created by unauthorized user
    And user remains logged in with customer role privileges only
    And security event is logged
    And system security is maintained

  @high @tc-nega-004
  Scenario: TC-NEGA-004 - Verify form handles session timeout gracefully during quote creation
    Given agent is logged into Agent Portal
    And quote initiation form is displayed with partial data entered
    And session timeout is configured (e.g., 30 minutes)
    And ability to simulate session expiration
    When fill quote form with valid data: Customer Name 'Session Test', Policy Type 'Auto', Coverage '$30000', Effective Date 'tomorrow', Email 'session@test.com', Phone '555-999-9999'
    Then form accepts all data, fields are populated
    And simulate session timeout by clearing session cookie or waiting for timeout period, then click 'Submit Quote'
    Then submission fails, error message appears: 'Your session has expired. Please log in again.' Form data is temporarily preserved in browser
    And click 'Login' button or link in error message
    Then user is redirected to login page, URL includes return parameter to quote form
    And log in again with valid agent credentials
    Then after successful login, user is redirected back to quote form with previously entered data restored from browser storage
    And click 'Submit Quote' again with restored data
    Then quote submits successfully with new valid session, confirmation and reference number displayed
    And user data is not lost due to session timeout
    And new session is established after re-login
    And quote is successfully created after session renewal
    And user experience is preserved despite timeout

  @medium @tc-nega-005
  Scenario: TC-NEGA-005 - Verify system handles invalid data types in numeric fields
    Given agent is logged into Agent Portal
    And quote initiation form is displayed
    And coverage Amount field expects numeric input
    And field validation is active
    When enter alphabetic characters 'ABCDEF' in Coverage Amount field and tab out
    Then red error message appears: 'Coverage Amount must be a valid number', field border turns red
    And clear field and enter special characters '!@#$%^' in Coverage Amount field
    Then same error message appears, special characters are rejected or field remains invalid
    And clear field and enter negative number '-5000' in Coverage Amount field
    Then error message appears: 'Coverage Amount must be a positive number', validation fails
    And clear field and enter decimal with excessive precision '50000.123456789' in Coverage Amount field
    Then either: (1) Value is auto-formatted to 2 decimal places '50000.12' OR (2) Error message appears: 'Coverage Amount can have maximum 2 decimal places'
    And fill all other mandatory fields with valid data and attempt to submit with invalid Coverage Amount
    Then form submission is blocked, error banner appears, Coverage Amount field is highlighted, focus moves to invalid field
    And no quote is created with invalid numeric data
    And form remains in edit mode for correction
    And all other valid data is preserved
    And data type integrity is maintained

  @medium @tc-nega-006
  Scenario: TC-NEGA-006 - Verify system handles network failure during quote submission
    Given agent is logged into Agent Portal
    And quote form is filled with valid data
    And ability to simulate network disconnection
    And browser developer tools are accessible
    When fill quote form with complete valid data: Customer 'Network Test', Policy 'Home', Coverage '$60000', Date 'next week', Email 'network@test.com', Phone '555-888-8888'
    Then all fields validate successfully with green indicators
    And open browser developer tools, go to Network tab, enable 'Offline' mode to simulate network failure
    Then browser is now in offline mode, no network requests can succeed
    And click 'Submit Quote' button
    Then loading spinner appears briefly, then error message displays: 'Network error. Please check your connection and try again.' Submit button becomes enabled again
    And verify form data is still present in all fields
    Then all entered data remains in form fields, no data is lost
    And disable offline mode to restore network connection and click 'Submit Quote' again
    Then quote submits successfully, confirmation message and reference number displayed
    And form data is preserved during network failure
    And user receives clear error message about network issue
    And quote is successfully created once network is restored
    And no duplicate quotes are created from retry

