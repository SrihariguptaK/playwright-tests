Feature: Input Validation Testing
  As a QA Tester
  I want to perform comprehensive validation testing
  So that I can ensure input validation behaves as expected and provides robust data quality

  @functional @regression @priority-high @client-side
  Scenario: Verify client-side real-time validation displays error messages for required fields
    Given test environment is accessible and functional
    And user is logged in with "QA Tester" role permissions
    And test form with validation rules is loaded in browser
    And browser console is open to monitor client-side validation events
    And test data set with valid and invalid inputs is prepared
    When user navigates to test form page containing input fields with validation rules
    Then form page loads successfully with all input fields visible and empty
    When user clicks into "Email Address" required field
    And user clicks outside field without entering any data
    Then error message "Email Address is required" appears immediately below field with error icon
    And error message should be displayed in red color
    When user enters "testuser@example.com" in "Email Address" field
    Then error message disappears
    And field border changes to green
    And success checkmark icon appears
    When user clicks into "Phone Number" required field
    And user enters "555-1234" in "Phone Number" field
    And user deletes all characters from "Phone Number" field
    Then error message "Phone Number is required" displays immediately with error icon
    When user verifies error message styling
    Then error message has red text color "#D32F2F"
    And error message includes error icon
    And error message has "aria-live" attribute with value "polite"
    And error message has "role" attribute with value "alert"
    And form remains in editable state with validation active
    And browser console shows no JavaScript errors related to validation

  @functional @regression @priority-high @server-side
  Scenario: Verify server-side validation rejects invalid data with appropriate HTTP error responses
    Given test API endpoint is accessible and responding
    And user has valid authentication token for API requests
    And API testing tool is configured with test environment
    And test database is in known state with existing test records
    And network monitoring tool is active to capture request response
    When user sends POST request to "/api/users" endpoint with payload containing invalid email format
    Then server returns HTTP status code 400
    And response contains error message "Invalid email format"
    And response contains field name "email"
    When user sends POST request with missing required field "name"
    Then server returns HTTP status code 400
    And response contains error message "Name is required"
    And response contains field name "name"
    When user sends POST request with valid data
    Then server returns HTTP status code 201
    And response contains created user object with unique ID
    When user verifies database to confirm invalid data was not persisted
    Then database query shows no records created for invalid requests
    And database contains only valid data from successful requests
    When user checks server logs for validation error entries
    Then server logs contain validation error entries with severity level "WARNING"
    And server logs contain timestamp and rejected payload details
    And API returns consistent error response format across all validation failures

  @functional @regression @priority-high @error-messages
  Scenario Outline: Verify validation error messages are accurate clear and user-friendly across all form fields
    Given test form with multiple field types is loaded
    And user is logged in and has access to form
    And error message content specification document is available for reference
    And browser is set to default language "English"
    When user leaves "<field_name>" required field empty
    And user clicks "Submit" button
    Then error message "<error_message>" appears in red text below field
    And error message uses clear non-technical language
    And error message uses red color "#D32F2F"
    And error message appears below respective field
    And error message uses font size "14px"
    And error message includes error icon
    And form remains in editable state allowing users to correct errors

    Examples:
      | field_name | error_message                                                    |
      | Username   | Username is required                                             |
      | Email      | Please enter a valid email address (e.g., user@example.com)      |
      | Age        | Age must be a positive number                                    |
      | Birth Date | Birth Date cannot be in the future                               |

  @functional @regression @priority-high @error-messages @length-validation
  Scenario: Verify field length validation displays accurate error messages with character count
    Given test form with multiple field types is loaded
    And user is logged in and has access to form
    When user enters "ab" in "Username" field that requires minimum 3 characters
    Then error message "Username must be at least 3 characters long" displays
    And current character count indicator is visible

  @functional @regression @priority-high @error-messages @format-validation
  Scenario: Verify email format validation displays helpful error message with example
    Given test form with multiple field types is loaded
    And user is logged in and has access to form
    When user enters "test@invalid" in "Email" field
    And user moves focus to next field
    Then error message "Please enter a valid email address (e.g., user@example.com)" appears with example format

  @functional @regression @priority-high @error-messages @numeric-validation
  Scenario: Verify numeric field validation rejects negative values with clear error message
    Given test form with multiple field types is loaded
    And user is logged in and has access to form
    When user enters "-50" in "Age" field that requires positive numbers only
    Then error message "Age must be a positive number" displays immediately upon input

  @functional @regression @priority-high @error-messages @date-validation
  Scenario: Verify date field validation prevents future dates with clear instruction
    Given test form with multiple field types is loaded
    And user is logged in and has access to form
    When user selects future date in "Birth Date" field that should be in past
    Then error message "Birth Date cannot be in the future" appears with calendar icon and clear instruction

  @functional @regression @priority-high @performance @load-testing
  Scenario: Verify validation features perform correctly under simulated high load conditions with 100 concurrent users
    Given load testing tool is configured with test scripts
    And test environment is isolated from production
    And baseline performance metrics are documented
    And server monitoring tools are active
    And test data set with 1000 unique validation scenarios is prepared
    When user configures load test to simulate 100 concurrent users submitting forms with validation errors over 5 minutes
    Then load test configuration is saved and ready to execute
    When user executes load test
    And user monitors server response times for validation error responses
    Then 95th percentile response time remains under 500 milliseconds throughout test duration
    And server continues to process validation requests
    And no timeouts occur
    When user reviews server resource utilization during peak load
    Then CPU usage stays below 80 percent
    And memory usage stays below 75 percent
    And database connection pool has available connections
    When user verifies validation error messages during high load conditions
    Then random sampling of 50 responses shows 100 percent accuracy in validation error messages
    And no truncation or corruption is detected
    When user checks application logs for validation-related errors
    Then logs show no critical errors
    And logs show no validation logic failures
    And logs show no database deadlocks or connection issues
    And system returns to normal performance levels after load test completion
    And no data corruption occurred during high load

  @functional @regression @priority-high @performance @load-testing @stress-test
  Scenario: Verify validation features handle increased load of 500 concurrent users
    Given load testing tool is configured with test scripts
    And test environment is isolated from production
    And baseline performance metrics are documented
    And server monitoring tools are active
    And test data set with 1000 unique validation scenarios is prepared
    When user increases load to 500 concurrent users
    And user monitors validation processing performance
    Then server continues to process validation requests with 95th percentile response time under 1000 milliseconds
    And no timeouts occur

  @functional @regression @priority-high @accessibility @wcag
  Scenario: Verify accessibility compliance of validation feedback elements using automated and manual testing
    Given test form is loaded in browser with accessibility testing extensions installed
    And screen reader software is installed and configured
    And keyboard navigation is enabled
    And WCAG 2.1 Level AA compliance checklist is available
    And color contrast analyzer tool is ready
    When user runs axe DevTools automated accessibility scan on form page with validation errors displayed
    Then scan completes with zero critical or serious accessibility violations related to validation elements
    When user uses keyboard only to navigate through form fields and trigger validation errors
    Then all form fields are reachable via keyboard
    And validation errors trigger on blur
    And focus indicator is visible with "3px" blue outline
    When user activates NVDA screen reader
    And user navigates to field with validation error using Tab key
    Then screen reader announces field label current value error state and error message
    When user verifies error messages have proper ARIA attributes by inspecting DOM
    Then error container has "aria-live" attribute with value "polite"
    And input field has "aria-invalid" attribute with value "true"
    And "aria-describedby" links to error message ID
    When user uses color contrast analyzer to check error message text color against background
    Then error text "#D32F2F" against white background "#FFFFFF" has contrast ratio of at least 4.5:1
    And contrast ratio meets WCAG AA standards
    When user tests with browser zoom at 200 percent
    Then error messages scale properly
    And error messages remain positioned correctly below fields
    And text does not overlap or truncate
    And all validation feedback elements meet WCAG 2.1 Level AA compliance

  @functional @regression @priority-medium @test-coverage
  Scenario: Verify validation test case execution coverage reaches 100 percent of defined test scenarios
    Given complete test case repository is available in test management tool
    And all validation requirements are documented with traceability matrix
    And test execution environment is stable and accessible
    And test data for all scenarios is prepared and validated
    And defect tracking system is configured and accessible
    When user generates test coverage report from test management tool showing all validation-related test cases
    Then report displays total of 150 validation test cases across functional negative edge case and accessibility categories
    When user executes all 150 validation test cases systematically
    And user marks each test case as Pass Fail or Blocked in test management tool
    Then all test cases are executed with results recorded
    And execution progress shows 100 percent completion
    When user generates requirements traceability matrix to verify all acceptance criteria are covered by executed tests
    Then traceability matrix shows 100 percent coverage
    And all 5 acceptance criteria are mapped to executed test cases with Pass status
    When user reviews test execution summary to identify any failed or blocked test cases
    Then summary report shows pass rate
    And failed test cases are logged as defects with severity and priority assigned
    When user verifies all identified defects are tracked in defect management system
    Then all defects have unique IDs
    And all defects are assigned to developers
    And all defects include reproduction steps
    And all defects are linked to failed test cases
    And 100 percent of validation test cases have been executed with documented results
    And test coverage report confirms all acceptance criteria are validated