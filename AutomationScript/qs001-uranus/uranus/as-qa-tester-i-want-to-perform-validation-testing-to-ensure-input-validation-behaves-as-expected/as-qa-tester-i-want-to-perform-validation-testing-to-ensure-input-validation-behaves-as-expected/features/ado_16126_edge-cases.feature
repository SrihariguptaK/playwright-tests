Feature: Input Validation Edge Cases Testing
  As a QA Tester
  I want to perform comprehensive edge case validation testing
  So that I can ensure input validation behaves correctly under boundary conditions and extreme scenarios

  Background:
    Given user is logged in with "QA Tester" role
    And user has access to the input validation test form

  @edge @regression @priority-high @TC-EDGE-001
  Scenario: Validate character limit boundary values for text input fields
    Given browser developer tools are open to monitor client-side validation
    And test data includes strings at exact max length, max+1, and max-1 characters
    When user navigates to "Input Validation Test Form" page
    Then form should load successfully with all input fields visible and empty
    When user enters string with exactly "255" characters in character-limited text field
    Then input should be accepted
    And character counter should display "255/255"
    And no validation error should appear
    When user attempts to enter one additional character beyond maximum limit
    Then client-side validation should prevent input or display error message
    And error message "Maximum character limit reached" should be displayed
    And field should show red border
    When user clears the field
    And user enters string with "254" characters in character-limited text field
    Then input should be accepted
    And character counter should display "254/255"
    And no validation error should appear
    And field should remain valid
    When user clicks "Submit" button
    Then form should submit successfully
    And server should accept the data
    And success message "Data saved successfully" should be displayed
    And data with boundary values should be correctly stored in database
    And no client-side or server-side errors should be logged

  @edge @regression @priority-high @TC-EDGE-002
  Scenario Outline: Validate special characters, Unicode, and emoji inputs
    Given test form with text input fields is accessible
    And database supports UTF-8 encoding
    When user navigates to "Input Validation Test Form" page
    Then form should display with all input fields ready for data entry
    When user enters "<input_value>" in "<field_name>" field
    Then characters should be accepted
    And no validation error should appear
    And field should display entered characters correctly
    And text should render in proper direction for language
    When user clicks "Submit" button
    Then form should submit successfully
    And server-side validation should accept the data
    And success confirmation should appear
    When user retrieves the saved data
    Then all characters should be correctly stored and displayed without corruption
    And data integrity should be maintained across save and retrieval operations
    And no character encoding errors should be logged in server logs

    Examples:
      | field_name              | input_value                           |
      | Special Characters      | !@#$%^&*()_+-=[]{}|;:,.<>?/          |
      | Unicode Text            | 中文测试 العربية テスト                |
      | Emoji Characters        | 😀🎉🚀💯                              |
      | Mixed Special Unicode   | Test!@# 中文 😀                       |

  @edge @regression @priority-high @TC-EDGE-003
  Scenario: Validate form behavior with rapid successive submissions
    Given test form with submit button is accessible
    And network throttling is disabled for maximum submission speed
    And server-side duplicate submission prevention is implemented
    When user navigates to "Input Validation Test Form" page
    Then form should load successfully with submit button enabled
    When user fills in all required fields with valid test data
    Then all fields should accept input
    And no validation errors should appear
    And submit button should remain enabled
    When user clicks "Submit" button rapidly "5" times within "1" second
    Then submit button should become disabled after first click
    And subsequent clicks should be ignored
    And loading indicator should appear
    And only one POST request should be sent to server
    And no duplicate submissions should occur
    When user waits for server response
    Then single success message "Data submitted successfully" should be displayed
    And no duplicate success messages should appear
    And only one record should be created in database
    And no duplicate entries should exist
    And submit button should be re-enabled after response is received

  @edge @regression @priority-high @TC-EDGE-004
  Scenario Outline: Validate empty, null, and whitespace-only inputs
    Given test form with required and optional fields is accessible
    And client-side and server-side validation are both active
    When user navigates to "Input Validation Test Form" page
    Then form should display with required fields marked with asterisk or "Required" label
    When user enters "<input_value>" in "<field_type>" field
    And user clicks "Submit" button
    Then validation should behave as "<validation_behavior>"
    And message "<expected_message>" should be displayed
    And field border should be "<border_color>"

    Examples:
      | field_type        | input_value          | validation_behavior           | expected_message                                              | border_color |
      | Required          |                      | prevent_submission            | This field is required                                        | red          |
      | Required          |                      | show_error                    | This field cannot be empty or contain only spaces             | red          |
      | Required          | valid data           | accept_and_trim               | Data saved successfully                                       | default      |
      | Optional          |                      | accept_empty                  | Data saved successfully                                       | default      |

  @edge @regression @priority-high @TC-EDGE-004
  Scenario: Validate whitespace handling in required fields
    Given test form with required and optional fields is accessible
    And client-side and server-side validation are both active
    When user navigates to "Input Validation Test Form" page
    Then form should display with required fields marked with asterisk or "Required" label
    When user leaves all required fields completely empty
    And user clicks "Submit" button
    Then client-side validation should prevent submission
    And error message "This field is required" should appear below each required field
    And fields should show red borders
    When user enters only whitespace characters "     " in required text field
    Then client-side validation should detect whitespace-only input
    And error message "This field cannot be empty or contain only spaces" should be displayed
    When user enters valid data in all required fields
    And user leaves optional fields empty
    And user clicks "Submit" button
    Then form should submit successfully
    And server should accept empty optional fields
    And success message should appear
    When user uses browser developer tools to set field value to null
    And user clicks "Submit" button
    Then server-side validation should reject null values for required fields
    And error response "Invalid data: required field cannot be null" should be returned
    When user enters "  valid data  " with leading and trailing whitespace in text field
    And user clicks "Submit" button
    Then server should trim whitespace automatically
    And data should be saved as "valid data" without leading or trailing spaces

  @edge @regression @priority-high @TC-EDGE-005
  Scenario: Validate performance under simulated high concurrent load
    Given load testing tool is configured and ready
    And test environment can handle concurrent requests
    And test data set with "1000" valid and invalid input combinations is prepared
    And server monitoring tools are active to track response times and errors
    When user configures load testing tool to simulate "100" concurrent users submitting forms simultaneously
    Then load test configuration should be saved and validated
    When user executes load test with "50" percent valid inputs and "50" percent invalid inputs over "5" minutes
    Then load test should run successfully
    And all requests should be sent to server
    And average response time should remain under "2" seconds
    And 95th percentile response time should remain under "5" seconds
    And no timeouts should occur
    And all invalid inputs should receive appropriate error responses with HTTP status code "400"
    And error messages should be accurate
    And all valid inputs should receive success responses with HTTP status code "200"
    And data should be correctly saved to database
    When user checks server logs and error logs
    Then no server errors, crashes, or validation logic failures should be logged
    And system should remain stable throughout test
    When user verifies data integrity in database
    Then database should contain exactly the number of valid submissions
    And no data corruption or duplicate entries should exist
    And validation system should perform correctly under high concurrent load
    And server should remain stable and responsive after load test completes

  @edge @regression @priority-medium @TC-EDGE-006
  Scenario Outline: Validate behavior across different browsers and browser versions
    Given test environment has access to multiple browsers
    And test form with various input types is accessible
    And user is logged in with "QA Tester" role in "<browser>" browser
    When user opens validation test form in "<browser>" browser
    Then form should load correctly
    And all input fields and validation messages should display properly
    When user enters invalid email format "test@invalid" in email field
    And user tabs out of field
    Then client-side validation should trigger
    And error message "Please enter a valid email address" should be displayed
    And field should show red border
    When user enters value outside min-max range in number field
    Then browser should enforce min-max constraints
    And validation message should appear
    When user enters invalid date in date picker field
    Then date validation should work correctly
    And invalid dates should be rejected with appropriate error messages
    And validation behavior should be consistent across all browsers
    And user experience should be uniform regardless of browser choice

    Examples:
      | browser         |
      | Chrome          |
      | Firefox         |
      | Safari          |
      | Edge            |

  @edge @regression @priority-medium @TC-EDGE-007
  Scenario Outline: Validate extremely large data sets and file uploads
    Given test form includes file upload field and large text area
    And server has file size limit configured as "<max_size_mb>" MB
    When user navigates to form with file upload validation
    Then form should display with file upload field showing accepted file types and size limit message
    When user attempts to upload file with size "<file_size_mb>" MB
    Then validation should behave as "<validation_result>"
    And message "<expected_message>" should be displayed

    Examples:
      | file_size_mb | max_size_mb | validation_result | expected_message                                    |
      | 50           | 25          | reject            | File size exceeds maximum limit of 25MB             |
      | 25           | 25          | accept            | File uploaded successfully                          |
      | 10           | 25          | accept            | File uploaded successfully                          |

  @edge @regression @priority-medium @TC-EDGE-007
  Scenario: Validate large text input and server-side file size enforcement
    Given test form includes file upload field and large text area
    And server has file size limit configured as "25" MB
    When user navigates to form with file upload validation
    Then form should display with file upload field showing accepted file types and size limit message
    When user uploads file at exactly maximum allowed size of "25" MB
    Then file upload should begin
    And progress bar should show upload progress
    And file should be accepted without error
    When user enters extremely large text with "100000" characters into text area field
    Then text area should accept input up to its limit
    And character counter should update correctly
    And performance should remain smooth without browser lag
    When user clicks "Submit" button
    Then form should submit successfully
    And loading indicator should show progress
    And server should process request within "30" seconds
    When user bypasses client-side checks and sends oversized file via API
    Then server-side validation should reject the request
    And HTTP status code "413" should be returned
    And error message "File size exceeds server limit" should be displayed
    And large valid files and text should be successfully uploaded and stored
    And system performance should remain stable when handling large data