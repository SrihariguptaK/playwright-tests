Feature: Task Commenting Validation and Error Handling
  As an Employee
  I want the system to validate and handle errors when commenting on tasks
  So that data integrity is maintained and I receive clear feedback on invalid submissions

  Background:
    Given user is logged in as authenticated employee
    And user is on task details page

  @negative @regression @priority-high
  Scenario: System rejects comment submission when character limit exceeds 500 characters
    Given comment input field is empty and ready for input
    And validation rules are configured to enforce 500 character maximum
    When user clicks on comment input field
    Then character counter should show "0/500"
    When user enters comment with 501 characters in comment input field
    Then character counter should show "501/500" in red color
    And error message "Comment exceeds maximum length of 500 characters" should be displayed below input field in red text
    When user clicks "Save" button
    Then save button should be disabled or show validation error "Please reduce comment to 500 characters or less"
    And comment should not be submitted
    When user deletes 2 characters from comment
    Then character counter should show "500/500"
    And error message should disappear
    And "Save" button should be enabled
    And no comment should be saved in database
    And no API call should be made to POST endpoint

  @negative @regression @priority-high
  Scenario Outline: System rejects empty or whitespace-only comment submission
    Given comment input field is visible and empty
    And validation rules require non-empty comment text
    When user clicks on comment input field
    Then character counter should show "0/500"
    When user enters "<comment_text>" in comment input field
    Then character counter should show "<character_count>"
    When user clicks "Save" button
    Then error message "<error_message>" should be displayed in red below input field
    And comment should not be submitted
    And no empty or whitespace-only comments should be saved in database
    And no notifications should be sent to team members
    And API endpoint should not be called

    Examples:
      | comment_text                    | character_count | error_message                              |
      |                                 | 0/500           | Comment cannot be empty                    |
      |                                 | 8/500           | Comment cannot contain only whitespace     |

  @negative @regression @priority-high
  Scenario: System rejects valid comment after entering whitespace-only text
    Given comment input field is visible and empty
    And validation rules require non-empty comment text
    When user clicks on comment input field
    And user enters only whitespace characters with 5 spaces and 3 tabs in comment input field
    Then character counter should show "8/500"
    And input should appear empty visually
    When user clicks "Save" button
    Then error message "Comment cannot contain only whitespace" should be displayed
    And comment should not be submitted
    When user enters "Valid comment text" in comment input field
    Then error message should disappear
    And character counter should show "18/500"
    And "Save" button should be enabled

  @negative @regression @priority-high
  Scenario: System prevents unauthenticated users from submitting comments
    Given user session has expired or been invalidated
    And comment input field is visible on page
    And API endpoint requires valid authentication token
    When user session is manually expired by clearing authentication token
    Then session should be expired but user remains on current page
    When user enters "Testing unauthenticated access" in comment input field
    Then character counter should show "32/500"
    When user clicks "Save" button
    Then error message "Your session has expired. Please log in again." should be displayed
    And user should be redirected to login page
    And API should return HTTP status 401 with error message "Authentication required"
    And no comment should be saved in database
    And return URL should be set to current task details page
    And comment text should not be persisted after redirect
    And security audit log should record unauthorized access attempt

  @negative @regression @priority-high
  Scenario: System handles API endpoint failure gracefully with appropriate error message
    Given network connection is active but API server is experiencing issues
    And browser developer tools are open
    When user enables network throttling to "Offline" mode in developer tools
    Then network should be set to offline mode
    When user enters "Testing network failure scenario" in comment input field
    Then character counter should show "34/500"
    When user clicks "Save" button
    Then loading indicator should appear briefly
    And error message "Unable to save comment. Please check your connection and try again." should be displayed in red banner at top of page
    And no comment should be saved in database
    And comment text should remain in input field
    And user should remain on task details page
    When user disables offline mode
    And user clicks "Save" button
    Then success message "Comment added successfully" should be displayed

  @negative @regression @priority-high
  Scenario: System rejects comment submission with SQL injection attempts
    Given input validation and SQL injection prevention measures are implemented
    And database has existing comments and task data
    When user clicks on comment input field
    Then character counter should show "0/500"
    When user enters "'; DROP TABLE comments; --" in comment input field
    Then character counter should show "29/500"
    When user clicks "Save" button
    Then comment should be saved as plain text string without executing SQL or validation error "Invalid characters detected" should appear
    And database table should be intact
    And all existing comments should be visible on page
    And no data loss should occur
    And SQL injection attempt should be logged in security audit log
    And database integrity should be maintained

  @negative @regression @priority-medium
  Scenario: System handles database connection failure during comment submission
    Given database connection can be simulated to fail or timeout
    And error handling is implemented for database failures
    When database connection failure is simulated at server level
    Then database should become unavailable for write operations
    When user enters "Testing database failure handling" in comment input field
    Then character counter should show "35/500"
    When user clicks "Save" button
    Then loading indicator should appear
    And error message "Unable to save comment due to system error. Please try again later." should be displayed in red banner
    And API should return HTTP status 503 or 500 with error details
    And no partial or corrupted data should be written to database
    And comment text should remain in input field
    And user session should remain active and valid
    When database connection is restored
    And user clicks "Save" button
    Then success message should be displayed
    And comment should be successfully saved

  @negative @regression @priority-medium
  Scenario: System rejects comment submission for non-existent task ID
    Given user has navigated to task details page URL with invalid task ID "99999"
    And task ID "99999" does not exist in database
    And API endpoint validates task existence before accepting comments
    When user navigates to "/tasks/99999/details" URL
    Then page should show "404 Task Not Found" error or "Task does not exist" message
    When comment input field is visible
    And user enters "Testing invalid task ID" in comment input field
    And user clicks "Save" button
    Then error message "Cannot add comment: Task not found" should be displayed in red banner
    And API should return HTTP status 404 with error message "Task with ID 99999 does not exist"
    And no comment record should be created in database
    And no notifications should be sent to team members
    And database referential integrity should be maintained with no orphaned comment records