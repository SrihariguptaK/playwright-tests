Feature: Task Commenting Edge Cases
  As an Employee
  I want to handle edge cases when commenting on tasks
  So that the system remains stable and reliable under unusual conditions

  Background:
    Given user is logged in as an authenticated employee
    And user is on the task details page for an existing task
    And comment input field is visible and enabled

  @edge @regression @priority-high
  Scenario: Comment submission with exactly 500 characters at maximum boundary
    Given browser has JavaScript enabled and network connectivity is stable
    When user clicks on "Comment" input field
    Then "Comment" input field should be focused with visible cursor
    When user enters 500 characters in "Comment" input field
    Then character counter should display "500/500"
    When user clicks "Save" button
    Then success message "Comment added successfully" should be displayed
    And "Save" button should be disabled during submission
    And user waits for comment to appear in comments section
    Then comment with 500 characters should be displayed in chronological order
    And comment should display timestamp and author name
    And comment text should not be truncated

  @edge @regression @priority-medium
  Scenario: Comment submission with special characters Unicode and emojis
    Given comment input field supports UTF-8 encoding
    And database is configured to handle Unicode characters
    When user clicks on "Comment" input field
    Then "Comment" input field should be focused
    When user enters "Test @#$%^&*()_+-={}[]|\:;<>?,./~` and Unicode: 你好 مرحبا Привет and emojis: 😀🎉✅❌" in "Comment" input field
    Then all special characters and Unicode should be displayed correctly in input field
    When user clicks "Save" button
    Then success message "Comment added successfully" should be displayed
    And comment should be displayed in comments section
    And all special characters should be rendered correctly
    And all Unicode text should be rendered correctly
    And all emojis should be rendered correctly without encoding issues

  @edge @regression @priority-high
  Scenario: Rapid successive comment submissions for performance testing
    Given network connection is stable with normal latency
    And no rate limiting is configured on API endpoint
    When user enters "Comment 1" in "Comment" input field
    And user clicks "Save" button
    Then "Save" button should be disabled during processing
    When user waits for comment to appear in comments section
    And user enters "Comment 2" in "Comment" input field
    And user clicks "Save" button
    And user waits for comment to appear in comments section
    And user enters "Comment 3" in "Comment" input field
    And user clicks "Save" button
    And user waits for comment to appear in comments section
    And user enters "Comment 4" in "Comment" input field
    And user clicks "Save" button
    And user waits for comment to appear in comments section
    And user enters "Comment 5" in "Comment" input field
    And user clicks "Save" button
    Then all 5 comments should be displayed in chronological order
    And comments should be displayed within 2 seconds
    And all comments should have accurate timestamps
    And no duplicate comments should exist
    And system performance should remain stable

  @edge @regression @priority-medium
  Scenario: Comment submission with whitespace-only content
    Given comment input field has validation enabled
    And system has whitespace validation rules configured
    When user clicks on "Comment" input field
    Then "Comment" input field should be focused with cursor visible
    When user enters whitespace with 20 spaces 5 tabs and 3 newlines in "Comment" input field
    And user clicks "Save" button
    Then error message "Comment cannot be empty or contain only whitespace" should be displayed
    And error message should be displayed in red text
    And comment should not be submitted
    And no new comment should appear in comments section
    And existing comments should remain unchanged
    And "Comment" input field should remain focused

  @edge @regression @priority-medium
  Scenario: Comment display with very large number of existing comments
    Given task has 150 existing comments in database
    And browser has sufficient memory and rendering capability
    When user navigates to task details page with 150 comments
    Then page should load within 2 seconds
    And all comments should be rendered in chronological order
    And browser should not freeze during rendering
    When user scrolls through comments section from top to bottom
    Then scrolling should be smooth without lag
    And all comments should be visible and properly formatted
    And timestamps should be displayed correctly for all comments
    And author names should be displayed correctly for all comments
    When user enters "Comment 151" in "Comment" input field
    And user clicks "Save" button
    Then success message "Comment added successfully" should be displayed
    And comment "Comment 151" should appear at bottom of comments list
    And new comment should be displayed within 2 seconds
    And new comment should display correct timestamp and author information
    And page performance should remain acceptable

  @edge @regression @priority-high
  Scenario: Comment submission when session expires during input
    Given user session timeout is set to 30 minutes
    And user has been idle for 29 minutes
    When user enters "This is a test comment before session expires" in "Comment" input field
    And user waits for 2 minutes
    And user clicks "Save" button
    Then error message "Your session has expired. Please log in again." should be displayed
    And comment should not appear in comments section
    And no new comment should be added
    And user should be redirected to login page

  @edge @regression @priority-high
  Scenario: Comment submission with network interruption during save operation
    Given browser developer tools are open with network throttling capability
    When user enters "Testing network interruption scenario" in "Comment" input field
    And user sets network to "Offline" mode in browser
    And user clicks "Save" button
    Then error message "Unable to save comment. Please check your network connection and try again." should be displayed
    And error message should be displayed in red
    And comment should not be saved
    When user restores network connection in browser
    And user clicks "Save" button
    Then success message "Comment added successfully" should be displayed
    And comment should appear in comments section
    And comment should display correct timestamp
    And notifications should be sent to relevant team members