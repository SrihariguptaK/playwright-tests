Feature: Task Commenting for Team Communication
  As an Employee
  I want to perform commenting on tasks
  So that I can achieve better communication with my team members

  Background:
    Given user is authenticated as an employee
    And user has access to task details page

  @usability @priority-critical @smoke @functional
  Scenario: Real-time feedback during comment submission with normal network
    Given task has at least 5 existing comments
    And network conditions are normal
    When user navigates to task details page
    Then loading indicator should be displayed while comments are being fetched
    And user should not see blank space or static content
    When user enters "100" characters in comment input field
    And user clicks "Save" button
    Then "Save" button should show loading state
    And "Save" button should be disabled
    And button text should change to "Saving..."
    And user should not be able to submit duplicate comments
    When user observes system behavior during comment save process
    Then visual feedback should be provided with progress indicator
    And disabled state should be maintained
    And input field should remain visible with submitted text
    When comment submission completes successfully
    Then success message "Comment posted successfully" should be displayed
    And success confirmation should be visible
    And new comment should appear in chronological list
    And new comment should be visually highlighted
    And input field should be cleared
    And input field should be ready for new comment

  @usability @priority-critical @negative
  Scenario: Real-time feedback during comment submission with slow network
    Given task has at least 5 existing comments
    And network is throttled to "3G" speed
    When user navigates to task details page
    And user enters "150" characters in comment input field
    And user clicks "Save" button
    Then extended loading state should be maintained throughout delay
    And "Posting comment..." message should be displayed
    And processing indicator should persist until completion

  @usability @priority-high @negative @edge
  Scenario: Prevent submission of empty comment
    Given user is on task details page
    And comment input field is visible
    When user clicks "Save" button without entering text
    Then "Save" button should be disabled
    And inline message "Please enter a comment before submitting." should be displayed

  @usability @priority-high @functional
  Scenario: Character counter display as user approaches limit
    Given user is on task details page
    And comment length limit is set to 500 characters
    When user enters "450" characters in comment input field
    Then character counter should display "450/500 characters"
    And character counter should be positioned near input field
    When user continues typing until "500" characters are entered
    Then character counter should display "500/500"
    And character counter color should change to yellow
    And input field should still accept text

  @usability @priority-high @edge @negative
  Scenario: Prevent character entry beyond maximum limit
    Given user is on task details page
    And comment length limit is set to 500 characters
    And user has entered "500" characters in comment input field
    When user attempts to enter additional character
    Then system should prevent additional character entry
    And character counter should turn red
    And character counter should display "500/500 - limit reached"
    And message "Maximum comment length reached. Please shorten your message." should be displayed

  @usability @priority-high @edge @negative
  Scenario: Prevent pasting content exceeding character limit
    Given user is on task details page
    And comment length limit is set to 500 characters
    When user pastes "600" character text block into comment field
    Then system should truncate content to 500 characters with warning
    And message "Pasted content exceeds 500 character limit. Please shorten your comment." should be displayed

  @usability @priority-high @negative
  Scenario: Prevent submission of whitespace-only comment
    Given user is on task details page
    When user enters only whitespace characters in comment input field
    And user clicks "Save" button
    Then system should prevent submission
    And message "Comment cannot be empty or contain only spaces." should be displayed
    And no invalid comment should be saved to database

  @usability @priority-high @negative @functional
  Scenario: Clear error message and recovery for network failure
    Given user is on task details page
    And network connection is disconnected
    When user enters "200" characters in comment input field
    And user clicks "Save" button
    Then error message "Unable to post comment. Please check your internet connection and try again." should be displayed
    And "Retry" button should be visible
    And comment text should be preserved in input field
    When network connection is restored
    And user clicks "Retry" button
    Then system should attempt resubmission without requiring re-entry
    And success or failure feedback should be provided

  @usability @priority-high @negative @functional
  Scenario: Clear error message and recovery for session timeout
    Given user is on task details page
    And user session has expired
    When user enters "200" characters in comment input field
    And user clicks "Save" button
    Then error message "Your session has expired. Please log in again to post your comment." should be displayed
    And comment text should be preserved in local storage
    And user should be redirected to login page with return path
    When user completes authentication
    And user returns to task details page
    Then previously entered comment text should be restored in input field
    And message "Your unsaved comment has been restored. Click save to post it." should be displayed

  @usability @priority-high @negative
  Scenario: Clear error message and recovery for server error
    Given user is on task details page
    And server returns "500" error during submission
    When user enters "200" characters in comment input field
    And user clicks "Save" button
    Then error message "Something went wrong on our end. Your comment couldn't be posted. Please try again in a moment." should be displayed
    And "Retry" button should be visible
    And "Copy Comment" button should be visible
    And comment text should be preserved in input field
    And error message should not contain technical jargon

  @usability @priority-high @negative @functional
  Scenario: Clear error message for validation failure
    Given user is on task details page
    When user enters comment with prohibited content in comment input field
    And user clicks "Save" button
    Then error message "Your comment contains content that violates our guidelines. Please review and modify your comment." should be displayed
    And problematic section should be highlighted if possible

  @usability @priority-high @accessibility
  Scenario: Error messages are prominently displayed and accessible
    Given user is on task details page
    When any error occurs during comment submission
    Then error message should be displayed near comment input field
    And error message should use red or orange color coding
    And error message should include warning or error icon
    And error message should remain visible until user takes action
    And error message should have ARIA labels for screen readers
    And error message should use polite and constructive language