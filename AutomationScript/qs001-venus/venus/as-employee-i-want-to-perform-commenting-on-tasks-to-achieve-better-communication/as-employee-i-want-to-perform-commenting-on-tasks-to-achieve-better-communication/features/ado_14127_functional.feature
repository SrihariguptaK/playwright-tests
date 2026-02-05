Feature: Task Commenting for Team Communication
  As an Employee
  I want to perform commenting on tasks
  So that I can achieve better communication with my team members

  Background:
    Given user is logged in as an authenticated employee
    And database connection is active and comments table is accessible

  @functional @regression @priority-high @smoke
  Scenario: Successfully add a comment to a task
    Given user has navigated to task details page with task ID
    And comment input field is visible and enabled on the task details page
    When user clicks on "Add a comment" input field
    Then comment input field should receive focus with cursor visible
    When user enters "This task is progressing well, will complete by EOD" in comment input field
    Then text should appear in the input field as typed
    And character counter should display "50/500"
    When user clicks "Save" button
    Then loading indicator should appear briefly
    And success message "Comment added successfully" should be displayed in green banner
    When user scrolls to the comments section
    Then new comment should appear at the bottom of the chronological list
    And comment should display employee name, timestamp, and comment text correctly
    And comment should be saved in the comments table with correct task ID association
    And notifications should be sent to relevant team members
    And comment input field should be cleared and ready for new input

  @functional @regression @priority-high
  Scenario: Comments are displayed in chronological order with correct metadata
    Given task details page contains at least 5 existing comments with different timestamps
    And comments were added by different team members at different times
    When user navigates to task details page with existing comments
    Then task details page should load with comments section visible
    When user scrolls to the comments section
    Then comments should be displayed in chronological order from oldest to newest
    And each comment should display format "Employee Name - MM/DD/YYYY HH:MM AM/PM" followed by comment text
    When user enters "Latest update on task progress" in comment input field
    And user clicks "Save" button
    Then new comment should appear at the bottom of the list as the most recent comment
    And all comments should remain in chronological order
    And page performance should remain under 2 seconds for comment display

  @functional @regression @priority-high @notification
  Scenario: Notification system sends alerts to relevant team members when new comment is added
    Given task has assigned team members "Employee B" and "Employee C"
    And notification system is enabled and configured correctly
    And user is on task details page for a task assigned to multiple team members
    When user navigates to the task details page
    Then task details page should load showing task assigned to all team members
    When user enters "Need input from team on this approach" in comment input field
    Then character counter should display "42/500"
    When user clicks "Save" button
    Then success message should be displayed
    And comment should appear in the comments list
    When "Employee B" logs in and checks notifications
    Then "Employee B" should see notification badge with count "1"
    And notification message "Employee A commented on Task: [Task Name]" should be displayed
    When "Employee C" logs in and checks notifications
    Then "Employee C" should see notification badge with count "1"
    And notification message "Employee A commented on Task: [Task Name]" should be displayed
    And notifications should be sent to all relevant team members except the comment author
    And notification records should be created in the notifications table

  @functional @regression @priority-medium @validation
  Scenario: Comment character counter updates correctly and enforces 500 character limit
    Given user is on task details page with comment input field visible
    And comment input field is empty and ready for input
    And character counter displays "0/500" initially
    When user clicks on comment input field
    Then input field should receive focus
    And character counter should display "0/500"
    When user enters "This is a test comment with exactly 250 characters to verify the character counter functionality works correctly. We need to ensure that the counter updates in real-time as the user types and provides accurate feedback about remaining characters." in comment input field
    Then character counter should update in real-time showing "250/500"
    And text should appear in black color
    When user continues typing " Additional text to reach the maximum limit of 500 characters for this comment field. This ensures we test the boundary condition properly and verify that the system handles the maximum allowed length correctly without any issues or errors occurring." in comment input field
    Then character counter should display "500/500" in orange or red color
    And "Save" button should be enabled
    When user clicks "Save" button
    Then comment should be successfully saved
    And success message "Comment added successfully" should be displayed
    And comment with exactly 500 characters should be saved in the database
    And comment should display correctly in the comments list with full text visible
    And character counter should reset to "0/500"
    And input field should be cleared and ready for new comment

  @functional @regression @priority-high @security
  Scenario: Only authenticated employees can access comment functionality
    Given user has valid employee credentials in the system
    And user is not currently logged in
    And authentication system is functioning correctly
    When user navigates directly to task details page URL without being logged in
    Then system should redirect to login page
    And message "Please log in to access this page" should be displayed
    When user enters "employee@company.com" in "Email" field
    And user enters "ValidPass123" in "Password" field
    And user clicks "Login" button
    Then login should be successful
    And user should be redirected to the originally requested task details page
    And comment input field should be visible and enabled
    And "Save" button should be enabled
    And comment input field should display placeholder text "Add a comment"
    When user enters "Testing authenticated access" in comment input field
    And user clicks "Save" button
    Then comment should be successfully saved
    And success message should be displayed
    And comment should be saved with correct employee ID association in database
    And user should remain authenticated with valid session token

  @functional @regression @priority-high @api
  Scenario: API endpoint POST /api/tasks/{id}/comments processes comment submission correctly
    Given user is logged in with valid JWT token
    And task with ID "12345" exists in the database
    And API endpoint "POST /api/tasks/12345/comments" is accessible and operational
    And user is on task details page for task ID "12345"
    When user opens browser developer tools and navigates to Network tab
    Then Network tab should be ready to capture API requests
    When user enters "Verifying API endpoint functionality" in comment input field
    Then character counter should display "38/500"
    When user clicks "Save" button
    Then POST request should be sent to "/api/tasks/12345/comments"
    And request payload should contain comment text and employee ID
    And API should return HTTP status 201 Created
    And response body should contain comment ID, timestamp, employee details, and success status
    And comment should appear in the UI comments list
    And comment should display in chronological order with correct text, employee name, and timestamp
    And comment record should be created in comments table with correct task_id foreign key
    And API response should include commentId, taskId, employeeId, commentText, and createdAt fields
    And database transaction should be committed successfully

  @functional @regression @priority-medium @performance
  Scenario: Comment display performance meets 2-second requirement
    Given task has 50 existing comments in the database
    And browser performance tools are available for measurement
    And network connection is stable with normal bandwidth
    When user opens browser developer tools and navigates to Performance tab
    And user starts performance recording
    Then performance recording should be active and capturing metrics
    When user navigates to task details page with 50 existing comments
    Then page should begin loading with loading indicator visible
    And all 50 comments should be displayed in chronological order with complete metadata
    When user stops performance recording and checks the timeline
    Then total time from page load to complete comment display should be under 2 seconds
    When user enters "Performance test comment" in comment input field
    And user clicks "Save" button
    Then new comment should appear in the comments list within 2 seconds
    And all 51 comments should be visible and properly formatted
    And no performance degradation should occur with increased comment count
    And browser memory usage should remain within acceptable limits