Feature: As Employee, I want to view my notification history to achieve better tracking of past updates

  Background:
    Given the application is accessible
    And the user is on the appropriate page

  # Functional Test Scenarios
  Scenario: Verify employee can access notification history for the last 30 days
    Given Employee account is created and active in the system
    Given Employee has valid login credentials
    Given Employee has received at least 5 notifications within the last 30 days
    Given Notification history database is accessible
    Given System is up and running
    When Navigate to the system login page
    Then Login page is displayed with username and password fields
    And Enter valid employee credentials and click Login button
    Then Employee is successfully authenticated and redirected to the dashboard
    And Locate and click on the Notification History menu option or icon
    Then Notification History page is displayed
    And Observe the list of notifications displayed on the page
    Then All notifications from the last 30 days are displayed in chronological order with date, time, and notification summary
    And Verify the date range of notifications displayed
    Then All notifications shown are within the last 30 days from current date, no notifications older than 30 days are visible
    And Check the page load time from step 3 to step 4
    Then Notification history loads and displays within 2 seconds

  Scenario: Verify search functionality for specific notifications within history
    Given Employee is logged into the system
    Given Employee has access to notification history page
    Given Multiple notifications exist in the history with different content and keywords
    Given At least one notification contains the keyword 'meeting' in the last 30 days
    When Navigate to the Notification History page
    Then Notification History page is displayed with list of notifications and search functionality visible
    And Locate the search input field on the notification history page
    Then Search input field is visible and enabled for text entry
    And Enter the keyword 'meeting' in the search field
    Then Text 'meeting' is entered in the search field
    And Click the Search button or press Enter key
    Then Search is executed and results are filtered
    And Review the filtered notification list
    Then Only notifications containing the keyword 'meeting' are displayed in the results
    And Clear the search field and verify results
    Then All notifications from the last 30 days are displayed again without filters

  Scenario: Verify notification details are displayed clearly and accurately
    Given Employee is logged into the system
    Given Employee has navigated to the Notification History page
    Given At least one notification exists in the history with complete details (title, message, timestamp, sender)
    When View the list of notifications in the notification history
    Then List of notifications is displayed with summary information for each notification
    And Select a specific notification from the list by clicking on it
    Then Notification is highlighted or selected, and detailed view is opened
    And Review the notification details displayed
    Then Complete notification details are shown including: notification title, full message content, date and time sent, sender information, and notification type
    And Verify the timestamp format and accuracy
    Then Timestamp is displayed in readable format (e.g., DD/MM/YYYY HH:MM) and matches the actual time the notification was sent
    And Check the readability and formatting of the notification content
    Then Text is clearly readable with appropriate font size, proper spacing, and correct formatting without any truncation or display issues
    And Close the notification detail view
    Then Detail view closes and user returns to the notification history list

  Scenario: Verify user can delete notifications from their history
    Given Employee is logged into the system
    Given Employee has navigated to the Notification History page
    Given At least 3 notifications exist in the employee's notification history
    Given Employee has permission to delete notifications from their own history
    When View the notification history list and count the total number of notifications
    Then Notification list is displayed with at least 3 notifications, total count is noted
    And Select a notification to delete by clicking on it or hovering over it
    Then Notification is selected and delete option/button becomes visible
    And Click on the Delete button or delete icon for the selected notification
    Then Confirmation dialog appears asking 'Are you sure you want to delete this notification?'
    And Click Confirm or Yes button in the confirmation dialog
    Then Confirmation dialog closes and notification is removed from the list
    And Verify the notification is no longer visible in the history list
    Then Deleted notification is not displayed in the list, total count is reduced by 1
    And Refresh the notification history page
    Then Page refreshes and the deleted notification remains absent from the list, confirming permanent deletion

  Scenario: Verify notification history loads within 2 seconds performance requirement
    Given Employee is logged into the system
    Given Employee's notification history contains at least 20 notifications
    Given Network connection is stable with normal bandwidth
    Given System is under normal load conditions
    Given Performance monitoring tool or browser developer tools are available
    When Open browser developer tools and navigate to the Network tab
    Then Developer tools are open and Network tab is active for monitoring
    And Clear browser cache and refresh the page to ensure clean test
    Then Cache is cleared and page is ready for fresh load
    And Start timer and click on the Notification History menu option
    Then Navigation to notification history is initiated and timer is running
    And Monitor the page load time until notification history is fully displayed
    Then Notification history page loads completely with all notifications visible
    And Stop timer and record the total load time from click to full display
    Then Total load time is recorded and is 2 seconds or less
    And Review the Network tab to verify API response time for GET /api/notifications/history
    Then API endpoint responds successfully with status 200 and contributes to overall load time within acceptable limits

  Scenario: Verify canceling delete operation does not remove notification from history
    Given Employee is logged into the system
    Given Employee has navigated to the Notification History page
    Given At least one notification exists in the history
    Given Delete confirmation dialog is implemented in the system
    When View the notification history list and select a specific notification to delete
    Then Notification is selected and delete option is visible
    And Note the details of the selected notification (title, date, content)
    Then Notification details are recorded for verification
    And Click on the Delete button for the selected notification
    Then Confirmation dialog appears asking 'Are you sure you want to delete this notification?' with Cancel and Confirm options
    And Click the Cancel or No button in the confirmation dialog
    Then Confirmation dialog closes without deleting the notification
    And Verify the notification is still present in the history list
    Then The notification remains in the list with all original details intact
    And Refresh the page and verify the notification is still present
    Then After page refresh, the notification is still visible in the history confirming no deletion occurred

  # Negative Test Scenarios
  Scenario: Verify notification history requires user authentication
    Given Employee account exists in the system
    Given Employee is not currently logged into the system
    Given Notification history page URL is known
    Given Security authentication is enabled on the system
    When Open a web browser and ensure no user is logged into the system
    Then Browser is open with no active user session
    And Attempt to directly access the notification history page by entering the URL (e.g., /notifications/history)
    Then Access is denied and user is redirected to the login page
    And Verify that an appropriate error message or authentication prompt is displayed
    Then Message displayed: 'Please log in to access this page' or 'Authentication required'
    And Enter valid employee credentials on the login page
    Then Employee is successfully authenticated and logged into the system
    And Navigate to the notification history page after successful login
    Then Notification history page is accessible and displays the employee's notification history

  Scenario: Verify employee can only view their own notification history
    Given Two employee accounts exist: Employee A and Employee B
    Given Both employees have notifications in their respective histories
    Given Employee A is logged into the system
    Given User permission validation is enabled
    When Log in as Employee A with valid credentials
    Then Employee A is successfully logged into the system
    And Navigate to the Notification History page
    Then Notification history page is displayed showing Employee A's notifications
    And Review all notifications displayed and verify ownership
    Then All notifications displayed belong to Employee A only, no notifications from other employees are visible
    And Attempt to manipulate URL parameters to access Employee B's notification history (e.g., change user ID in URL)
    Then Access is denied with error message 'Unauthorized access' or user is redirected to their own notification history
    And Verify that no API calls can retrieve other employees' notification data
    Then API endpoint GET /api/notifications/history returns only Employee A's notifications and rejects requests for other users' data

  # Edge Case Test Scenarios
  Scenario: Verify notification history does not display notifications older than 30 days
    Given Employee is logged into the system
    Given Test data includes notifications that are exactly 30 days old, 31 days old, and within the last 30 days
    Given System date and time are correctly configured
    Given Notification history database contains notifications spanning more than 30 days
    When Navigate to the Notification History page
    Then Notification History page is displayed with list of notifications
    And Review all notifications displayed and note the oldest notification date
    Then All notifications displayed have dates within the last 30 days from current date
    And Verify that notifications exactly 30 days old are visible
    Then Notifications that are exactly 30 days old from current date are displayed in the list
    And Attempt to search or scroll for notifications older than 30 days
    Then No notifications older than 30 days are found or displayed in the history
    And Check if there is any option or filter to view notifications older than 30 days
    Then No option exists to view notifications beyond the 30-day limit

  Scenario: Verify notification history displays empty state when no notifications exist
    Given New employee account is created in the system
    Given Employee has never received any notifications
    Given Employee is logged into the system
    Given Notification history database is accessible
    When Log in as the new employee with no notification history
    Then Employee is successfully logged into the system
    And Navigate to the Notification History page
    Then Notification History page loads successfully
    And Observe the content displayed on the notification history page
    Then Empty state message is displayed such as 'No notifications found' or 'You have no notification history'
    And Verify that the page layout and UI elements are properly displayed
    Then Page displays correctly with appropriate empty state icon or graphic, no errors or broken elements are visible
    And Verify search functionality behavior with no notifications
    Then Search field is either disabled or returns 'No results found' message when used

  # Accessibility Test Scenarios
  Scenario: Keyboard Navigation
    When the user navigates using keyboard only
    Then all interactive elements should be accessible via keyboard
    And focus indicators should be clearly visible

  Scenario: Screen Reader Compatibility
    When the user accesses the page with a screen reader
    Then all content should be properly announced
    And ARIA labels should be present for all interactive elements

  Scenario: Color Contrast
    Then all text should meet WCAG AA color contrast standards
    And important information should not rely solely on color

