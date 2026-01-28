Feature: Schedule Notification System

  Background:
    Given the application is accessible
    And the user is on the appropriate page

  # Functional Test Scenarios
  Scenario: Validate reminder subscription functionality
    Given Employee account exists in the system with valid credentials
    Given Employee has at least one upcoming shift scheduled
    Given Reminder service is operational and accessible
    Given Employee has a valid email address and/or phone number registered in their profile
    Given Web interface is accessible and functional
    When Navigate to the login page of the web interface
    Then Login page is displayed with username and password fields
    And Enter valid employee credentials (username and password) and click the login button
    Then User is successfully authenticated and redirected to the dashboard or home page
    And Locate and click on the profile or settings menu option
    Then Profile or settings menu expands showing available options
    And Navigate to the reminder settings or notification preferences section
    Then Reminder settings page is displayed showing available reminder options and current preferences
    And Review the available reminder options including delivery method (email/SMS), timing preferences, and shift details inclusion
    Then All reminder configuration options are visible and accessible
    And Select preferred reminder delivery method (email or SMS or both)
    Then Selected delivery method is highlighted or checked
    And Set the reminder timing preference (e.g., 24 hours before shift, 2 hours before shift)
    Then Timing preference is selected and displayed correctly
    And Enable the option to include shift details in reminders
    Then Shift details inclusion option is checked or enabled
    And Click the Save or Subscribe button to confirm reminder preferences
    Then System processes the request and displays a confirmation message indicating reminder settings have been saved successfully
    And Verify the confirmation message contains details of the saved preferences
    Then Confirmation message displays the selected delivery method, timing, and other preferences accurately
    And Refresh the reminder settings page or navigate away and return to verify persistence
    Then Previously saved reminder preferences are displayed correctly, confirming they were persisted in the system

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

