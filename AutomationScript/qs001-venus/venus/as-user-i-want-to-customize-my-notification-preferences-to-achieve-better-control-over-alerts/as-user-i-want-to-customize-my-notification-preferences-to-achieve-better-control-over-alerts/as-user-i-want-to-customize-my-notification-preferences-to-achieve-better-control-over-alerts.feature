Feature: User Notification System

  Background:
    Given the application is accessible
    And the user is on the appropriate page

  # Functional Test Scenarios
  Scenario: Validate saving of notification preferences
    Given User is logged into the system with valid credentials
    Given User has an active account with notification settings enabled
    Given User has permission to modify notification preferences
    Given System is accessible and responsive
    When Navigate to notification settings page from user profile or settings menu
    Then Notification settings page is displayed with all available options visible including notification channels (email, SMS, in-app), frequency settings, and conflict type options
    And Select preferred notification channels by checking email, SMS, and/or in-app notification options
    Then Selected channels are highlighted/checked without any errors, UI responds immediately to selections, and no error messages are displayed
    And Select notification frequency from available options (immediate, daily digest, weekly summary)
    Then Frequency option is selected and visually indicated as active
    And Choose conflict types to be notified about (scheduling conflicts, resource conflicts, priority conflicts)
    Then Conflict types are selected and marked appropriately in the UI
    And Click the 'Save' or 'Save Preferences' button
    Then System processes the request within 2 seconds, displays a success confirmation message (e.g., 'Preferences saved successfully'), and the save button may briefly show a loading state
    And Verify that the saved preferences are retained by refreshing the page or navigating away and returning to notification settings
    Then All previously selected preferences are displayed correctly and remain saved

  Scenario: Ensure preferences are applied consistently
    Given User is logged into the system with valid credentials
    Given User has previously saved notification preferences
    Given User has selected specific notification channels (e.g., email and in-app)
    Given System has the ability to generate scheduling conflicts for testing
    Given User has access to the selected notification channels
    When Navigate to notification settings page
    Then Notification settings page is displayed with current preferences shown
    And Change notification preferences by selecting different channels (e.g., change from email only to email + SMS) and/or modify frequency settings
    Then New preferences are selected and visually indicated in the UI
    And Click 'Save' button to update preferences
    Then System confirms preferences are updated successfully with a confirmation message, update is processed within 2 seconds
    And Trigger a scheduling conflict by creating or simulating a double-booking scenario or resource conflict
    Then Scheduling conflict is created successfully in the system and conflict detection mechanism identifies it
    And Wait for notification to be sent and check the selected notification channel(s) for incoming notification
    Then Notification is sent via the newly selected channel(s) only (e.g., email and SMS if both were selected), notification arrives within expected timeframe
    And Verify notification content includes conflict details such as conflict type, affected resources, time/date, and recommended actions
    Then Notification content accurately matches user preferences, includes all relevant conflict information, is formatted correctly, and matches the selected conflict types from preferences
    And Verify that notifications are NOT sent through channels that were deselected
    Then No notifications appear in deselected channels, confirming preferences are applied consistently
    And Trigger another scheduling conflict of a different type to verify consistency
    Then Notification is sent again via the same selected channels with appropriate content based on conflict type preferences

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

