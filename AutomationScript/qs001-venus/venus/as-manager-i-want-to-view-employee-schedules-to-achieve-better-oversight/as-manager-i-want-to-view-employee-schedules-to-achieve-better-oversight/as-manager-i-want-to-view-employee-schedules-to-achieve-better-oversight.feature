Feature: Employee Schedule Management

  Background:
    Given the application is accessible
    And the user is on the appropriate page

  # Functional Test Scenarios
  Scenario: Validate successful viewing of employee schedules
    Given User is logged in with Manager role credentials
    Given Manager has appropriate permissions to view employee schedules
    Given EmployeeSchedules table contains schedule data for the test period
    Given At least one shift is marked as unfilled in the system
    Given System is accessible and operational
    When Navigate to the employee schedule view from the main dashboard or menu
    Then Schedule interface is displayed with calendar format showing current date range, navigation controls, and filter options are visible
    And Select a date range using the date picker (e.g., select start date and end date for a 7-day period)
    Then Schedule for the selected period is displayed showing all employee shifts, shift times, employee names, and shift types in calendar format within 2 seconds
    And Review the displayed schedule and identify unfilled shifts by looking for visual indicators
    Then Unfilled shifts are clearly highlighted with distinct visual markers (e.g., different color, border, or icon) making them easily distinguishable from filled shifts

  Scenario: Verify filtering of schedules by employee
    Given User is logged in with Manager role credentials
    Given Manager has appropriate permissions to view employee schedules
    Given EmployeeSchedules table contains schedule data for multiple employees
    Given At least one employee has multiple shifts assigned in the current period
    Given Employee filter dropdown is populated with active employees
    Given System is accessible and operational
    When Navigate to the employee schedule view from the main dashboard or menu
    Then Schedule interface is displayed with calendar format, showing all employees' shifts, and filter options including employee filter dropdown are visible
    And Click on the employee filter dropdown and select a specific employee from the list
    Then Schedule is filtered and refreshed to show only the selected employee's shifts, with the employee's name displayed in the filter indicator, and response time is under 2 seconds
    And Review all displayed shifts in the calendar view and verify each shift belongs to the selected employee
    Then Only the selected employee's shifts are visible in the calendar, showing their shift times, dates, and shift types, with no shifts from other employees displayed

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

