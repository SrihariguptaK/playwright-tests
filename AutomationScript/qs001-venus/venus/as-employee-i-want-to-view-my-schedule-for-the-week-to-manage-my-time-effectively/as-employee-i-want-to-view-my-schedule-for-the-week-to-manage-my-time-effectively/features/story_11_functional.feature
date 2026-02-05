Feature: Employee Weekly Schedule Viewing
  As an employee
  I want to view my schedule for the week
  So that I can manage my time effectively and plan personal activities

  Background:
    Given employee account exists in the system with valid credentials
    And schedule database is accessible and contains schedule data

  @functional @regression @priority-high @smoke
  Scenario: Successfully view current week schedule with all shift details
    Given employee has at least 3 shifts scheduled for the current week
    And user is on the login page of the web interface
    When user enters "emp001@company.com" in "Username" field
    And user enters "ValidPass123" in "Password" field
    And user clicks "Login" button
    Then user should be redirected to employee dashboard
    When user clicks "My Schedule" link in main navigation menu
    Then schedule page should load and display current week by default
    And week range header should be visible
    And schedule grid should display all days from Monday through Sunday
    And all scheduled shifts should be displayed with complete details
    And each shift should show start time
    And each shift should show end time
    And each shift should show duration
    And each shift should show location or department
    And each shift should show any notes
    And each shift card should display color-coded status
    And confirmed shifts should be displayed in green
    And pending shifts should be displayed in yellow
    And all information should be clearly readable
    And total hours summary should be displayed at bottom of schedule
    And total scheduled hours for the week should be calculated correctly

  @functional @regression @priority-high
  Scenario: Filter schedule by selecting different weeks using date picker
    Given employee is logged into the web interface
    And employee is on "My Schedule" page viewing current week
    And employee has shifts scheduled in multiple weeks
    And date picker component is functional and accessible
    When user clicks "Select Week" dropdown at top of schedule page
    Then date picker should open showing calendar view
    And current week should be highlighted in calendar
    When user selects a date 2 weeks ahead in calendar
    Then calendar should update selection and highlight chosen week range
    When user clicks "Apply" button to confirm selection
    Then loading indicator should be shown briefly
    And schedule page should refresh and display shifts for selected week
    And week range header should update to show selected week dates
    When user clicks "Previous Week" arrow button
    Then schedule should update to show previous week with smooth transition
    When user clicks "Current Week" button
    Then schedule should reset to display current week
    And "Current Week" label should be visible

  @functional @regression @priority-high
  Scenario: Schedule changes are highlighted and clearly identifiable
    Given employee is logged into the system
    And employee has at least 2 shifts that were recently modified within last 48 hours
    And schedule change tracking is enabled in the system
    And employee is viewing current week schedule
    When user navigates to "My Schedule" page
    Then schedule should load with modified shifts visually distinguished
    And modified shifts should display orange border or "Updated" badge
    When user hovers over change indicator icon on modified shift
    Then tooltip should appear showing change details
    And tooltip should display modification timestamp
    And tooltip should display original value and new value
    When user clicks on modified shift card
    Then modal or expanded view should open
    And complete change history should be displayed
    And change history should show original values
    And change history should show new values
    And change history should show who made the change
    And change history should show timestamp
    And notification banner should be displayed at top of schedule page
    And banner should display message "You have 2 schedule changes this week"
    And banner should display "View Details" link
    When user clicks "View Details" link in notification banner
    Then change summary panel should open
    And all recent changes should be listed with dates and descriptions

  @functional @regression @priority-medium @accessibility
  Scenario Outline: Schedule displays correctly on different device screen sizes
    Given employee is logged into the web interface
    And employee has a full week schedule with 5 shifts
    And browser supports responsive design testing
    And schedule page is loaded and displaying current week
    When user views schedule on "<device_type>" resolution "<resolution>"
    Then schedule should display in "<layout_format>"
    And "<visibility_details>" should be visible
    And navigation controls should adjust appropriately
    And all interactive elements should remain accessible and clickable
    And no layout breaking or content overflow should occur

    Examples:
      | device_type | resolution | layout_format                          | visibility_details                                    |
      | desktop     | 1920x1080  | full week grid view with 7 days        | all days side-by-side with shift details expanded     |
      | tablet      | 768x1024   | 3-4 days per row                       | all shift details with adjusted navigation controls   |
      | mobile      | 375x667    | single-column list view one day        | swipe or arrow navigation for moving between days     |
      | landscape   | 667x375    | landscape mode layout                  | schedule without horizontal scrolling                 |

  @functional @regression @priority-high @performance
  Scenario: Schedule loads within performance requirements under 2 seconds
    Given employee is logged into the system
    And network conditions are normal
    And schedule database contains employee schedule data for current week
    And browser developer tools are open to monitor network performance
    When user clears browser cache
    And user navigates to "My Schedule" page while monitoring network tab
    Then page should begin loading immediately
    And loading spinner or skeleton screen should be displayed
    And complete schedule with all shift details should load in under 2 seconds
    And API response time for "GET /api/schedules/{employeeId}" should be under 500 milliseconds
    And API should respond with status 200
    And API should return complete schedule data
    When user changes week filter to next week
    Then schedule should update in under 1 second
    When user refreshes the page
    Then page should reload and display schedule in under 1.5 seconds
    And cached assets should be utilized