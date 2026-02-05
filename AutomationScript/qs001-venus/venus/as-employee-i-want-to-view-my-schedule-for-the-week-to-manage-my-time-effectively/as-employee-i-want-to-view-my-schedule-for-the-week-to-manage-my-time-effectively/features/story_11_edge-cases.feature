Feature: Employee Weekly Schedule Viewing with Edge Case Handling
  As an employee
  I want to view my weekly schedule with proper handling of edge cases
  So that I can reliably manage my time even with complex scheduling scenarios

  Background:
    Given employee is logged into the system
    And employee is on the schedule page

  @edge @regression @priority-medium
  Scenario: Schedule displays maximum number of shifts in a single day without performance issues
    Given test employee has 8 shifts scheduled in a single day
    And schedule page supports displaying multiple shifts per day
    And UI layout can accommodate multiple shift cards
    When employee navigates to schedule page
    And employee selects the week containing the day with 8 shifts
    Then schedule page should load without performance degradation
    And all 8 shifts should be displayed in the day column
    And scrollable area should be available if needed
    And no overlapping or hidden shifts should exist
    And each shift card should display complete information including time, location, and duration
    And all shift details should be readable and properly formatted
    And no text truncation or layout breaking should occur
    And total hours calculation should show "16" hours for the day
    And total hours should be displayed accurately
    And smooth scrolling within day column should work
    And all shifts should remain accessible

  @edge @regression @priority-high
  Scenario: Schedule handles shifts spanning midnight correctly
    Given employee has shift starting at "11:00 PM" on "Tuesday" and ending at "7:00 AM" on "Wednesday"
    And system supports overnight shift display logic
    And time zone handling is properly configured
    When employee navigates to week containing overnight shift
    Then schedule should load and display the week correctly
    And overnight shift should be displayed spanning both "Tuesday" and "Wednesday" columns
    And shift timing should show "Tue 11:00 PM - Wed 7:00 AM" with clear indication of day change
    And shift duration should be calculated correctly as 8 hours
    And duration should not show negative or incorrect value
    And weekly total hours should include the full 8 hours from overnight shift
    And no duplication or omission should occur in weekly totals

  @edge @regression @priority-medium
  Scenario Outline: Schedule handles daylight saving time transitions correctly
    Given test environment is set to time zone that observes daylight saving time
    And employee has shifts scheduled during DST transition week
    And system time zone handling is configured correctly
    When employee navigates to schedule for week containing "<dst_type>" transition on "<transition_date>"
    And employee views shift scheduled during "<affected_time_range>"
    Then schedule should load and display the transition week
    And system should handle time gap appropriately
    And shift times should be adjusted or warning should be displayed if shift falls in non-existent hour
    And total hours for the day should reflect "<expected_day_hours>" hours
    And all shift times should display in correct time zone with DST indicator
    And times should show correct DST offset
    And all shifts should be in local time

    Examples:
      | dst_type      | transition_date | affected_time_range | expected_day_hours |
      | spring forward| March 10, 2024  | 2:00 AM - 3:00 AM   | 23                 |
      | fall back     | November 3, 2024| 1:00 AM - 2:00 AM   | 25                 |

  @edge @regression @priority-low
  Scenario: Schedule handles rapid week navigation without performance degradation
    Given employee is viewing current week on schedule page
    And multiple weeks of schedule data exist in the database
    And browser performance monitoring tools are available
    When employee rapidly clicks "Next Week" button 10 times within 5 seconds
    Then system should handle rapid requests without crashing
    And requests should be queued or debounced appropriately
    And schedule should update smoothly
    And loading states should be shown
    And no UI freezing or unresponsive behavior should occur
    And final displayed week should match expected week 10 weeks ahead
    And no skipped or duplicate weeks should appear
    And no JavaScript errors should be logged in browser console
    And memory usage should remain stable
    And no memory leaks should be detected
    And system should implement request cancellation or debouncing
    And only necessary API calls should be made

  @edge @regression @priority-low
  Scenario: Schedule displays extremely long shift notes with proper truncation
    Given test employee has shift with 500 character note
    And schedule page has character limit handling
    When employee navigates to schedule page containing shift with long note
    Then schedule should load without errors
    And long note should be truncated with "Read more" link or displayed in scrollable area
    And text should remain readable and properly formatted

  @edge @regression @priority-low
  Scenario Outline: Schedule displays special characters in shift details correctly
    Given test employee has shift with "<character_type>" in shift notes
    And schedule page has XSS protection enabled
    When employee navigates to schedule page containing shift with special characters
    Then schedule should load without errors
    And "<character_type>" should display correctly without rendering issues
    And text should remain readable and properly encoded
    And no character encoding issues should occur
    And no boxes or question marks should be displayed

    Examples:
      | character_type                          |
      | emoji characters                        |
      | Unicode Chinese characters              |
      | Unicode Arabic characters               |
      | Unicode special symbols                 |

  @edge @regression @priority-low
  Scenario Outline: Schedule prevents XSS attacks from shift note content
    Given test employee has shift with "<malicious_content>" in shift notes
    And schedule page has XSS protection enabled
    When employee navigates to schedule page containing shift with HTML-like text
    Then schedule should load without errors
    And HTML tags should be escaped and displayed as plain text
    And no script execution should occur
    And XSS protection should be working
    And text should show literally as "<displayed_text>"
    And content should not be executed

    Examples:
      | malicious_content                | displayed_text                   |
      | <script>alert("test")</script>   | <script>alert("test")</script>   |
      | <b>Bold text</b>                 | <b>Bold text</b>                 |
      | <img src=x onerror=alert(1)>     | <img src=x onerror=alert(1)>     |

  @edge @regression @priority-low
  Scenario: Schedule handles special formatting characters in shift notes
    Given test employee has shift with newlines, tabs, and multiple spaces in shift notes
    When employee navigates to schedule page containing shift with special formatting
    Then schedule should load without errors
    And formatting should be preserved or normalized appropriately
    And no layout breaking should occur
    And UI layout should remain intact