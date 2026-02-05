Feature: Employee Weekly Schedule Accessibility
  As an employee with accessibility needs
  I want to access my weekly schedule using assistive technologies
  So that I can manage my time effectively regardless of my abilities

  Background:
    Given employee is logged into the system
    And employee has multiple shifts scheduled for the week

  @accessibility @a11y @priority-high @keyboard-navigation
  Scenario: Complete keyboard navigation through schedule interface without mouse
    Given employee is using keyboard only navigation
    And screen reader is available for testing
    And schedule page is loaded with current week displayed
    When employee presses Tab key to navigate to "My Schedule" link
    Then focus should move to "My Schedule" link with visible focus indicator
    And focus indicator should have "2px" solid outline
    When employee presses Enter key on "My Schedule" link
    Then employee should navigate to schedule page
    When employee presses Tab to navigate through week selector controls
    Then focus should move sequentially through "Previous Week" button
    And focus should move to "Week Picker" button
    And focus should move to "Next Week" button
    And each control should have clear focus indicator
    And focus order should be logical from left to right
    When employee presses Enter on "Next Week" button
    Then week should change to next week
    And focus should remain on the button or move to updated schedule content
    And screen reader should announce "Schedule updated to week of [dates]"
    When employee presses Tab to navigate through shift cards
    Then focus should move through each shift card in logical order
    And each shift card should be focusable
    And each shift card should have visible focus indicator
    When employee presses Enter on focused shift card
    Then shift details modal should open
    And focus should move to modal content
    When employee presses Escape key
    Then modal should close
    And focus should return to shift card
    When employee tests keyboard trap using Tab and Shift+Tab
    Then no keyboard traps should exist
    And employee should navigate forward through all interactive elements
    And employee should navigate backward through all interactive elements
    And employee should reach browser controls to exit page

  @accessibility @a11y @priority-high @screen-reader
  Scenario: Screen reader announces all schedule information correctly with proper ARIA labels
    Given screen reader is active
    And schedule page is loaded with multiple shifts for current week
    And ARIA labels and landmarks are implemented
    When employee navigates to schedule page
    Then screen reader should announce "My Schedule, main region, Viewing schedule for week of January 15 to January 21, 2024, 5 shifts scheduled"
    When employee navigates to week selector controls
    Then screen reader should announce "Previous week, button"
    And screen reader should announce "Week picker, button, current value January 15 to 21"
    And screen reader should announce "Next week, button"
    When employee navigates to first shift card
    Then screen reader should announce "Monday, January 15, Shift from 9:00 AM to 5:00 PM, 8 hours, Location: Main Office, Status: Confirmed, button, 1 of 5 shifts"
    When employee navigates to shift marked as "Recently Changed"
    Then screen reader should announce "Tuesday, January 16, Shift from 10:00 AM to 6:00 PM, Recently modified on January 16 at 3:45 PM, alert"
    When employee navigates to empty day with no shifts
    Then screen reader should announce "Wednesday, January 17, No shifts scheduled"
    When employee changes week using week selector
    Then screen reader should announce "Schedule updated, now viewing week of January 22 to 28, 2024, 4 shifts scheduled" via ARIA live region
    And announcement should occur without user needing to navigate

  @accessibility @a11y @priority-high @color-contrast
  Scenario: Color contrast ratios meet WCAG 2.1 AA standards for all text elements
    Given schedule page is loaded and displaying shifts
    And color contrast analyzer tool is available
    And schedule contains various shift statuses with different color coding
    When employee checks regular body text against background using contrast analyzer
    Then contrast ratio should be at least "4.5:1" for normal text
    When employee checks shift status indicators contrast
    Then green text on light green background should have contrast ratio of at least "4.5:1"
    And yellow text on light yellow background should have contrast ratio of at least "4.5:1"
    And red text on light red background should have contrast ratio of at least "4.5:1"
    When employee verifies "Recently Changed" highlight color contrast
    Then orange indicator should have contrast of at least "3:1" against white background
    And text within orange area should have contrast of at least "4.5:1"
    When employee checks link colors and hover states
    Then links should have contrast of at least "4.5:1" in default state
    And hover states should maintain contrast of at least "4.5:1"
    And hover states should have additional visual indicator beyond color
    When employee tests disabled or inactive elements
    Then disabled elements should have contrast ratio of at least "3:1"
    When employee verifies information conveyed by color
    Then all color-coded information should have additional non-color indicator
    And confirmed shifts should have checkmark icon plus green color
    And status information should use icons, text labels, or patterns

  @accessibility @a11y @priority-medium @zoom @responsive
  Scenario Outline: Schedule remains functional and readable at increased browser zoom levels
    Given schedule page is loaded with current week displayed
    And browser zoom is set to "100%" initially
    And schedule contains multiple shifts for testing
    When employee sets browser zoom to "<zoom_level>"
    Then page should scale to "<zoom_level>"
    And all content should increase in size proportionally
    And schedule should remain readable
    And no horizontal scrolling should be required for content
    And all text should be readable
    When employee checks schedule grid layout at "<zoom_level>"
    Then schedule may reflow to fewer columns if needed
    And all interactive elements should remain clickable
    And all buttons and links should be at least "44x44" pixels
    And no overlapping elements should exist
    And all controls should remain functional
    When employee tests week navigation controls at "<zoom_level>"
    Then week picker should be fully visible and functional
    And Previous and Next buttons should be fully visible and functional
    And date picker modal should open and display correctly
    When employee verifies shift details at "<zoom_level>"
    Then shift times should remain readable
    And locations should remain readable
    And notes should remain readable
    And text should wrap appropriately without being cut off
    And no content should be hidden or inaccessible

    Examples:
      | zoom_level |
      | 200%       |
      | 400%       |

  @accessibility @a11y @priority-high @focus-management @modal
  Scenario: Focus management in modal dialogs and dynamic content updates
    Given employee is using keyboard navigation
    And schedule page is loaded with shifts that can be clicked for details
    And modal dialogs are implemented for shift details and date picker
    And focus trap is implemented in modals
    When employee navigates to shift card using Tab key
    And employee presses Enter to open shift details modal
    Then modal should open
    And focus should automatically move to first focusable element in modal
    And modal should have "role" attribute set to "dialog"
    And modal should have "aria-modal" attribute set to "true"
    When employee presses Tab to navigate through modal content
    Then focus should cycle through all interactive elements within modal
    And focus should not leave modal
    And Shift+Tab should navigate backward within modal
    When employee presses Escape key
    Then modal should close
    And focus should return to the shift card that opened the modal
    And screen reader should announce "Dialog closed"
    When employee opens week picker modal
    Then focus should move to date picker
    And employee should navigate dates with arrow keys
    And Tab should move through month and year controls
    When employee presses Escape key on date picker
    Then picker should close
    And focus should return to week picker button
    When employee changes week
    Then focus should move to meaningful location after dynamic content update
    And screen reader should announce update via ARIA live region
    When employee tests focus visible indicator throughout all interactions
    Then focus indicator should always be visible
    And focus indicator should have minimum "2px" width
    And focus indicator should have sufficient contrast of at least "3:1"