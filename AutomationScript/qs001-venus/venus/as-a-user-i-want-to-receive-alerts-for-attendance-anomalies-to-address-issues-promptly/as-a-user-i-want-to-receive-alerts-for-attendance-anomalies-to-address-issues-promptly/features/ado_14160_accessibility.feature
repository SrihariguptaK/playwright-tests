Feature: Attendance Alerts Accessibility Compliance
  As a user with accessibility needs
  I want the attendance alerts system to be fully accessible
  So that I can receive and respond to attendance anomalies regardless of my abilities

  Background:
    Given user is logged into the system
    And attendance monitoring system is active

  @accessibility @a11y @priority-high @keyboard-navigation
  Scenario: Complete keyboard navigation through attendance alerts dashboard and acknowledgment workflow
    Given user has keyboard-only access with mouse disabled
    And "5" attendance anomaly alerts exist in user's inbox
    And alerts dashboard is accessible via main navigation
    And browser supports standard keyboard navigation
    When user presses Tab key from main navigation menu to reach "Alerts" link
    Then focus indicator should be visible on "Alerts" navigation link
    And focus indicator should have minimum contrast ratio of "3:1"
    When user presses Enter key to navigate to alerts dashboard
    Then alerts dashboard should load successfully
    And focus should move to "Attendance Alerts" heading
    And page title should include "Alerts"
    When user presses Tab key to navigate through alert list
    Then focus should move sequentially through each alert item
    And each alert should receive visible focus indicator
    And focus order should be logical from top to bottom
    When user presses Enter key on focused alert
    Then alert should expand to show full anomaly description
    And focus should remain on expanded alert
    And expansion should be announced to screen readers
    When user presses Tab key to reach "Acknowledge" button
    Then focus should move to "Acknowledge" button with clear visual indicator
    And button should be clearly identified as interactive
    When user presses Enter key to acknowledge alert
    Then alert should be acknowledged successfully
    And confirmation message should appear and receive focus
    And success message should be announced to screen readers
    When user presses Escape key while viewing expanded alert
    Then alert should collapse
    And focus should return to alert item in list
    And no focus trap should occur
    When user presses Shift+Tab to navigate backwards
    Then focus should move in reverse order through all interactive elements
    And no elements should be skipped
    And focus should remain visible at all times

  @accessibility @a11y @priority-high @screen-reader
  Scenario: Screen reader compatibility and ARIA announcements for alert notifications
    Given screen reader software is active
    And attendance monitoring system is configured to generate test alerts
    And browser is compatible with screen reader
    When user navigates to alerts dashboard using screen reader
    Then screen reader should announce page title "Attendance Alerts Dashboard"
    And screen reader should announce main landmark regions
    When user uses screen reader to read alerts list heading
    Then screen reader should announce "Attendance Alerts, heading level 1"
    And screen reader should announce "You have 5 unacknowledged alerts"
    When user navigates to first alert item using screen reader
    Then screen reader should announce "Alert 1 of 5"
    And screen reader should announce alert type "Late Arrival"
    And screen reader should announce detection time "9:15 AM on January 15, 2024"
    And screen reader should announce status "Unacknowledged"
    And screen reader should announce "button Acknowledge"
    When new alert is triggered while on alerts dashboard
    Then ARIA live region should announce "New attendance alert received: Late Arrival at 10:30 AM"
    And current screen reader position should not be disrupted
    When user activates "Acknowledge" button using screen reader
    Then screen reader should announce button activation
    And ARIA live region should announce "Alert acknowledged successfully" with assertive politeness
    When user navigates through alert details using screen reader
    Then all text content should be accessible
    And anomaly description should be announced
    And timestamp should be announced
    And suggested actions should be announced
    And no content should be hidden from screen reader
    When user reads alert priority information
    Then screen reader should announce alert severity level
    And ARIA attributes should properly convey urgency

  @accessibility @a11y @priority-high @focus-management
  Scenario: Focus management and focus trap prevention in alert modal dialogs
    Given user has keyboard-only access
    And alert system displays detailed information in modal dialogs
    And multiple alerts are available for testing
    And modal dialog follows ARIA dialog pattern
    When user navigates to alert and presses Enter to open modal
    Then modal dialog should open
    And focus should automatically move to first focusable element in modal
    And background content should be inert
    When user presses Tab key repeatedly in modal
    Then focus should cycle through close button
    And focus should cycle through alert details
    And focus should cycle through suggested actions
    And focus should cycle through acknowledge button
    And focus should return to close button
    And focus should remain trapped within modal
    When user presses Shift+Tab from first focusable element
    Then focus should move to last focusable element in modal
    And focus trap should work in both directions
    When user presses Escape key while modal is open
    Then modal should close
    And focus should return to trigger element
    And no focus should be lost
    When user opens modal again and clicks "Acknowledge" button using keyboard
    Then alert should be acknowledged successfully
    And modal should close
    And focus should return to alert list
    And success message should be announced and receive focus
    When user attempts to Tab outside modal while modal is open
    Then focus should remain within modal
    And background should have "aria-hidden" attribute set to "true"
    And screen reader should not access background content

  @accessibility @a11y @priority-high @color-contrast
  Scenario Outline: Color contrast and visual indicators for alert severity levels
    Given user is on alerts dashboard
    And alerts display different severity levels
    And color contrast analyzer tool is available
    When user views alert with "<severity>" severity level
    Then alert should be distinguishable by multiple indicators
    And alert should display severity icon
    And alert should display severity text label
    And alert should display severity color
    When color contrast is measured for "<severity>" alert
    Then normal text should have minimum contrast ratio of "4.5:1"
    And large text should have minimum contrast ratio of "3:1"
    When color contrast is measured for status indicators
    Then status indicators should have minimum contrast ratio of "3:1"
    And status should be conveyed through text labels
    When color blindness simulation "<color_blindness_type>" is enabled
    Then alert severity should remain distinguishable
    And icons should provide redundant information
    And text labels should provide redundant information
    When focus indicators are tested for contrast
    Then focus indicators should have minimum contrast ratio of "3:1" against adjacent colors
    And focus should be clearly visible for all interactive elements
    When error messages and success confirmations are tested
    Then feedback messages should have minimum contrast ratio of "4.5:1"
    And icons should supplement color-coded messages

    Examples:
      | severity | color_blindness_type |
      | low      | protanopia          |
      | medium   | deuteranopia        |
      | high     | tritanopia          |
      | critical | protanopia          |

  @accessibility @a11y @priority-medium @zoom-support
  Scenario Outline: Alerts dashboard functionality at various browser zoom levels
    Given user is on alerts dashboard
    And browser zoom is set to "100" percent initially
    And alerts dashboard contains multiple alerts with varying content lengths
    And browser supports zoom functionality
    When user increases browser zoom to "<zoom_level>" percent
    Then page content should scale proportionally
    And all text should remain readable
    And no content should be cut off or hidden
    When user verifies alert information accessibility
    Then content should reflow to fit viewport
    And horizontal scrolling should not be required
    And responsive design should adapt to zoomed view
    When user tests interactive elements at "<zoom_level>" percent zoom
    Then all buttons should remain clickable
    And all links should remain clickable
    And touch targets should be at least "44" by "44" pixels
    And no overlapping elements should exist
    And spacing should be maintained
    When user navigates through alerts using keyboard at "<zoom_level>" percent zoom
    Then keyboard navigation should work correctly
    And focus indicators should be visible and properly sized
    And no layout breaks should occur during navigation
    When user acknowledges alert at "<zoom_level>" percent zoom
    Then acknowledgment workflow should function correctly
    And confirmation message should be visible and readable
    And no functionality should be lost

    Examples:
      | zoom_level |
      | 150        |
      | 175        |
      | 200        |

  @accessibility @a11y @priority-high @aria-live-regions
  Scenario: ARIA live regions for real-time alert notifications and dynamic content updates
    Given screen reader is active
    And user is viewing alerts dashboard
    And attendance monitoring system can generate test alerts in real-time
    And ARIA live regions are implemented in alerts interface
    When user positions screen reader focus on dashboard main content area
    Then screen reader should be actively monitoring page
    When high-priority attendance anomaly alert is triggered
    Then ARIA live region with "assertive" politeness should announce immediately
    And announcement should include "New high priority alert: Late arrival detected at 2:30 PM. Please review immediately."
    And current screen reader position should not be interrupted
    When low-priority informational alert is triggered
    Then ARIA live region with "polite" politeness should announce after current announcement
    And announcement should include "New alert: Early departure at 4:45 PM"
    When user acknowledges alert using keyboard
    Then ARIA live region should announce "Alert acknowledged successfully"
    And alert count should update
    And updated count should be announced "You now have 4 unacknowledged alerts"
    When "3" rapid alerts are triggered within "10" seconds
    Then ARIA live region should announce each alert without overwhelming user
    And announcements should be queued appropriately
    And no announcements should be lost
    And no announcements should be duplicated
    When ARIA live region attributes are verified
    Then live regions should have "aria-live" attribute set to "polite" or "assertive"
    And live regions should have "aria-atomic" attribute set to "true"
    And live regions should have "aria-relevant" attribute set to "additions text"

  @accessibility @a11y @priority-medium @mobile-accessibility
  Scenario: Mobile accessibility including touch target sizes and gesture support for alerts
    Given user is accessing system on mobile device
    And multiple attendance alerts are available in user's inbox
    And mobile browser supports touch interactions and accessibility features
    When user navigates to alerts dashboard on mobile device
    Then dashboard should render in mobile-responsive layout
    And all content should be visible without horizontal scrolling
    And text should be readable without zooming
    When touch target sizes are measured for interactive elements
    Then all touch targets should be minimum "44" by "44" pixels
    And adequate spacing of minimum "8" pixels should exist between targets
    When user taps on alert item to expand details
    Then alert should expand smoothly
    And tap should be registered accurately
    And no accidental activation of adjacent elements should occur
    And expansion animation should be smooth
    When swipe gestures are tested on alert items
    Then swipe gestures should work consistently
    And alternative tap-based methods should be available
    And gestures should be discoverable
    When mobile screen reader is enabled and user navigates alerts
    Then screen reader should announce all alert content
    And swipe navigation should move through elements logically
    And double-tap should activate buttons
    And all functionality should be accessible
    When user tests acknowledge button with screen reader active
    Then button should be announced as "Acknowledge button"
    And double-tap should activate acknowledgment
    And confirmation should be announced
    And focus management should work correctly
    When device is rotated from portrait to landscape orientation
    Then layout should adapt to orientation change
    And all content should remain accessible
    And no functionality should be lost
    And focus should be maintained during rotation
    When mobile accessibility features are enabled
    Then interface should respect system accessibility settings
    And text should scale appropriately with larger text setting
    And text should display correctly with bold text setting
    And animations should be reduced when reduce motion is enabled