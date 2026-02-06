Feature: Schedule Change Notification Accessibility
  As a user with accessibility needs
  I want schedule change notifications to be fully accessible via keyboard, screen readers, and assistive technologies
  So that I can stay informed about my commitments regardless of my abilities

  @accessibility @a11y @priority-high @keyboard-navigation
  Scenario: Complete keyboard navigation through notification center and acknowledgment workflow
    Given user is logged into the system
    And user has 3 unread schedule change notifications in the notification center
    And keyboard is the only input device being used
    And browser supports standard keyboard navigation
    When user presses Tab key repeatedly from the main page header until notification icon receives focus
    Then notification icon should display visible focus indicator
    And screen reader should announce "Notifications, 3 unread, button"
    When user presses Enter key to open notification center
    Then notification center should open
    And focus should automatically move to the first notification in the list
    When user presses Tab key to navigate through each notification item
    Then focus should move sequentially through each notification with visible focus indicator
    And screen reader should announce notification content including appointment details and time change
    When user presses Enter key on the first notification to view full details
    Then notification should expand or open detail view
    And focus should remain on the notification or move to the detail content
    When user presses Tab key to navigate to the acknowledge button
    Then focus should move to the acknowledge button with visible focus indicator
    And screen reader should announce "Acknowledge notification, button"
    When user presses Enter key to acknowledge the notification
    Then notification should be marked as read
    And visual indicator should change
    And screen reader should announce "Notification acknowledged" confirmation
    When user presses Escape key to close the notification center
    Then notification center should close
    And focus should return to the notification icon in the navigation bar
    When user presses Tab key to continue navigation
    Then focus should move logically to the next focusable element without focus traps
    And unread notification count should update from 3 to 2

  @accessibility @a11y @priority-high @screen-reader
  Scenario: Screen reader announces schedule change notifications with complete and accurate information
    Given screen reader software is installed and running
    And user is logged into the system
    And user has notification preferences enabled
    And system has one scheduled appointment ready to be modified
    When user navigates to the schedule with screen reader active
    And user modifies an appointment time from "2:00 PM" to "3:30 PM"
    Then schedule change should be saved successfully
    When user waits up to 1 minute for the notification to arrive
    And user navigates to the notification icon using Tab key
    Then screen reader should announce "Notifications, 1 unread, button"
    When user presses Enter to open the notification center
    Then screen reader should announce "Notification center opened"
    And screen reader should read the first notification heading or summary
    When user navigates to the new notification using arrow keys
    Then screen reader should announce complete notification content with appointment name and time change from "2:00 PM" to "3:30 PM"
    And screen reader should announce "Unread" status
    When user navigates to the notification timestamp
    Then screen reader should announce the time notification was received
    When user navigates to the acknowledge button
    Then screen reader should announce "Acknowledge notification, button"
    When user activates the acknowledge button using Enter key
    Then screen reader should announce "Notification acknowledged" confirmation
    And notification status should change to read

  @accessibility @a11y @priority-high @aria-live-region
  Scenario: ARIA live region announces new notifications in real-time without page refresh
    Given screen reader software is active
    And user is logged into the system and on the dashboard page
    And user has notification preferences enabled
    And no unread notifications currently exist
    And ARIA live region is implemented for notification announcements
    When user remains on the dashboard page without interacting with any elements
    And another administrator modifies the user's schedule appointment time
    And user waits up to 1 minute without refreshing the page
    Then screen reader should automatically announce the new notification via ARIA live region with appointment name and time change
    And notification badge should update to show 1 unread notification
    And screen reader should announce "Notifications, 1 unread"
    When user navigates to the notification icon using Tab key
    Then screen reader should announce "Notifications, 1 unread, button"
    When user opens notification center
    Then notification center should open with the new schedule change notification visible and accessible

  @accessibility @a11y @priority-high @color-contrast @wcag
  Scenario: Notification center and email notifications meet WCAG 2.1 color contrast requirements
    Given user is logged into the system
    And user has at least one unread schedule change notification
    And color contrast analyzer tool is available
    And email notification has been received in user's inbox
    When user opens the notification center and locates an unread notification
    Then unread notification should be displayed with distinct visual styling
    When user measures contrast ratio between notification text and background using color contrast analyzer
    Then contrast ratio should be at least "4.5:1" for normal text or "3:1" for large text
    When user measures contrast ratio between unread notification indicator and its background
    Then contrast ratio should be at least "3:1" for non-text UI components
    When user checks notification timestamp text contrast against its background
    Then timestamp text should have contrast ratio of at least "4.5:1"
    When user opens email notification and measures text contrast
    Then email notification body text should have contrast ratio of at least "4.5:1" against background
    When user verifies schedule change details presentation
    Then changes should be indicated by text labels, icons, or formatting in addition to any color coding
    When user tests notification center in high contrast mode
    Then all notification content should remain visible and readable in high contrast mode

  @accessibility @a11y @priority-medium @zoom @responsive
  Scenario Outline: Notification center remains fully functional and readable at various browser zoom levels
    Given user is logged into the system using a desktop browser
    And browser zoom level is set to "100%"
    And user has at least 5 unread schedule change notifications
    And screen resolution is set to "1920x1080" or higher
    When user opens the notification center at "100%" zoom
    Then notification center should display correctly with all 5 notifications visible and readable
    When user increases browser zoom to "<zoom_level>"
    Then browser zoom should increase to "<zoom_level>"
    And page content should scale proportionally
    When user clicks the notification icon to open notification center
    Then notification center should open and be fully visible without horizontal scrolling required
    And all notification text should be readable without truncation or overlapping
    When user scrolls through the notification list
    Then vertical scrolling should work smoothly
    And all notifications should be accessible without hidden content
    When user clicks on a notification to view full details
    Then notification detail view should open without requiring horizontal scrolling
    When user navigates to and clicks the acknowledge button
    Then button should be fully visible, clickable, and functional at "<zoom_level>" zoom

    Examples:
      | zoom_level |
      | 150%       |
      | 175%       |
      | 200%       |

  @accessibility @a11y @priority-high @focus-management @modal
  Scenario: Focus management and focus trap prevention when notification modal opens
    Given user is logged into the system
    And user has at least one unread schedule change notification
    And keyboard is the primary input device
    And notification center opens as a modal dialog or overlay panel
    When user navigates to the notification icon using Tab key from the page header
    Then notification icon should receive visible focus indicator
    When user presses Enter key to open the notification center modal
    Then notification center should open
    And focus should automatically move to the first focusable element inside
    When user presses Tab key repeatedly to navigate through all focusable elements
    Then focus should move sequentially through close button, notification items, acknowledge buttons, and other interactive elements
    When user continues pressing Tab after reaching the last focusable element
    Then focus should cycle back to the first focusable element within the modal
    When user presses Shift and Tab to navigate backwards
    Then focus should move in reverse order through all interactive elements
    And focus should cycle to the last element when reaching the first element
    When user presses Escape key to close the notification center
    Then notification center should close
    And focus should return to the notification icon that originally opened it
    When user reopens the notification center and navigates to close button
    And user presses Enter on close button
    Then notification center should close
    And focus should return to the notification icon
    When user verifies focus behavior while modal is open
    Then focus should never move to elements behind the modal
    And background page elements should not be focusable while modal is open