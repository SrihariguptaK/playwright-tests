Feature: Accessible Schedule Change Notifications
  As a user with accessibility needs
  I want to interact with schedule change notifications using assistive technologies and alternative input methods
  So that I can stay informed about my commitments regardless of my abilities

  Background:
    Given user is logged into the system with valid credentials

  @accessibility @a11y @priority-high @keyboard-navigation
  Scenario: Complete keyboard navigation through notification center
    Given user has 5 unread schedule change notifications in notification center
    And browser is set to standard keyboard navigation mode
    And no mouse or pointing device is used
    When user presses Tab key repeatedly from main page header
    Then focus indicator should move through page elements in logical order
    And focus should reach notification bell icon with clear visual focus indicator
    When user presses Enter key on notification bell icon
    Then notification center panel should open
    And focus should automatically move to first notification in list
    And notification count badge should be visible
    When user presses Tab key to navigate through each notification
    Then focus should move sequentially through each notification item with visible focus indicator
    And notification details should be readable
    And focus should not get trapped
    When user presses Enter key on focused notification
    Then notification should expand or detail modal should open
    And focus should move to notification detail content
    And all interactive elements should be keyboard accessible
    When user presses Tab to navigate to "Acknowledge" button
    And user presses Enter key
    Then notification should be marked as acknowledged
    And visual confirmation should appear
    And focus should return to logical location
    When user presses Escape key
    Then notification center should close
    And focus should return to notification bell icon
    And notification count should update to reflect acknowledged notification
    When user presses Shift+Tab to navigate backwards
    Then focus should move in reverse order through all previously accessible elements
    And focus should not skip or trap

  @accessibility @a11y @priority-high @screen-reader
  Scenario: Screen reader announces schedule change notifications with complete context
    Given user has notification preferences enabled for in-app alerts
    And user is on dashboard page
    And screen reader is enabled
    And screen reader is set to announce live regions and notifications
    When administrator updates user scheduled appointment from "2:00 PM" to "3:00 PM"
    Then screen reader should immediately announce new notification via ARIA live region
    And announcement should include "Alert: Schedule change notification. Your appointment has been changed from 2:00 PM to 3:00 PM"
    When user navigates to notification bell icon using screen reader navigation commands
    Then screen reader should announce "Notifications button, 1 unread notification"
    When user activates notification bell icon using Enter key
    Then screen reader should announce "Notification center opened, list of 1 notification"
    And screen reader should read first notification summary
    When user navigates through notification using arrow keys
    Then screen reader should announce notification type "Schedule change"
    And screen reader should announce original time "2:00 PM"
    And screen reader should announce new time "3:00 PM"
    And screen reader should announce date and timestamp
    When user navigates to "Acknowledge" button within notification
    Then screen reader should announce "Acknowledge button" with appropriate role and state
    When user activates "Acknowledge" button using Enter key
    Then screen reader should announce "Notification acknowledged"
    And screen reader should announce updated state "Notification marked as read"
    When user navigates to notification history section
    Then screen reader should announce "Notification history, list of X items"
    And screen reader should provide context about past notifications being available
    When user navigates through past notifications using screen reader commands
    Then screen reader should announce each past notification with full context
    And screen reader should announce date, time, and acknowledgment status

  @accessibility @a11y @priority-high @focus-management
  Scenario: Focus management and focus trap prevention in notification modal dialogs
    Given user has 1 schedule change notification available
    And notification detail view opens in modal dialog
    When user navigates to notification center using Tab key
    And user opens notification center with Enter key
    Then notification center should open
    And focus should be placed on first focusable element within panel
    When user presses Enter on notification to open detailed view modal
    Then modal dialog should open
    And focus should automatically move to first focusable element in modal
    And background content should be inert
    When user presses Tab key repeatedly to cycle through all focusable elements
    Then focus should move through all interactive elements in logical order
    And focus should include notification details, "Acknowledge" button, "Close" button
    When user continues pressing Tab after reaching last focusable element
    Then focus should wrap back to first focusable element in modal
    And focus should not escape to background page elements
    When user presses Shift+Tab from first focusable element
    Then focus should move to last focusable element in modal
    When user presses Escape key while focus is anywhere in modal
    Then modal should close
    And focus should return to element that triggered modal
    And background content should become focusable again
    When user opens modal again
    And user clicks "Acknowledge" button using Enter key
    Then notification should be acknowledged
    And modal should close
    And focus should return to notification list or next unread notification
    And visual focus indicator should be clearly visible

  @accessibility @a11y @priority-high @color-contrast
  Scenario: Color contrast ratios and non-color-dependent information in notification UI
    Given user has multiple notifications with different statuses
    And notifications include different priority levels or types
    And color contrast analyzer tool is available
    When user opens notification center
    And user checks contrast ratio between notification text and background
    Then text contrast ratio should meet WCAG 2.1 AA standards minimum 4.5:1 for normal text
    And text contrast ratio should meet 3:1 for large text
    And all notification text should be readable
    When user checks contrast ratio of notification bell icon and background
    Then icon contrast ratio should meet WCAG 2.1 AA standards minimum 3:1 for UI components
    And notification count badge should have sufficient contrast minimum 4.5:1
    When user identifies how unread notifications are distinguished from read notifications
    Then unread notifications should use multiple indicators beyond color
    And indicators should include bold text, icon, or text label
    And notifications should not rely solely on color difference
    When user checks how different notification types or priorities are indicated
    Then notification priority should be indicated through multiple methods
    And methods should include icons, text labels, and patterns
    And priority should not be indicated by color alone
    When user enables browser high contrast mode
    Then all notification elements should remain visible and distinguishable
    And text should be readable
    And interactive elements should be identifiable
    And no information should be lost
    When user checks "Acknowledge" button and other interactive elements for contrast
    Then button text and borders should have sufficient contrast minimum 3:1
    And button states should be distinguishable without relying on color alone
    When user verifies timestamp and metadata text contrast
    Then all secondary text should meet minimum contrast requirements of 4.5:1 against background

  @accessibility @a11y @priority-medium @zoom-scaling
  Scenario: Notification interface usability at 200% browser zoom and text scaling
    Given user has 3 schedule change notifications with varying content lengths
    And browser supports zoom functionality
    And notification center contains notifications with full details
    When user sets browser zoom to 200 percent
    Then page should zoom to 200 percent
    And all content should scale proportionally
    And notification bell icon should remain visible and accessible
    When user clicks notification bell icon at 200 percent zoom
    Then notification center should open and display correctly
    And no content should be cut off or hidden
    And horizontal scrolling should not be required for notification content
    When user navigates through notification list at 200 percent zoom
    Then all notifications should be readable
    And text should wrap appropriately
    And no overlapping content should exist
    And vertical scrolling should work smoothly if needed
    When user opens notification detail view at 200 percent zoom
    Then modal or detail view should display correctly
    And all content should be accessible without horizontal scrolling
    And buttons and interactive elements should be fully visible and clickable
    When user tests "Acknowledge" button at 200 percent zoom
    Then all buttons should be large enough to click easily
    And buttons should meet minimum 44x44 CSS pixels touch target
    And button text should be fully visible
    And no UI elements should overlap
    When user enables browser text-only zoom to 200 percent
    Then text should scale to 200 percent while layout adapts
    And all text should remain readable without truncation
    And containers should expand to accommodate larger text
    And no text should overlap other elements
    When user verifies notification timestamps at 200 percent zoom
    Then all secondary information should remain visible and readable
    And proper spacing should be maintained between elements
    And no information should be hidden or cut off

  @accessibility @a11y @priority-high @aria-implementation
  Scenario: ARIA roles, labels, and live region implementation for dynamic notification updates
    Given user is on dashboard page
    And browser developer tools are open to inspect ARIA attributes
    And user has notification preferences enabled
    And administrator account is available to trigger schedule changes
    When user inspects notification bell icon element in browser developer tools
    Then element should have role "button"
    And element should have aria-label "Notifications" or "View notifications"
    And element should have aria-haspopup "true"
    And element should have aria-expanded "false" when closed
    When user checks notification count badge for ARIA implementation
    Then badge should have aria-label describing count
    And screen readers should announce the count
    When administrator creates new schedule change while user inspects notification area
    Then ARIA live region should announce new notification
    And live region should have aria-live "polite" or "assertive"
    And live region should contain descriptive text about schedule change
    And announcement should not interrupt user current task
    When user opens notification center and inspects notification list container
    Then container should have role "list" or role "region" with aria-label "Notifications"
    And individual notifications should have role "listitem" or appropriate semantic structure
    When user inspects individual notification elements for ARIA attributes
    Then each notification should have aria-label or aria-labelledby providing complete context
    And unread status should be indicated with aria-describedby or within aria-label
    And interactive elements should have appropriate roles
    When user inspects "Acknowledge" button for ARIA implementation
    Then button should have role "button"
    And button should have aria-label "Acknowledge notification" or similar descriptive label
    And button should have aria-pressed or aria-checked if it represents toggle state
    When user acknowledges notification and checks for ARIA live region update
    Then ARIA live region should announce acknowledgment
    And notification count should update and be announced
    And aria-expanded should update if notification center closes
    When user inspects modal dialog for notification details for ARIA attributes
    Then modal should have role "dialog"
    And modal should have aria-modal "true"
    And modal should have aria-labelledby pointing to modal title
    And modal should have aria-describedby pointing to modal content if applicable

  @accessibility @a11y @priority-medium @mobile-accessibility
  Scenario: Mobile accessibility including touch target sizes and gesture alternatives
    Given user is on mobile device or mobile browser emulation
    And user has 5 schedule change notifications available
    And mobile screen reader is available for testing
    And touch screen functionality is enabled
    When user measures notification bell icon touch target size on mobile
    Then touch target should be minimum 44x44 CSS pixels
    And adequate spacing should exist between notification icon and adjacent interactive elements minimum 8 pixels
    When user taps notification bell icon to open notification center
    Then notification center should open reliably with single tap
    And no accidental activation of adjacent elements should occur
    And visual feedback should confirm tap
    When user verifies touch target sizes for individual notifications in list
    Then each notification item should have minimum 44x44 pixel touch target
    And adequate spacing between notifications should prevent accidental taps
    And entire notification area should be tappable
    When user tests swipe gestures on notifications
    Then swipe gestures should work reliably
    And alternative tap-based methods should be available for all swipe actions
    And gesture hints or instructions should be provided for discoverability
    When user enables mobile screen reader and navigates to notification center
    Then screen reader should announce notification bell with count
    And double-tap gesture should open notification center
    And all notifications should be accessible via swipe navigation
    When user uses screen reader to navigate through notifications and activate "Acknowledge" button
    Then each notification should be announced with full context
    And "Acknowledge" button should be clearly labeled and accessible
    And double-tap should activate button
    And confirmation should be announced
    When user tests notification modal or detail view on mobile with screen reader
    Then modal should open and focus should be managed correctly
    And all content should be accessible via swipe gestures
    And close button should have adequate touch target size 44x44 pixels
    And modal should be dismissible with standard gestures
    When user rotates device between portrait and landscape orientation
    Then notification interface should adapt to both orientations
    And all content should remain accessible
    And no functionality should be lost in either orientation
    And layout should adjust appropriately