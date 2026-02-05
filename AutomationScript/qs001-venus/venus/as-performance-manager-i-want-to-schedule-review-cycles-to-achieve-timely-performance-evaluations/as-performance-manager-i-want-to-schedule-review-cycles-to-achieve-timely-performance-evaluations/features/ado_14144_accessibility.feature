Feature: Accessibility compliance for review cycle scheduling
  As a Performance Manager with accessibility needs
  I want the review cycle scheduling interface to be fully accessible
  So that I can manage performance evaluations regardless of my abilities or assistive technology used

  Background:
    Given user is logged in as "Performance Manager"
    And user is on "Review Cycle Management" page

  @accessibility @a11y @priority-high @keyboard-navigation
  Scenario: Complete keyboard navigation through entire review cycle scheduling workflow
    Given no mouse or pointing device is used for this test
    When user presses Tab key repeatedly from page load
    Then focus indicator should move sequentially through all interactive elements
    And focus should be visible on navigation menu
    And focus should be visible on "Schedule New Review Cycle" button
    And focus should be visible on existing review cycle items
    And focus should be visible on edit and delete buttons
    And focus should be visible on calendar navigation controls
    When user navigates to "Schedule New Review Cycle" button using keyboard
    And user presses Enter key
    Then "Schedule Review Cycle" modal should open
    And focus should automatically move to "Review Cycle Name" field
    And visible focus indicator should be displayed
    When user presses Tab to navigate through form fields
    Then focus should move logically through "Cycle Name" field
    And focus should move logically through "Frequency" dropdown
    And focus should move logically through "Date Picker" field
    And focus should move logically through "Time Picker" field
    And focus should move logically through "Notification Settings" field
    And each field should show clear focus indicator
    And no focus traps should be encountered
    When user navigates to "Frequency" dropdown using keyboard
    And user presses Space key
    Then dropdown should open
    When user presses Arrow Down key
    And user presses Enter key on "Monthly" option
    Then "Monthly" option should be selected
    And dropdown should close
    And focus should return to dropdown trigger
    When user navigates to "Date Picker" field using keyboard
    And user presses Enter key
    Then calendar widget should open
    When user presses Arrow Right key
    Then focus should move to next date
    When user presses Arrow Left key
    Then focus should move to previous date
    When user presses Arrow Down key
    Then focus should move to date one week later
    When user presses Arrow Up key
    Then focus should move to date one week earlier
    And current focused date should be clearly highlighted
    When user presses Enter key on selected date
    Then date should be selected
    And calendar should close
    When user navigates to "Save Review Cycle" button using keyboard
    And user presses Enter key
    Then save action should be activated
    And success message should appear
    And success message should be keyboard accessible
    When user presses Escape key
    Then modal should close
    And focus should return to "Schedule New Review Cycle" button
    When user navigates to calendar view using Tab key
    And user presses Arrow keys to navigate between dates
    Then calendar should be keyboard navigable
    And all interactive elements should be reachable via keyboard

  @accessibility @a11y @priority-high @screen-reader
  Scenario: Screen reader announces all review cycle information and state changes correctly
    Given screen reader is active
    And at least 1 review cycle is already scheduled
    When user navigates to "Review Cycle Management" page
    Then screen reader should announce "Review Cycle Management" page title
    And screen reader should announce main heading level 1
    And screen reader should announce "You have X scheduled review cycles" summary
    And announcement should use appropriate ARIA live region
    When user navigates to "Schedule New Review Cycle" button using screen reader
    Then screen reader should announce "Schedule New Review Cycle, button"
    And screen reader should indicate element type
    And screen reader should announce any associated keyboard shortcuts
    When user activates "Schedule New Review Cycle" button
    Then screen reader should announce "Schedule Review Cycle dialog opened"
    And screen reader should announce modal title
    And screen reader should indicate focus has moved to first form field
    And screen reader should announce "Review Cycle Name, edit text, required"
    When user navigates through form fields using screen reader
    Then screen reader should announce label text for each field
    And screen reader should announce field type for each field
    And screen reader should announce required status for each field
    And screen reader should announce current value if any
    And screen reader should announce help text or instructions
    When user leaves required field empty
    And user activates "Save" button
    Then screen reader should announce "Error: Review Cycle Name is required" via ARIA live region
    And ARIA live region should use assertive politeness
    And focus should move to invalid field
    And screen reader should announce "Review Cycle Name, edit text, required, invalid entry"
    When user fills all fields correctly
    And user activates "Save" button
    Then screen reader should announce "Success: Review cycle scheduled successfully" via ARIA live region
    And modal should close
    And focus should return to main page
    And screen reader should announce "Review Cycle Management, X review cycles scheduled"
    When user navigates to calendar view using screen reader
    Then calendar structure should be announced with proper table semantics
    And each date cell should announce date and scheduled reviews
    And screen reader should announce "January 15, 2025, has 2 scheduled reviews: Q1 Performance Review at 9:00 AM, Monthly Check-in at 2:00 PM"

  @accessibility @a11y @priority-high @color-contrast @wcag-aa
  Scenario: Verify sufficient color contrast ratios for all text and interactive elements
    Given color contrast analyzer tool is available
    And page displays various states including default, hover, focus, active, disabled, and error
    When user measures contrast ratio between body text and background
    Then contrast ratio should be at least 4.5:1 for normal text
    And contrast ratio should be at least 3:1 for large text
    And contrast should meet WCAG 2.1 AA standards
    When user measures contrast ratio for "Schedule New Review Cycle" button text against button background
    Then button text should have minimum 4.5:1 contrast ratio
    When user hovers over "Schedule New Review Cycle" button
    And user measures contrast ratio in hover state
    Then hover state should maintain minimum 4.5:1 contrast ratio
    And button background color change should not be only indicator of hover state
    When user focuses on "Schedule New Review Cycle" button using keyboard
    And user measures contrast ratio of focus indicator
    Then focus indicator should have minimum 3:1 contrast ratio against adjacent colors
    And focus indicator should be at least 2 pixels thick
    When user measures contrast ratios for form field labels in scheduling modal
    Then labels should have 4.5:1 minimum contrast ratio
    When user measures contrast ratios for input text in scheduling modal
    Then input text should have 4.5:1 minimum contrast ratio
    When user measures contrast ratios for placeholder text in scheduling modal
    Then placeholder text should have 4.5:1 minimum contrast ratio
    When user measures contrast ratios for borders in scheduling modal
    Then borders should have 3:1 minimum contrast ratio for interactive elements
    When user triggers validation error
    And user measures contrast ratio of error message text
    Then error message text should have 4.5:1 minimum contrast
    And error indicators should have 3:1 minimum contrast
    And errors should not be indicated by color alone
    When user checks calendar view
    And user measures contrast for date numbers
    Then date numbers should have 4.5:1 minimum contrast
    When user measures contrast for selected dates
    Then selected dates should have 3:1 minimum contrast for interactive elements
    When user measures contrast for current date indicator
    Then current date indicator should have 3:1 minimum contrast
    When user measures contrast for scheduled review indicators
    Then scheduled review indicators should have 3:1 minimum contrast
    And information should not be conveyed by color alone

  @accessibility @a11y @priority-high @focus-management @modal
  Scenario: Test focus management and focus trap prevention in modal dialogs
    Given keyboard navigation is being used exclusively
    And at least 1 review cycle exists for testing
    When user navigates to "Schedule New Review Cycle" button using keyboard
    And user presses Enter key
    Then modal should open
    And focus should automatically move to "Review Cycle Name" field
    And visible focus indicator should be displayed
    When user presses Tab repeatedly to cycle through modal elements
    Then focus should move through all interactive elements in logical order
    And focus should move through form fields
    And focus should move through "Save" button
    And focus should move through "Cancel" button
    And focus should cycle back to first field
    When focus is on "Cancel" button
    And user presses Tab key
    Then focus should wrap to "Review Cycle Name" field
    And focus should not escape to page content behind modal
    When focus is on "Review Cycle Name" field
    And user presses Shift+Tab keys
    Then focus should wrap to "Cancel" button
    And focus trap should be maintained within modal
    When user presses Escape key while modal is open
    Then modal should close
    And focus should return to "Schedule New Review Cycle" button
    And no focus loss should occur
    When user navigates to existing review cycle
    And user activates "Delete" button
    Then confirmation dialog should open
    And focus should be on "Cancel" button
    And focus should be trapped within confirmation dialog
    When user presses Tab to navigate between buttons
    Then focus should move between "Cancel" and "Confirm Delete" buttons
    When user presses Escape key
    Then dialog should close
    And focus should return to "Delete" button
    And page content behind dialog should not be accessible while dialog is open

  @accessibility @a11y @priority-medium @zoom @text-scaling
  Scenario: Verify page functionality at 200% browser zoom level
    Given browser zoom is set to 100%
    And test viewport is at least 1280x720 pixels
    When user sets browser zoom to 200%
    Then page content should scale to 200% zoom
    And all text should be readable and larger
    And no horizontal scrolling should be required for main content
    And all text content should be visible without truncation
    And all text content should be visible without overlap
    And headings should be fully visible
    And labels should be fully visible
    And button text should be fully visible
    And body content should be fully visible
    When user navigates to "Schedule New Review Cycle" button at 200% zoom
    Then button should be fully visible with all text readable
    And button should remain clickable
    And no layout breaking should occur
    And no elements should be pushed off screen
    When user opens review cycle scheduling modal at 200% zoom
    Then modal should scale appropriately
    And all form fields should be visible and usable
    And labels should be associated with inputs
    And dropdown menus should function correctly
    And date pickers should function correctly
    When user navigates to calendar view at 200% zoom
    Then calendar should scale appropriately
    And date cells should be readable and clickable
    And scheduled reviews should be visible with readable text
    And navigation controls should be accessible
    When user tests all interactive elements at 200% zoom
    Then all interactive elements should remain functional
    And touch targets should be at least 44x44 pixels
    And no functionality should be lost due to zoom
    When user scrolls through entire page at 200% zoom
    Then all page content should be accessible via scrolling
    And no fixed position elements should obscure content
    And sticky headers should not block interactive elements
    And sticky footers should not block interactive elements

  @accessibility @a11y @priority-high @aria @semantic-html
  Scenario: Verify ARIA landmarks and semantic HTML structure for assistive technology navigation
    Given browser developer tools is open
    And screen reader is available for testing
    When user examines page structure for ARIA landmarks
    Then page should contain banner landmark
    And page should contain main content landmark
    And page should contain navigation landmark
    And page should contain complementary content landmark if applicable
    When user uses screen reader landmark navigation to navigate between regions
    Then screen reader should announce "Main navigation"
    And screen reader should announce "Main content: Review Cycle Management"
    And screen reader should announce "Complementary: Upcoming Reviews"
    And each landmark should be reachable via landmark navigation
    When user inspects heading structure using accessibility inspector
    Then page should have single H1 for "Review Cycle Management" page title
    And page should have H2 for "Scheduled Review Cycles" section
    And page should have H2 for "Calendar View" section
    And page should have H3 for subsections
    And no heading levels should be skipped
    When user opens review cycle scheduling modal
    And user examines modal for proper ARIA attributes
    Then modal should have role="dialog"
    And modal should have aria-modal="true"
    And modal should have aria-labelledby pointing to modal title
    And modal should have aria-describedby for modal description if present
    And focus should be trapped within dialog
    When user inspects form fields for proper labeling
    Then all form inputs should have associated labels via label element
    And required fields should have aria-required="true"
    And invalid fields should have aria-invalid="true"
    And invalid fields should have aria-describedby pointing to error message
    When user checks calendar component for proper semantics
    Then calendar should use role="grid" or semantic table
    And calendar should have proper row and column headers
    And date cells should have aria-label with full date
    And selected date should have aria-selected="true"
    And current date should have aria-current="date"
    When user verifies ARIA live regions for dynamic content updates
    Then success messages should use aria-live="polite" or "assertive"
    And error messages should use aria-live="polite" or "assertive"
    And loading states should announce via aria-live or aria-busy="true"
    And dynamic content changes should be announced to screen readers

  @accessibility @a11y @priority-medium @mobile @touch-targets
  Scenario: Test mobile accessibility with touch targets and screen reader on mobile devices
    Given user accesses page on mobile device with viewport 375x667 pixels
    And mobile screen reader is available
    When user loads review cycle management page on mobile device
    Then all touch targets should be minimum 44x44 pixels on iOS
    And all touch targets should be minimum 48x48 pixels on Android
    And adequate spacing should exist between targets
    When user enables mobile screen reader
    And user swipes right to navigate through page elements
    Then screen reader should announce each element in logical order
    And screen reader should announce proper labels
    And swipe gestures should navigate through all interactive elements
    And no elements should be skipped or unreachable
    When user navigates to "Schedule New Review Cycle" button using screen reader
    And user double-taps to activate
    Then button should be announced clearly
    And double-tap gesture should activate button
    And modal should open
    And screen reader should announce modal opening
    And focus should be on first field
    When user uses screen reader to navigate through form fields on mobile
    Then all form fields should be announced with labels and types
    And date picker controls should be accessible via screen reader gestures
    And dropdown controls should be accessible via screen reader gestures
    And custom controls should have proper mobile accessibility support
    When user performs pinch-to-zoom gesture on mobile device
    Then page should support pinch-to-zoom without viewport restrictions
    And content should reflow appropriately when zoomed
    And no horizontal scrolling should be required for main content
    When user navigates to calendar view on mobile
    And user tests touch interaction with scheduled reviews
    Then calendar should be touch-friendly with appropriately sized date cells
    And swipe gestures should navigate between months
    And tapping date cells should open review details
    And all interactions should work with screen reader enabled
    When user tests form submission with mobile screen reader enabled
    Then form should be completable using screen reader
    And submit button should be accessible
    And success message should be announced via screen reader after submission
    And focus management should work correctly on mobile