Feature: Accessible Task Commenting for Employee Communication
  As an Employee
  I want to perform commenting on tasks with full accessibility support
  So that all team members including those using assistive technologies can communicate effectively

  Background:
    Given user is logged in as an authenticated employee
    And user is on the task details page for an existing task

  @accessibility @a11y @priority-high @keyboard-navigation
  Scenario: Complete keyboard navigation for comment input and submission
    Given no mouse or pointing device is being used
    And browser supports standard keyboard navigation
    When user presses Tab key repeatedly from the top of the page until comment input field receives focus
    Then comment input field should receive focus with visible focus indicator
    And focus order should be logical following the visual layout
    When user types "Testing keyboard accessibility for comments" using the keyboard
    Then text should be entered successfully in the input field
    And characters should appear as typed without issues
    When user presses Tab key to move focus to "Save" button
    Then focus should move to "Save" button with visible focus indicator
    When user presses Enter key to activate "Save" button
    Then comment should be submitted successfully
    And success message "Comment added successfully" should be displayed
    And success message should be announced by screen readers
    When user presses Tab key to navigate through the newly added comment
    Then focus should move to the new comment element
    And comment content should be accessible and readable
    And focus indicator should be visible on the comment container
    When user presses Shift+Tab to navigate backwards through the page elements
    Then focus should move in reverse order logically
    And focus should return through "Save" button and comment input field
    And no keyboard traps should exist where focus cannot escape

  @accessibility @a11y @priority-high @screen-reader
  Scenario: Screen reader announcements and ARIA labels for comment functionality
    Given screen reader software is active and running
    And browser is compatible with screen reader
    When user navigates to the comment input field using screen reader navigation commands
    Then screen reader should announce "Comment input field, edit text" with role and label
    When user checks for ARIA label or aria-describedby attribute on the comment input field
    Then screen reader should announce additional context "Maximum 500 characters"
    When user types "Testing screen reader accessibility" in the input field
    Then screen reader should announce each character or word as typed
    And no announcement errors should occur
    When user navigates to "Save" button using screen reader commands
    Then screen reader should announce "Save button" with clear button role identification
    When user activates "Save" button using Enter key
    Then screen reader should announce "Comment added successfully"
    And ARIA live region should announce the update dynamically
    When user navigates to the comments section where the new comment appears
    Then screen reader should announce the comment content in logical order
    And screen reader should announce author name and timestamp
    And announcement should follow pattern "Comment by John Doe, posted 2 minutes ago: Testing screen reader accessibility"

  @accessibility @a11y @priority-high @focus-management
  Scenario: Focus management after successful comment submission
    Given keyboard navigation is being used exclusively
    And comment input field is visible and accessible
    When user navigates to the comment input field using Tab key
    And user enters "Testing focus management" in comment input field
    Then comment input field should receive focus with visible focus indicator
    And text should be entered successfully
    When user presses Tab to move to "Save" button
    And user presses Enter to submit the comment
    Then comment should be submitted successfully
    And success message should appear
    And focus should be automatically moved to logical location
    And focus should not be lost or moved to illogical location

  @accessibility @a11y @priority-high @focus-management @negative
  Scenario: Focus management after validation error
    Given keyboard navigation is being used exclusively
    And comment input field is visible and accessible
    When user navigates to the comment input field using Tab key
    And user enters a comment with 501 characters in comment input field
    And user presses Tab to move to "Save" button
    And user presses Enter to attempt submission
    Then validation error message "Comment must be 500 characters or less" should appear
    And error message should be displayed in red text
    And focus should be automatically moved to the error message
    And focus should be returned to the comment input field
    And focus should not be lost or trapped

  @accessibility @a11y @priority-medium @color-contrast
  Scenario Outline: Color contrast for comment interface elements
    Given browser has color contrast checking tools available
    And page is displayed at 100% zoom level
    When user measures the contrast ratio between "<element>" and "<background>"
    Then contrast ratio should be at least "<minimum_ratio>"
    And element should meet WCAG 2.1 Level AA requirements

    Examples:
      | element                          | background                | minimum_ratio |
      | comment input field border       | page background           | 3:1           |
      | comment text                     | input field background    | 4.5:1         |
      | focus indicator                  | adjacent background       | 3:1           |
      | Save button text                 | button background         | 4.5:1         |
      | success message text             | success message background| 4.5:1         |
      | error message text               | error message background  | 4.5:1         |

  @accessibility @a11y @priority-medium @color-contrast @keyboard-navigation
  Scenario: Focus indicator visibility and contrast
    Given browser has color contrast checking tools available
    When user focuses on the comment input field using Tab key
    Then focus indicator should have contrast ratio of at least 3:1 against adjacent background
    And focus indicator should be clearly visible
    And focus indicator should not rely solely on color

  @accessibility @a11y @priority-medium @color-contrast @negative
  Scenario: Error indication does not rely on color alone
    When user triggers a validation error
    Then error message should have contrast ratio of at least 4.5:1
    And error should be indicated by both color and icon or text label
    And error should not rely on color alone to convey meaning

  @accessibility @a11y @priority-medium @zoom
  Scenario: Comment interface functionality at 200% browser zoom
    Given browser zoom is initially set to 100%
    And browser window is at standard desktop resolution
    When user increases browser zoom to 200%
    Then page content should scale to 200% zoom level
    And layout should adjust appropriately
    And comment input field should be fully visible without horizontal scrolling
    And comment input field should be large enough to see at least 80 characters
    When user enters "Testing 200% zoom accessibility" in comment input field
    Then text entry should work normally
    And typed text should be clearly visible and readable at 200% zoom
    And no text overflow or truncation should occur
    When user clicks "Save" button
    Then comment should be submitted successfully
    And success message should be fully visible and readable at 200% zoom
    When user scrolls to view the newly added comment
    Then comment should be displayed correctly with proper text wrapping
    And author name and timestamp should be visible and readable
    And no content should be cut off or require horizontal scrolling

  @accessibility @a11y @priority-high @aria-live @screen-reader
  Scenario: ARIA live regions for successful comment submission
    Given screen reader software is active
    And ARIA live region exists for comment notifications
    When user enters "Testing ARIA live region" in comment input field
    And user submits comment using "Save" button
    Then screen reader should announce success message "Comment added successfully" via ARIA live region
    And announcement should occur without requiring user navigation

  @accessibility @a11y @priority-high @aria-live @screen-reader @negative
  Scenario: ARIA live regions for validation errors
    Given screen reader software is active
    And ARIA live region exists for comment notifications
    When user attempts to submit a comment with 501 characters
    Then screen reader should announce error message "Comment must be 500 characters or less" via ARIA live region
    And announcement should occur immediately when validation fails
    And ARIA live region should use aria-live polite attribute
    And announcements should not interrupt user input or navigation

  @accessibility @a11y @priority-high @aria-live @screen-reader
  Scenario: ARIA live regions for real-time comment notifications
    Given screen reader software is active
    And another team member has access to add comments to the same task
    When another team member adds a comment to the same task
    Then screen reader should announce "New comment added by [Author Name]" via ARIA live region
    And announcement should occur when new comment appears on page

  @accessibility @a11y @priority-medium @mobile @touch-targets
  Scenario: Mobile touch target sizes for comment interface
    Given user is on a mobile device
    And user is on the task details page using mobile browser
    And device is in portrait orientation
    When user measures the touch target size of comment input field
    Then comment input field should have minimum touch target size of 44x44 CSS pixels
    And touch target should meet WCAG 2.1 Level AAA requirements
    When user taps on the comment input field
    Then input field should be activated on first tap
    And mobile keyboard should appear
    And field should be focused with visible focus indicator
    And no double-tap should be required
    When user measures the touch target size of "Save" button
    Then "Save" button should have minimum touch target size of 44x44 CSS pixels
    And button should have adequate spacing from other interactive elements

  @accessibility @a11y @priority-medium @mobile @screen-reader
  Scenario: Mobile screen reader support for comment functionality
    Given user is on a mobile device
    And mobile screen reader is enabled
    And device is in portrait orientation
    When user navigates to comment input field using swipe gestures
    Then screen reader should announce "Comment input field, text field"
    And field should be easily discoverable through swipe navigation
    When user enters "Testing mobile accessibility" using mobile keyboard
    Then text entry should work correctly with screen reader active
    And screen reader should announce typed characters or words
    And no conflicts should exist between screen reader and keyboard input
    When user navigates to "Save" button using screen reader swipe gestures
    And user double-taps to activate "Save" button
    Then screen reader should announce "Save button"
    And comment should be submitted successfully
    And success announcement should be provided