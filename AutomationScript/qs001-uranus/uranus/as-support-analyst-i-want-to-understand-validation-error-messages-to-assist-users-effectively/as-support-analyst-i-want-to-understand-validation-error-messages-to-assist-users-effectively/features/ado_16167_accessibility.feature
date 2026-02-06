Feature: Validation Error Documentation Accessibility for Support Analysts
  As a Support Analyst
  I want accessible validation error documentation
  So that I can effectively assist users regardless of my abilities or assistive technology needs

  Background:
    Given Support Analyst is logged into knowledge base system
    And validation error documentation page is loaded

  @accessibility @a11y @priority-high @keyboard-navigation
  Scenario: Complete keyboard navigation through validation error documentation without mouse
    Given mouse or trackpad is disconnected for testing
    And keyboard is the only input device available
    When user presses Tab key from browser address bar
    Then focus should move to first interactive element with visible focus indicator
    When user continues pressing Tab through all interactive elements
    Then focus should move in logical order through search bar, filter dropdowns, and error list items
    And focus indicator should be clearly visible with minimum "2px" outline
    And no focus traps should occur
    When user presses Shift+Tab to navigate backwards
    Then focus should move in reverse order correctly
    And all previously focused elements should be accessible in reverse
    When user navigates to search field using Tab
    And user enters "VAL-ERR-001" in search field
    And user presses Enter key
    Then search should execute successfully
    And focus should move to search results
    And results should be announced to assistive technologies
    When user uses Tab to navigate to first search result
    And user presses Enter key
    Then detailed documentation should open
    And focus should move to main heading of documentation page
    When user presses Escape key
    Then view should close
    And focus should return to search result link that triggered the action
    When user navigates to filter dropdown using Tab
    And user presses Space key to open dropdown
    And user uses Arrow keys to select filter option
    And user presses Enter to apply selection
    Then dropdown should open with Space or Enter
    And Arrow keys should navigate options
    And Enter should apply selection
    And Escape should close without applying

  @accessibility @a11y @priority-high @screen-reader
  Scenario: Screen reader announces validation error documentation with proper semantic structure
    Given "NVDA" screen reader is installed and running
    And screen reader is set to verbose mode
    When user activates screen reader heading navigation with H key
    Then screen reader should announce all headings in hierarchical order
    And "Validation Error Documentation" should be announced as main h1
    And error categories should be announced as h2
    And individual errors should be announced as h3
    When user navigates to search field using E key for edit fields
    Then screen reader should announce "Search validation errors, edit text" with proper label association
    When user navigates through list of validation errors using L key
    Then screen reader should announce "List with X items"
    And each error entry should be announced with format "Error code: VAL-ERR-001, Description: [description], list item 1 of X"
    When user activates validation error link
    Then screen reader should announce "Leaving list, heading level 1: [Error Code and Title]"
    And detailed description should be read with proper semantic structure
    When user navigates through troubleshooting steps using Down arrow
    Then screen reader should announce ordered list "List with X items"
    And each step should be read as "Step 1: [action], list item 1 of X" with proper numbering
    When user navigates to interactive buttons using Tab key
    Then screen reader should announce button purpose clearly as "Copy error code, button"
    When user navigates to interactive links using Tab key
    Then screen reader should announce link purpose clearly as "View related errors, link"
    When user uses screen reader landmark navigation with D key
    Then screen reader should announce "Main navigation" landmark
    And screen reader should announce "Search region" landmark
    And screen reader should announce "Main content" landmark
    And screen reader should announce "Complementary information" landmark
    And screen reader should announce "Content information footer" landmark

  @accessibility @a11y @priority-high @color-contrast
  Scenario: Color contrast ratios meet WCAG 2.1 AA standards throughout documentation
    Given color contrast analyzer tool is installed
    And documentation includes text, buttons, links, error indicators, and success messages
    When user checks body text color against background color using contrast analyzer
    Then contrast ratio should be at least "4.5:1" for normal text meeting WCAG AA standard
    When user checks heading text contrast ratios against backgrounds
    Then large text should have minimum "3:1" contrast ratio
    And preferably "4.5:1" for AA compliance
    When user analyzes link text color contrast in default state
    Then link should maintain minimum "4.5:1" contrast ratio
    When user analyzes link text color contrast in hover state
    Then link should maintain minimum "4.5:1" contrast ratio
    When user analyzes link text color contrast in focus state
    Then link should maintain minimum "4.5:1" contrast ratio
    When user analyzes link text color contrast in visited state
    Then link should maintain minimum "4.5:1" contrast ratio
    And links should be distinguishable from surrounding text without relying solely on color
    And underline or other indicator should be present
    When user checks error indicator colors against backgrounds
    Then error indicators should have "3:1" contrast ratio for UI components
    And error indicators should not rely solely on color
    And icons or text labels should accompany color coding
    When user verifies button text and background color combinations
    Then button text should have "4.5:1" contrast against button background
    And button should have "3:1" contrast against page background
    And disabled buttons should be clearly distinguishable
    When user tests focus indicators on interactive elements for color contrast
    Then focus indicators should have minimum "3:1" contrast ratio against adjacent colors
    And focus indicators should be clearly visible

  @accessibility @a11y @priority-high @color-contrast @dark-mode
  Scenario: Color contrast meets WCAG standards in dark mode
    Given color contrast analyzer tool is installed
    And dark mode is available
    When user switches to dark mode
    And user checks body text color against background color
    Then contrast ratio should be at least "4.5:1" for text
    When user checks UI components contrast
    Then contrast ratio should be at least "3:1" for UI components
    And dark mode should maintain same WCAG AA contrast standards

  @accessibility @a11y @priority-high @zoom @responsive
  Scenario: Documentation remains functional and readable at 200% browser zoom
    Given browser is set to standard viewport size "1920x1080"
    And browser zoom is set to "100" percent
    When user verifies documentation displays correctly at baseline
    Then all content should be visible and readable
    And content should be properly formatted
    When user increases browser zoom to "150" percent using Ctrl and plus key
    Then content should reflow appropriately
    And no horizontal scrolling should be required
    And all text should remain readable
    And no content overlap should occur
    When user increases browser zoom to "200" percent
    Then all content should remain accessible without horizontal scrolling
    And text should reflow within viewport
    And no content should be cut off or hidden
    And all functionality should remain operational
    When user navigates through documentation using keyboard at "200" percent zoom
    Then focus indicators should remain visible
    And Tab navigation should work correctly
    And focused elements should scroll into view automatically
    When user uses search functionality at "200" percent zoom
    And user enters search term in search field
    And user views search results
    Then search field should be fully visible and functional
    And search results should display without layout breaking
    And results should be readable and clickable
    When user opens detailed troubleshooting steps at "200" percent zoom
    Then modal or detail view should open correctly
    And all content should be readable
    And close button should be visible and accessible
    And no content overflow issues should occur
    When user resizes browser window at "200" percent zoom
    Then content should continue to reflow appropriately
    And mobile responsive breakpoints should trigger correctly
    And no loss of functionality should occur

  @accessibility @a11y @priority-medium @aria-live @dynamic-content
  Scenario: ARIA live regions announce dynamic content updates for real-time changes
    Given screen reader "NVDA" is active and running
    And documentation system supports real-time updates
    And ARIA live regions are implemented for dynamic content
    When administrator publishes new validation error entry
    Then screen reader should announce "New validation error added: [Error Code]" via ARIA live region
    And user focus should not move
    When user performs search for validation error that returns results dynamically
    Then screen reader should announce "Search results updated, X results found"
    And aria-live should be set to "polite" to avoid interrupting user
    When user applies filter to error list that updates content dynamically
    Then screen reader should announce "Filter applied, showing X of Y errors"
    And current reading position should not be disrupted
    When user triggers error state during documentation loading
    Then screen reader should immediately announce "Error: Unable to load documentation. Please try again."
    And aria-live should be set to "assertive" for critical information
    When user receives notification that documentation has been updated
    Then screen reader should announce "This documentation has been updated. Refresh to view latest version."
    And polite live region should be used
    When user uses pagination to load additional error entries
    Then screen reader should announce "Loading more results"
    And screen reader should announce "X additional errors loaded" when content appears

  @accessibility @a11y @priority-medium @mobile @touch-targets
  Scenario: Mobile accessibility with touch targets and gesture support on tablets
    Given Support Analyst is accessing knowledge base on tablet device
    And validation error documentation is loaded in mobile browser
    And touch screen is primary input method
    And device is in portrait orientation
    When user measures all interactive elements using browser developer tools
    Then all touch targets should be minimum "44x44" CSS pixels
    And adequate spacing should exist between targets
    When user taps on search field
    Then search field should activate on first tap
    And virtual keyboard should appear
    And field should be large enough to tap accurately without hitting adjacent elements
    When user taps on validation error list items
    Then list items should respond to single tap
    And no accidental activations of adjacent items should occur
    And tap area should include entire list item row
    When user uses pinch-to-zoom gesture on documentation content
    Then pinch-to-zoom should work smoothly up to "200" percent
    And content should reflow appropriately
    And no horizontal scrolling should be required after zoom
    When user rotates device from portrait to landscape orientation
    Then documentation should reflow correctly
    And all content should remain accessible
    And touch targets should maintain minimum size requirements
    And no functionality should be lost
    When user tests swipe gestures for navigation
    Then swipe gestures should work consistently
    And alternative navigation methods should be available for users who cannot perform gestures
    When user enables "VoiceOver" accessibility feature on iOS device
    And user navigates documentation
    Then mobile screen reader should announce all content correctly
    And touch exploration should work
    And double-tap to activate should function properly

  @accessibility @a11y @priority-medium @mobile @touch-targets @android
  Scenario: Mobile accessibility with TalkBack on Android tablets
    Given Support Analyst is accessing knowledge base on Android tablet
    And validation error documentation is loaded in Chrome mobile browser
    And touch screen is primary input method
    When user enables "TalkBack" accessibility feature on Android device
    And user navigates documentation
    Then mobile screen reader should announce all content correctly
    And touch exploration should work
    And double-tap to activate should function properly

  @accessibility @a11y @priority-high @focus-management @modal
  Scenario: Focus management and focus trap prevention in modal dialogs
    Given validation error documentation includes modal dialogs for detailed views
    And keyboard is primary input method
    And screen reader is active
    When user navigates to validation error entry
    And user presses Enter to open detailed view in modal dialog
    Then modal should open
    And focus should automatically move to first focusable element in modal
    And screen reader should announce modal title and role "dialog"
    When user presses Tab key repeatedly within modal
    Then focus should cycle only through elements within modal
    And focus trap should be active
    And focus should move in logical order through modal content
    And background content should not be accessible via Tab
    When user presses Shift+Tab from first focusable element in modal
    Then focus should move to last focusable element in modal
    And circular focus trap should be active
    And focus should not escape to background content
    When user presses Escape key while modal is open
    Then modal should close
    And focus should return to validation error link that triggered modal
    And screen reader should announce modal closure
    When user reopens modal
    And user clicks close button
    Then modal should close
    And focus should return to triggering element
    And no focus should be lost or moved to unexpected location
    When user verifies background content while modal is open
    Then background content should have aria-hidden attribute set to "true"
    And clicking background should not activate background elements
    And screen reader should not read background content
    When user tests with screen reader virtual cursor
    Then screen reader should announce modal beginning and end
    And virtual cursor navigation should be contained within modal
    And background content should not be accessible via virtual cursor