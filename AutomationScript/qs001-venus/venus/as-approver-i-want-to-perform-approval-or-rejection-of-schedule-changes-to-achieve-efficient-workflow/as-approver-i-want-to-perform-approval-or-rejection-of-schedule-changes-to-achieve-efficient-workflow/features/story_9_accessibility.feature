Feature: Approval Workflow Accessibility Compliance
  As an Approver using assistive technologies
  I want to perform approval or rejection of schedule changes using keyboard navigation and screen readers
  So that I can efficiently manage workflow regardless of my accessibility needs

  Background:
    Given user is logged in with "Approver" role
    And at least one pending schedule change request exists

  @accessibility @a11y @priority-high @keyboard-navigation
  Scenario: Complete keyboard navigation for approval workflow without mouse interaction
    Given user is on the approver dashboard
    And keyboard is the only input device being used
    When user presses Tab key repeatedly to navigate to "Pending Requests" link
    Then focus indicator should move sequentially through interactive elements
    And "Pending Requests" link should receive visible focus with clear border
    When user presses Enter key on "Pending Requests" link
    Then "Pending Requests" page should load successfully
    And focus should move to first interactive element on the page
    When user uses Tab key to navigate through pending requests list
    And user presses Enter on a specific request
    Then request details modal should open
    And focus should move through each request row with visible focus indicator
    When user uses Tab to navigate to "Approve" button in request details
    And user presses Enter to open approval dialog
    Then approval dialog should open
    And focus should automatically move to first interactive element in dialog
    And focus should be trapped within the modal
    When user types approval comment using keyboard
    And user presses Tab to navigate to "Confirm Approval" button
    And user presses Enter on "Confirm Approval" button
    Then comment should be entered successfully
    And approval should be submitted
    And focus should return to logical position after modal closes
    When user presses Escape key when approval dialog is open
    Then dialog should close without submitting approval
    And focus should return to "Approve" button

  @accessibility @a11y @priority-high @screen-reader
  Scenario: Screen reader announces all critical information and state changes during approval process
    Given screen reader software is active
    And user is on the pending requests page
    When user navigates to pending requests page
    Then screen reader should announce page title "Pending Schedule Change Requests"
    And screen reader should announce main heading level 1
    And screen reader should announce "You have 5 pending requests"
    When user navigates through pending requests table using screen reader table navigation
    Then screen reader should announce "Table with 5 rows and 6 columns"
    And screen reader should announce column headers "Request ID, Requester Name, Submission Date, Status, Actions"
    And screen reader should announce cell content for each row
    When user focuses on "Approve" button for a specific request
    Then screen reader should announce "Approve button, for request ID 12345 submitted by John Doe"
    And screen reader should announce appropriate role and state information
    When user activates "Approve" button
    Then screen reader should announce "Approval dialog, heading level 2: Approve Schedule Change Request"
    And screen reader should announce "Comment text area, optional"
    And screen reader should announce "Confirm Approval button"
    When user enters comment in text area
    Then screen reader should provide character echo as user types
    And screen reader should announce "Comment text area, has text"
    When user submits approval
    Then screen reader should announce "Success: Schedule change request has been approved successfully"
    And announcement should use appropriate alert or status role
    When user navigates to request history
    Then screen reader should announce approved request with updated status
    And screen reader should announce "Request ID 12345, Status: Approved, Approved by [Approver Name] on [Date]"

  @accessibility @a11y @priority-high @focus-management
  Scenario: Focus management and focus trap behavior in approval modal
    Given user is on the pending requests page
    And keyboard is being used for navigation
    When user navigates to a pending request using Tab key
    And user presses Enter on "Approve" button
    Then approval modal should open
    And focus should automatically move to first focusable element inside modal
    When user presses Tab key repeatedly to cycle through modal elements
    Then focus should move through comment text area, "Confirm Approval" button, "Cancel" button, and close icon
    And focus should cycle back to first element
    And focus should remain trapped within modal
    And focus should not move to background content
    When user presses Shift+Tab to navigate backwards
    Then focus should move in reverse order through modal elements
    And focus should cycle from first element to last element
    When user presses Escape key
    Then modal should close
    And focus should return to "Approve" button with visible focus indicator
    When user opens approval modal again
    And user presses Enter on "Cancel" button
    Then modal should close
    And focus should return to "Approve" button with visible focus indicator
    When user presses Enter on "Reject" button
    Then rejection modal should open
    And focus should be on comment text area
    And focus trap should work correctly
    And Escape key should return focus to "Reject" button

  @accessibility @a11y @priority-high @focus-management
  Scenario: Focus management and focus trap behavior in rejection modal
    Given user is on the pending requests page
    And keyboard is being used for navigation
    When user navigates to a pending request using Tab key
    And user presses Enter on "Reject" button
    Then rejection modal should open
    And focus should be on comment text area
    And focus trap should work correctly
    When user presses Escape key
    Then modal should close
    And focus should return to "Reject" button with visible focus indicator

  @accessibility @a11y @priority-high @color-contrast @wcag-aa
  Scenario Outline: Color contrast ratios meet WCAG 2.1 AA standards for all elements
    Given user is on the pending requests page
    And color contrast checking tool is available
    When user measures contrast ratio of "<element_type>" element "<element_name>"
    Then contrast ratio should be at least "<minimum_ratio>"
    And element should meet WCAG 2.1 AA standard

    Examples:
      | element_type        | element_name                                  | minimum_ratio |
      | page heading        | Pending Schedule Change Requests              | 4.5:1         |
      | body text           | requester names in table                      | 4.5:1         |
      | body text           | dates in table                                | 4.5:1         |
      | body text           | request details in table                      | 4.5:1         |
      | button text         | Approve button default state                  | 4.5:1         |
      | button text         | Reject button default state                   | 4.5:1         |
      | button text         | Approve button hover state                    | 4.5:1         |
      | button text         | Reject button hover state                     | 4.5:1         |
      | button text         | Approve button focus state                    | 4.5:1         |
      | button text         | Reject button focus state                     | 4.5:1         |
      | status badge text   | Pending status badge                          | 4.5:1         |
      | status badge text   | Approved status badge                         | 4.5:1         |
      | status badge text   | Rejected status badge                         | 4.5:1         |
      | feedback message    | error message text                            | 4.5:1         |
      | feedback message    | success message text                          | 4.5:1         |
      | feedback message    | validation text                               | 4.5:1         |
      | link text           | link default state                            | 4.5:1         |
      | link text           | link visited state                            | 4.5:1         |
      | link text           | link hover state                              | 4.5:1         |
      | link text           | link focus state                              | 4.5:1         |

  @accessibility @a11y @priority-high @color-contrast @wcag-aa
  Scenario: Button backgrounds and focus indicators meet contrast requirements
    Given user is on the pending requests page
    And color contrast checking tool is available
    When user measures contrast ratio of button background against page background
    Then contrast ratio should be at least "3:1"
    When user measures contrast ratio of focus indicator against background
    Then contrast ratio should be at least "3:1"

  @accessibility @a11y @priority-high @color-contrast @wcag-aa
  Scenario: Status indicators are distinguishable by more than color alone
    Given user is on the pending requests page
    When user views status badges for "Pending" requests
    Then status should be distinguishable by icons or text labels
    And status should not be conveyed by color alone
    When user views status badges for "Approved" requests
    Then status should be distinguishable by icons or text labels
    And status should not be conveyed by color alone
    When user views status badges for "Rejected" requests
    Then status should be distinguishable by icons or text labels
    And status should not be conveyed by color alone

  @accessibility @a11y @priority-medium @zoom @responsive
  Scenario: Page functionality and layout at 200% browser zoom level
    Given user is on the pending requests page
    And browser zoom is set to "100" percent
    And browser window is at standard desktop resolution
    When user sets browser zoom to "200" percent
    Then page content should scale to "200" percent zoom level
    And all content should remain visible without horizontal scrolling
    When user verifies pending requests table at "200" percent zoom
    Then table columns should adjust responsively
    And text should be readable without overlapping
    And all data should be accessible
    When user navigates through page using keyboard at "200" percent zoom
    Then all buttons should remain accessible and functional
    And all links should remain accessible and functional
    And all form fields should remain accessible and functional
    And focus indicators should be visible
    And no content should be cut off or hidden
    When user opens approval modal at "200" percent zoom
    Then modal dialog should scale appropriately
    And all modal content should be visible without scrolling within modal
    And modal heading should be fully visible
    And comment field should be fully visible
    And buttons should be fully visible
    And modal can be closed using keyboard
    When user tests approval workflow at "200" percent zoom
    And user selects request
    And user approves with comments
    Then entire approval workflow should function correctly
    And all text should be readable
    And buttons should be clickable
    And success message should be fully visible
    When user checks navigation menu at "200" percent zoom
    Then navigation elements should scale appropriately
    And navigation should remain accessible
    And navigation should not overlap with main content
    When user checks header at "200" percent zoom
    Then header should scale appropriately
    And header should remain accessible
    And header should not overlap with main content
    When user checks footer at "200" percent zoom
    Then footer should scale appropriately
    And footer should remain accessible
    And footer should not overlap with main content

  @accessibility @a11y @priority-high @aria @semantic-markup
  Scenario: ARIA labels and roles are properly implemented for pending requests table
    Given user is on the pending requests page
    And browser developer tools are open
    When user inspects pending requests table
    Then table should have role "table" or use semantic table element
    And rows should have role "row"
    And column headers should have role "columnheader"
    And data cells should have role "cell" or appropriate semantic markup

  @accessibility @a11y @priority-high @aria @semantic-markup
  Scenario: ARIA labels provide descriptive context for action buttons
    Given user is on the pending requests page
    And browser developer tools are open
    When user inspects "Approve" button
    Then button should have aria-label "Approve schedule change request for John Doe, submitted on 01/15/2024"
    When user inspects "Reject" button
    Then button should have aria-label providing context beyond visible button text

  @accessibility @a11y @priority-high @aria @semantic-markup
  Scenario: Modal dialogs have proper ARIA attributes
    Given user is on the pending requests page
    And browser developer tools are open
    When user opens approval modal
    And user inspects modal element
    Then modal should have role "dialog"
    And modal should have aria-modal "true"
    And modal should have aria-labelledby pointing to modal heading
    And modal should have aria-describedby if description is present

  @accessibility @a11y @priority-high @aria @semantic-markup
  Scenario: Form fields have proper labels and ARIA attributes
    Given user is on the pending requests page
    And browser developer tools are open
    When user opens approval modal
    And user inspects comment text area
    Then text area should have associated label element or aria-label
    And text area should have aria-required "false" for optional field
    When user opens rejection modal
    And user inspects comment text area
    Then text area should have associated label element or aria-label
    And text area should have aria-required "true" for mandatory field

  @accessibility @a11y @priority-high @aria @live-regions
  Scenario: Success messages use ARIA live regions for announcements
    Given user is on the pending requests page
    And browser developer tools are open
    When user submits approval
    And user inspects success message container
    Then success message should have role "status" or role "alert"
    And success message should have aria-live "polite" or aria-live "assertive"
    And screen readers should announce message automatically

  @accessibility @a11y @priority-high @aria @semantic-markup
  Scenario: Status badges have ARIA labels providing full context
    Given user is on the pending requests page
    And browser developer tools are open
    When user inspects status badge for "Pending" request
    Then status indicator should have aria-label "Status: Pending"
    When user inspects status badge for "Approved" request
    Then status indicator should have aria-label "Status: Approved"
    When user inspects status badge for "Rejected" request
    Then status indicator should have aria-label "Status: Rejected"

  @accessibility @a11y @priority-high @aria @live-regions
  Scenario: Loading indicators have appropriate ARIA attributes
    Given user is on the pending requests page
    And browser developer tools are open
    When user submits approval
    And loading indicator is displayed
    And user inspects loading indicator
    Then loading indicator should have role "status"
    And loading indicator should have aria-live "polite"
    And loading indicator should have aria-label "Processing approval request"