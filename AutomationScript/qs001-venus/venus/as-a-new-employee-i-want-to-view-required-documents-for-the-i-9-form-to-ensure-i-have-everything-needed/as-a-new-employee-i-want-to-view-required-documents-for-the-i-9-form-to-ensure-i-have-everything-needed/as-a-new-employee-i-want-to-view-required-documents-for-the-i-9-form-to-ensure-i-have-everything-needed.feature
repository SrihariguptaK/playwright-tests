Feature: As a new employee, I want to view required documents for the I-9 form to ensure I have everything needed.

  Background:
    Given the application is accessible
    And the user is on the appropriate page

  # Functional Test Scenarios
  Scenario: Verify required documents are listed clearly on the landing page
    Given User has access to the I-9 landing page URL
    Given User is authenticated as a new employee
    Given I-9 landing page is deployed and accessible
    Given Required documents list is populated in the system
    When Navigate to the I-9 landing page
    Then I-9 landing page loads successfully and displays the main content
    And Locate the 'Required Documents' section on the landing page
    Then 'Required Documents' section is visible and clearly labeled on the page
    And Review the list of required documents displayed
    Then A complete list of acceptable I-9 documents is displayed with clear formatting and organization
    And Verify that document names are clearly readable and properly formatted
    Then All document names are displayed in readable font size, proper spacing, and logical grouping
    And Check if the documents are categorized (List A, List B, List C)
    Then Documents are organized into appropriate categories with clear category headers

  Scenario: Verify each document link is functional and leads to the correct resource
    Given User is on the I-9 landing page
    Given Required documents section is visible
    Given All document links are configured in the system
    Given Target document resources are available
    When Identify all clickable document links in the Required Documents section
    Then All document links are visually identifiable (underlined, colored, or with icons)
    And Click on the first document link in the list
    Then Link is clickable and initiates navigation or download action
    And Verify the document opens or downloads correctly
    Then Correct document opens in a new tab/window or downloads to the device with proper filename
    And Return to the I-9 landing page and repeat steps 2-3 for each remaining document link
    Then Each document link successfully opens or downloads the corresponding correct document
    And Verify that no broken links (404 errors) are present
    Then All links resolve successfully without error messages
    And Check that external links open in new tabs/windows
    Then External document links open in new browser tabs, preserving the original I-9 landing page

  Scenario: Verify users can easily understand the categories of documents required
    Given User is on the I-9 landing page
    Given User has no prior knowledge of I-9 document requirements
    Given Required Documents section is fully loaded
    Given Document categories are configured in the system
    When Navigate to the Required Documents section on the I-9 landing page
    Then Required Documents section is displayed with clear heading
    And Review the document category structure (List A, List B, List C)
    Then Document categories are clearly labeled with distinct headings or visual separators
    And Read the explanation or description provided for each document category
    Then Each category includes a clear explanation of what types of documents belong to that category and their purpose
    And Verify that List A explanation indicates documents that establish both identity and employment authorization
    Then List A description clearly states these documents prove both identity and work authorization
    And Verify that List B explanation indicates documents that establish identity only
    Then List B description clearly states these documents prove identity only
    And Verify that List C explanation indicates documents that establish employment authorization only
    Then List C description clearly states these documents prove employment authorization only
    And Check for instructions on which combination of documents is acceptable
    Then Clear instructions state that employees must provide either one List A document OR one List B document AND one List C document
    And Look for any visual aids (icons, colors, diagrams) that help distinguish categories
    Then Visual elements are present and enhance understanding of document categories

  Scenario: Verify user can download necessary forms from the Required Documents section
    Given User is on the I-9 landing page
    Given Required Documents section is accessible
    Given Downloadable forms are available in the system
    Given User has appropriate browser permissions for downloads
    When Navigate to the Required Documents section
    Then Required Documents section is displayed with all available forms
    And Identify forms that are available for download (e.g., I-9 form, instructions)
    Then Downloadable forms are clearly marked with download icons or labels
    And Click on the download link for the I-9 form
    Then Download initiates immediately or download dialog appears
    And Verify the downloaded file is saved to the default download location
    Then File is successfully downloaded with correct filename (e.g., 'I-9_Form.pdf')
    And Open the downloaded form
    Then Form opens correctly in appropriate application (PDF reader) and is readable and complete
    And Return to the page and download any additional available forms
    Then All additional forms download successfully with correct filenames and content

  Scenario: Verify Required Documents section is accessible from the I-9 landing page navigation
    Given User is on the I-9 landing page
    Given Page has fully loaded
    Given Required Documents section exists on the page
    When Load the I-9 landing page
    Then I-9 landing page displays with all sections visible
    And Locate the 'Required Documents' section link or button in the navigation or page content
    Then 'Required Documents' link/button is clearly visible and labeled
    And Click on the 'Required Documents' section link
    Then Page scrolls to or navigates to the Required Documents section smoothly
    And Verify the Required Documents section content is fully displayed
    Then Complete list of required documents with categories and explanations is visible

  # Negative Test Scenarios
  Scenario: Verify error handling when document link is broken or unavailable
    Given User is on the I-9 landing page
    Given Test environment allows simulation of broken links
    Given At least one document link is configured to be broken or unavailable
    When Navigate to the Required Documents section
    Then Required Documents section is displayed
    And Click on a broken or unavailable document link
    Then System detects the broken link
    And Observe the error message or notification displayed
    Then User-friendly error message is displayed indicating the document is temporarily unavailable
    And Verify that the error message provides alternative actions or contact information
    Then Error message includes helpful information such as 'Please contact HR' or 'Try again later'
    And Verify that the page does not crash or become unresponsive
    Then Page remains functional and other document links are still accessible

  # Edge Case Test Scenarios
  Scenario: Verify document links remain functional after page refresh
    Given User is on the I-9 landing page
    Given Required Documents section is visible
    Given Browser supports page refresh functionality
    When Navigate to the Required Documents section
    Then Required Documents section is displayed with all document links
    And Click on any document link to verify it works
    Then Document link opens or downloads successfully
    And Refresh the browser page (F5 or refresh button)
    Then Page reloads successfully and Required Documents section is still visible
    And Click on the same document link again
    Then Document link still functions correctly and opens/downloads the document
    And Test multiple document links after refresh
    Then All document links remain functional after page refresh

  Scenario: Verify Required Documents section displays correctly on mobile devices
    Given User has access to a mobile device or mobile emulator
    Given I-9 landing page is responsive
    Given User can access the I-9 landing page on mobile
    When Open the I-9 landing page on a mobile device (or use browser mobile emulation)
    Then Page loads and adapts to mobile screen size
    And Scroll to the Required Documents section
    Then Required Documents section is visible and properly formatted for mobile view
    And Verify that all document names are readable without horizontal scrolling
    Then Text wraps appropriately and is fully readable on mobile screen
    And Verify that document categories are clearly separated and distinguishable
    Then Category headers and document lists are properly formatted with adequate spacing
    And Tap on a document link
    Then Link is easily tappable (adequate touch target size) and opens/downloads the document
    And Test multiple document links on mobile
    Then All links are functional and accessible on mobile device

  Scenario: Verify document list updates reflect the latest acceptable documents from HR
    Given HR has provided an updated list of acceptable I-9 documents
    Given Updated document list has been loaded into the system
    Given User has access to the I-9 landing page
    Given Previous version of document list is known for comparison
    When Obtain the latest list of acceptable I-9 documents from HR
    Then Current official list of acceptable documents is available for reference
    And Navigate to the Required Documents section on the I-9 landing page
    Then Required Documents section is displayed
    And Compare each document listed on the page with the official HR list
    Then All documents on the page match the official HR list exactly
    And Verify that no outdated or deprecated documents are listed
    Then Only current, acceptable documents are displayed
    And Check that any newly added acceptable documents are included
    Then All new documents from the updated HR list are present on the page
    And Verify document descriptions match current HR guidelines
    Then All document descriptions and category assignments are accurate and current

  Scenario: Verify accessibility of Required Documents section for users with disabilities
    Given User has access to screen reader software or accessibility testing tools
    Given I-9 landing page is loaded
    Given Accessibility standards (WCAG 2.1) are defined as requirements
    When Enable screen reader software (e.g., JAWS, NVDA)
    Then Screen reader is active and functioning
    And Navigate to the I-9 landing page using keyboard only (Tab key)
    Then Page is navigable using keyboard without requiring mouse
    And Tab to the Required Documents section
    Then Screen reader announces the Required Documents section heading clearly
    And Navigate through the document list using keyboard
    Then Each document link is reachable via Tab key and screen reader announces link text
    And Verify that document categories are announced by screen reader
    Then Screen reader clearly announces category headings (List A, List B, List C)
    And Press Enter on a document link using keyboard
    Then Document opens or downloads successfully using keyboard interaction only
    And Check color contrast of text and links using accessibility tools
    Then All text meets WCAG 2.1 AA contrast ratio requirements (4.5:1 for normal text)
    And Verify that all images or icons have appropriate alt text
    Then Screen reader announces meaningful alt text for all visual elements

  # Accessibility Test Scenarios
  Scenario: Keyboard Navigation
    When the user navigates using keyboard only
    Then all interactive elements should be accessible via keyboard
    And focus indicators should be clearly visible

  Scenario: Screen Reader Compatibility
    When the user accesses the page with a screen reader
    Then all content should be properly announced
    And ARIA labels should be present for all interactive elements

  Scenario: Color Contrast
    Then all text should meet WCAG AA color contrast standards
    And important information should not rely solely on color

