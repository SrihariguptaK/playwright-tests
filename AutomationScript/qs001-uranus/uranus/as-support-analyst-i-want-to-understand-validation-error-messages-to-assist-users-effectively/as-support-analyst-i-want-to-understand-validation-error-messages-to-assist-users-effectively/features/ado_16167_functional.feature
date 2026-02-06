Feature: Support Analyst Validation Error Documentation Access
  As a Support Analyst
  I want to access and utilize validation error documentation
  So that I can assist users effectively and reduce resolution time

  Background:
    Given support analyst is logged into the support knowledge base system
    And validation error documentation has been published in the knowledge base

  @functional @regression @priority-high @smoke
  Scenario: Access validation error documentation from knowledge base
    Given support analyst has "Read" permissions for documentation section
    And browser is "Chrome" version "90" or higher
    When support analyst navigates to the knowledge base homepage
    Then knowledge base homepage should load successfully
    And search bar should be visible
    And navigation menu should be visible
    When support analyst clicks "Documentation" menu item in left navigation panel
    Then "Documentation" section should expand
    And subcategory "Validation Errors" should be visible
    When support analyst clicks "Validation Errors" subcategory link
    Then validation error documentation page should load
    And list of common validation errors should be displayed
    And section "Common Validation Errors" should be visible
    And section "Causes" should be visible
    And section "Troubleshooting Steps" should be visible
    When support analyst clicks on validation error entry "Invalid Email Format Error"
    Then detailed explanation should expand
    And error code should be displayed
    And error description should be displayed
    And common causes should be displayed
    And step-by-step resolution instructions should be displayed

  @functional @regression @priority-high @smoke
  Scenario: Search for specific validation error by error code
    Given validation error documentation contains at least 10 documented error codes
    And search functionality is enabled and indexed
    And support analyst has received user query with error code "VAL-ERR-1001"
    When support analyst clicks on search bar at top of interface
    Then search bar should become active
    And placeholder text "Search documentation..." should be displayed
    When support analyst enters "VAL-ERR-1001" in search bar
    Then auto-suggest dropdown should appear
    And matching result "VAL-ERR-1001: Invalid Date Format" should be displayed
    When support analyst presses Enter key
    Then search results page should display
    And "VAL-ERR-1001" should be top result
    And error code should be highlighted
    When support analyst clicks on search result "VAL-ERR-1001: Invalid Date Format"
    Then detailed error documentation page should open
    And error description should be displayed
    And 3 common causes should be listed
    And 5 troubleshooting steps should be displayed
    And screenshots should be visible
    When support analyst scrolls down to "Resolution Steps" section
    Then step-by-step resolution instructions should be displayed
    And numbered steps should be visible
    And expected format examples should be displayed
    And links to related documentation should be visible

  @functional @regression @priority-high
  Scenario: Guide user through resolution steps using troubleshooting guide
    Given support analyst has accessed validation error documentation for "VAL-ERR-2005: Required Field Missing"
    And support analyst is on active support call with user
    And documentation includes step-by-step troubleshooting guide with screenshots
    And support ticket system is open in separate browser tab
    When support analyst reads "Error Description" section for "VAL-ERR-2005"
    Then error description "This error occurs when a mandatory field is left empty during form submission. Common fields include Email, Username, and Password." should be displayed
    When support analyst reviews "Common Causes" section
    Then 3 causes should be listed
    And cause "User skipped required field" should be displayed
    And cause "Field validation not triggered" should be displayed
    And cause "Browser autofill failed to populate field" should be displayed
    When support analyst follows "Troubleshooting Steps" section
    And support analyst instructs user to check step "Verify all fields marked with red asterisk (*) are filled"
    Then clear instruction with screenshot should be provided
    And required field indicators should be shown
    When support analyst guides user through step "Clear browser cache and refresh the form page"
    Then browser-specific cache clearing instructions should be displayed
    And instructions for "Chrome" should be visible
    And instructions for "Firefox" should be visible
    And instructions for "Safari" should be visible
    When support analyst follows step "Try submitting form in incognito/private browsing mode"
    Then incognito mode instructions should be displayed
    And keyboard shortcuts for different browsers should be shown
    When support analyst documents resolution using "Resolution Template"
    Then template text "Issue resolved by [action taken]. Error VAL-ERR-2005 cleared after [specific step]." should be provided
    And support analyst can copy template text

  @functional @regression @priority-medium @mobile
  Scenario: Access validation error documentation on mobile device during field support
    Given support analyst is logged into knowledge base mobile app
    And mobile device has active internet connection
    And validation error documentation is mobile-responsive
    And support analyst has "Mobile Access" permission enabled
    When support analyst opens knowledge base mobile app
    And support analyst taps on menu icon in top-left corner
    Then navigation menu should slide out from left
    And menu option "Documentation" should be visible
    And menu option "Search" should be visible
    And menu option "Recent" should be visible
    And menu option "Favorites" should be visible
    When support analyst taps on "Documentation" menu item
    Then documentation categories list should appear
    And "Validation Errors" category should be visible
    When support analyst taps on "Validation Errors" category
    Then list of validation errors should load in mobile-optimized view
    And error codes should be displayed
    And brief descriptions should be visible
    When support analyst taps on "VAL-ERR-3010: Invalid Phone Number Format" entry
    Then full error documentation should open
    And collapsible section "Description" should be visible
    And collapsible section "Causes" should be visible
    And collapsible section "Resolution Steps" should be visible
    And content should be formatted for mobile screen
    When support analyst taps on "Resolution Steps" section
    Then section should expand
    And 4 numbered steps should be displayed
    And mobile-friendly formatting should be applied
    And text size should be readable
    And images should support tap-to-zoom

  @functional @regression @priority-medium @analytics
  Scenario: Track documentation usage metrics and support efficiency improvements
    Given support team lead is logged in with "Manager" role
    And support team lead has analytics access permissions
    And validation error documentation has been live for at least 30 days
    And support ticket system is integrated with knowledge base
    And at least 50 validation error tickets have been resolved
    When support team lead navigates to "Analytics Dashboard" from main menu
    Then analytics dashboard should load
    And metric "Documentation Views" should be displayed
    And metric "Average Resolution Time" should be displayed
    And metric "First-Contact Resolution Rate" should be displayed
    When support team lead clicks on "Validation Error Documentation" filter
    Then dashboard should update with validation error specific metrics
    And total views "250" should be displayed
    And unique users "45" should be displayed
    And search queries "180" should be displayed
    When support team lead reviews "Average Resolution Time" chart
    Then chart should display comparison of 30 days before and after documentation launch
    And 20 percent reduction should be shown
    And previous average "25" minutes should be displayed
    And current average "20" minutes should be displayed
    When support team lead clicks on "First-Contact Resolution Rate" metric tile
    Then detailed breakdown should be displayed
    And improvement from "65" percent to "78" percent should be shown
    When support team lead scrolls to "Most Accessed Documentation" section
    Then top 5 validation errors should be listed with view counts
    And "VAL-ERR-1001" with "45" views should be displayed
    And "VAL-ERR-2005" with "38" views should be displayed
    And "VAL-ERR-3010" with "32" views should be displayed
    When support team lead clicks "Export Report" button
    Then PDF report should download
    And report should contain all metrics
    And report should contain charts
    And report should contain success indicators