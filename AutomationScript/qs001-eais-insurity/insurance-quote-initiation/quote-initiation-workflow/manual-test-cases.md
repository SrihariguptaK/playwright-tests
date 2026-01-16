# Manual Test Cases

## Story: As Insurance Agent, I want to view confirmation of quote initiation to achieve assurance of successful quote creation
**Story ID:** story-8

### Test Case: Validate display of quote initiation confirmation
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as an Insurance Agent
- Quote initiation form is accessible and functional
- All mandatory fields for quote submission are available
- System is connected to quote processing backend
- Printer or save functionality is available in browser

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the quote initiation form | Quote initiation form is displayed with all required fields |
| 2 | Fill in all mandatory applicant information fields (name, contact details, address) | All applicant fields are populated with valid data |
| 3 | Fill in all mandatory risk data fields (coverage type, coverage amount, risk details) | All risk data fields are populated with valid data |
| 4 | Click the Submit button to submit the completed quote | Confirmation screen is displayed within 2 seconds showing successful quote initiation |
| 5 | Verify that a unique quote ID is displayed on the confirmation screen | A unique alphanumeric quote ID is clearly visible on the confirmation screen |
| 6 | Verify that the confirmation screen shows a summary of submitted applicant data | Applicant name, contact details, and address match the data submitted in the form |
| 7 | Verify that the confirmation screen shows a summary of submitted risk data | Coverage type, coverage amount, and risk details match the data submitted in the form |
| 8 | Locate and click the Print option on the confirmation screen | Print dialog opens with confirmation details formatted correctly for printing |
| 9 | Complete the print action or cancel the print dialog | Confirmation details are printed successfully or print dialog is closed without errors |
| 10 | Locate and click the Save option on the confirmation screen | Save dialog opens allowing user to save confirmation details as a file (PDF or other format) |
| 11 | Save the confirmation details to a local directory | Confirmation details are saved successfully and file can be opened to verify content |

**Postconditions:**
- Quote is successfully created in the system with unique quote ID
- Confirmation screen remains accessible for review
- Confirmation details are available in printed or saved format
- Agent can proceed to next workflow steps
- Quote data is stored in the database

---

### Test Case: Ensure confirmation is only visible to submitting user
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Two different user accounts exist: User A and User B
- Both users have Insurance Agent role and valid credentials
- User A is logged into the system
- Quote initiation form is accessible
- System enforces user-level security for quote confirmations

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in to the system as User A | User A is successfully authenticated and logged into the system |
| 2 | Navigate to the quote initiation form as User A | Quote initiation form is displayed for User A |
| 3 | Fill in all mandatory fields with valid applicant and risk data as User A | All required fields are populated with valid data |
| 4 | Submit the completed quote as User A | Confirmation screen is displayed to User A with unique quote ID and data summary |
| 5 | Note the unique quote ID and confirmation URL displayed to User A | Quote ID and URL are recorded for later verification |
| 6 | Verify that User A can view all confirmation details including quote ID and submitted data summary | User A has full access to view the confirmation screen with all details |
| 7 | Log out User A from the system | User A is successfully logged out and session is terminated |
| 8 | Log in to the system as User B using different credentials | User B is successfully authenticated and logged into the system |
| 9 | Attempt to access User A's confirmation screen by navigating to the confirmation URL or quote ID | Access is denied with appropriate error message (e.g., 'Unauthorized access' or 'Confirmation not found') |
| 10 | Verify that User B cannot view any details of User A's quote confirmation | No quote ID, applicant data, or risk data from User A's submission is visible to User B |
| 11 | Verify that the system does not display sensitive information in the access denial message | Error message is generic and does not reveal quote details or User A's information |

**Postconditions:**
- User A's quote confirmation remains secure and accessible only to User A
- User B is unable to access User A's confirmation details
- System security logs record the unauthorized access attempt
- No data breach or information leakage occurs
- Both user sessions are properly managed

---

## Story: As Insurance Agent, I want to receive error messages during quote initiation to achieve clarity on issues preventing submission
**Story ID:** story-9

### Test Case: Validate display of specific error messages on invalid submission
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- User is logged in as an Insurance Agent
- Quote initiation form is accessible and functional
- Form validation rules are configured and active
- Mandatory fields include: applicant name, contact number, email, address, coverage type, coverage amount
- System validation engine is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the quote initiation form | Quote initiation form is displayed with all fields visible |
| 2 | Leave the applicant name field empty | Applicant name field remains blank |
| 3 | Leave the contact number field empty | Contact number field remains blank |
| 4 | Leave the email field empty | Email field remains blank |
| 5 | Leave the coverage type field unselected | Coverage type field has no selection |
| 6 | Click the Submit button with multiple mandatory fields empty | Form submission is prevented and error messages are displayed within 1 second |
| 7 | Verify that a specific error message is displayed for the missing applicant name field | Error message reads 'Applicant name is required' or similar specific message near the name field |
| 8 | Verify that a specific error message is displayed for the missing contact number field | Error message reads 'Contact number is required' or similar specific message near the contact field |
| 9 | Verify that a specific error message is displayed for the missing email field | Error message reads 'Email address is required' or similar specific message near the email field |
| 10 | Verify that a specific error message is displayed for the missing coverage type field | Error message reads 'Coverage type must be selected' or similar specific message near the coverage type field |
| 11 | Verify that all fields with errors are visually highlighted or distinguished | Fields with missing data are highlighted with red border, background color, or icon indicating error state |
| 12 | Verify that error messages provide guidance on how to correct each error | Each error message includes actionable guidance (e.g., 'Please enter applicant full name', 'Please provide valid email format') |
| 13 | Fill in the applicant name field with valid data | Applicant name field is populated and error highlighting is removed from this field |
| 14 | Fill in the contact number field with valid data | Contact number field is populated and error highlighting is removed from this field |
| 15 | Fill in the email field with valid data | Email field is populated and error highlighting is removed from this field |
| 16 | Select a valid coverage type from the dropdown | Coverage type is selected and error highlighting is removed from this field |
| 17 | Fill in all remaining mandatory fields with valid data | All mandatory fields are populated with valid data and no error indicators remain |
| 18 | Click the Submit button to resubmit the corrected quote | Form submission succeeds without errors and confirmation screen is displayed with quote ID |

**Postconditions:**
- All validation errors are resolved
- Quote is successfully submitted and created in the system
- No error messages are displayed on confirmation screen
- User receives confirmation with unique quote ID
- Form data is saved to database

---

### Test Case: Ensure error messages do not expose sensitive data
- **ID:** tc-004
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in as an Insurance Agent
- Quote initiation form is accessible
- Form contains fields that may contain sensitive data (SSN, credit card, bank account, medical information)
- Validation rules are configured to detect invalid data formats
- System security policies prohibit exposure of sensitive data in error messages

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the quote initiation form | Quote initiation form is displayed with all fields |
| 2 | Enter an invalid format for a sensitive field (e.g., invalid SSN format like '123-45-678X') | Invalid SSN data is entered in the field |
| 3 | Enter invalid data in other fields that may contain sensitive information (e.g., invalid credit score, invalid medical condition code) | Invalid data is entered in multiple sensitive fields |
| 4 | Click the Submit button to trigger validation | Form validation is triggered and errors are detected |
| 5 | Review all error messages displayed on the screen | Error messages are displayed for fields with invalid data |
| 6 | Verify that error messages do not display the actual invalid SSN value entered | Error message reads 'Invalid SSN format' or 'Please enter valid SSN' without showing '123-45-678X' |
| 7 | Verify that error messages do not display any partial sensitive data (e.g., last 4 digits, masked values) | No portion of the sensitive data is visible in error messages |
| 8 | Verify that error messages do not expose internal system information (database fields, table names, validation logic) | Error messages contain only user-friendly text without technical or system details |
| 9 | Verify that error messages do not reveal information about other users or quotes | Error messages are specific to current submission only and contain no references to other data |
| 10 | Check browser console and network logs for any sensitive data exposure | No sensitive data is logged in browser console or visible in network response payloads |
| 11 | Verify that all error messages provide generic but helpful guidance without exposing confidential information | Error messages are actionable (e.g., 'Please enter valid format') but do not contain sensitive or confidential details |

**Postconditions:**
- No sensitive data is exposed in error messages
- User receives clear guidance to correct errors without security risk
- System maintains security compliance standards
- Error handling does not create data breach vulnerability
- Form remains in editable state for corrections

---

## Story: As Insurance Agent, I want to navigate through the quote initiation process efficiently to achieve a streamlined user experience
**Story ID:** story-10

### Test Case: Validate step-by-step navigation with progress indicators
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as an Insurance Agent with valid credentials
- User has permissions to create quotes
- Quote initiation system is accessible and operational
- Browser is supported (Chrome, Firefox, Safari, Edge - latest versions)
- Network connection is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the quote initiation page and click 'Start New Quote' button | Quote initiation process begins and displays the first step (Applicant Data). Navigation controls (Next, Previous, Save) are visible at the bottom. Progress indicator shows Step 1 of 4 with visual representation (e.g., progress bar or step numbers). Current step is highlighted. |
| 2 | Enter valid applicant data in all required fields (Name, Contact Information, Address) | All fields accept input correctly. Required field indicators are displayed. No validation errors appear for valid data. |
| 3 | Click 'Next' button to proceed to the next step | System navigates to Step 2 (Risk Data). Progress indicator updates to show Step 2 of 4. Previous step is marked as completed. Entered applicant data is saved automatically. Navigation transition completes in under 1 second. |
| 4 | Enter valid risk data in all required fields (Property Type, Coverage Amount, Risk Assessment) | All risk data fields accept input correctly. Field validations work as expected. No errors are displayed for valid entries. |
| 5 | Click 'Previous' button to return to the Applicant Data step | System navigates back to Step 1 (Applicant Data). Progress indicator updates to show Step 1 of 4. All previously entered applicant data is retained and displayed correctly. No data loss occurs. |
| 6 | Click 'Next' button to return to Risk Data step | System navigates to Step 2 (Risk Data). Previously entered risk data is retained and displayed correctly. Progress indicator shows Step 2 of 4. |
| 7 | Click 'Next' button to proceed to Step 3 | System navigates to Step 3 (Additional Information/Coverage Details). Progress indicator updates to Step 3 of 4. All previous data is saved. Navigation controls remain visible and functional. |
| 8 | Complete Step 3 fields and click 'Next' to proceed to the Review step | System navigates to Step 4 (Review and Submit). Progress indicator shows Step 4 of 4. All entered data from previous steps is displayed in a summary format for review. |
| 9 | Review all entered information and click 'Submit Quote' button | Quote is submitted successfully. Confirmation message is displayed with quote reference number. Progress indicator shows completion (100%). User is redirected to quote confirmation page or dashboard. |

**Postconditions:**
- Quote is saved in the system with status 'Submitted'
- Quote reference number is generated and stored
- All entered data is persisted in the database
- User can access the submitted quote from their dashboard
- Navigation progress is reset for next quote initiation
- System logs the successful quote submission with timestamp

---

### Test Case: Ensure navigation is responsive and accessible
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 25 mins

**Preconditions:**
- User is logged in as an Insurance Agent with valid credentials
- Quote initiation system is accessible
- Multiple test devices/browsers are available (Desktop, Tablet, Mobile)
- Screen reader software is installed and configured (JAWS, NVDA, or VoiceOver)
- Accessibility testing tools are available
- Different screen resolutions are configured for testing (1920x1080, 1366x768, 768x1024, 375x667)

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Access quote initiation page on a desktop browser with 1920x1080 resolution | Page loads correctly. Navigation controls are fully visible and properly aligned. Progress indicators are clearly displayed. All buttons and form fields are appropriately sized and spaced. No horizontal scrolling is required. |
| 2 | Resize browser window to 1366x768 resolution | Page layout adjusts responsively. Navigation controls remain visible and functional. Progress indicators adapt to smaller screen size. All interactive elements remain accessible and clickable. Content is readable without zooming. |
| 3 | Access quote initiation page on a tablet device (iPad or similar) in portrait orientation (768x1024) | Page renders correctly for tablet screen size. Navigation controls are touch-friendly with adequate tap targets (minimum 44x44 pixels). Progress indicators are visible and clear. Form fields are appropriately sized for touch input. Virtual keyboard does not obscure important content. |
| 4 | Rotate tablet to landscape orientation and verify navigation | Page layout adjusts to landscape orientation. Navigation controls remain accessible. Progress indicators are still visible. No content is cut off or hidden. All functionality remains intact. |
| 5 | Access quote initiation page on a mobile device (iPhone or Android) with 375x667 resolution | Page is fully responsive on mobile screen. Navigation controls are stacked or collapsed appropriately. Progress indicators are visible (may be simplified for mobile). All buttons are touch-friendly. Content is readable without horizontal scrolling. Mobile-optimized layout is applied. |
| 6 | Navigate through all steps using only keyboard (Tab, Shift+Tab, Enter, Space keys) | All interactive elements can be accessed via keyboard. Tab order is logical and follows visual flow. Focus indicators are clearly visible on all focusable elements. 'Next' and 'Previous' buttons can be activated with Enter or Space. No keyboard traps exist. Skip navigation links are available. |
| 7 | Enable screen reader (JAWS, NVDA, or VoiceOver) and navigate through the quote initiation process | Screen reader announces page title and main heading. Progress indicators are announced with current step and total steps. Form labels are properly associated and announced. Navigation buttons have descriptive labels announced. Error messages and validation feedback are announced. ARIA landmarks and roles are properly implemented. All content is accessible in logical reading order. |
| 8 | Use screen reader to navigate backward and forward through steps | Screen reader announces step changes. Progress updates are communicated. Data retention is confirmed through screen reader feedback. Navigation state changes are announced appropriately. |
| 9 | Test color contrast and visual accessibility using accessibility tools (WAVE, axe DevTools) | Color contrast ratios meet WCAG 2.1 AA standards (minimum 4.5:1 for normal text). Progress indicators are distinguishable without relying solely on color. Navigation controls have sufficient contrast. No accessibility violations are reported for navigation components. |
| 10 | Verify navigation performance across all tested devices | Navigation transitions complete in under 1 second on all devices. No lag or delay in button responses. Progress indicator updates are smooth. Page rendering is optimized for each device type. |

**Postconditions:**
- Navigation is confirmed functional across all tested devices and screen sizes
- Accessibility compliance is verified for WCAG 2.1 AA standards
- Keyboard navigation is fully operational
- Screen reader compatibility is confirmed
- Performance benchmarks are met across all platforms
- Test results are documented for compliance records

---

