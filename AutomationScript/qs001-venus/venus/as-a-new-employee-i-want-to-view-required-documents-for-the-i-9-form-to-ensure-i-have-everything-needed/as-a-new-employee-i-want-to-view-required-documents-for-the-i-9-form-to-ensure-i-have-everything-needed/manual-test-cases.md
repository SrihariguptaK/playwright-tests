# Manual Test Cases

## Story: As a new employee, I want to view required documents for the I-9 form to ensure I have everything needed.
**Story ID:** db-story-story-2

### Test Case: Verify required documents are listed clearly on the landing page
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User has access to the I-9 landing page URL
- User is authenticated as a new employee
- I-9 landing page is deployed and accessible
- Required documents list is populated in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the I-9 landing page | I-9 landing page loads successfully and displays the main content |
| 2 | Locate the 'Required Documents' section on the landing page | 'Required Documents' section is visible and clearly labeled on the page |
| 3 | Review the list of required documents displayed | A complete list of acceptable I-9 documents is displayed with clear formatting and organization |
| 4 | Verify that document names are clearly readable and properly formatted | All document names are displayed in readable font size, proper spacing, and logical grouping |
| 5 | Check if the documents are categorized (List A, List B, List C) | Documents are organized into appropriate categories with clear category headers |

**Postconditions:**
- User can identify all required documents for I-9 completion
- No errors or broken elements are present on the page

---

### Test Case: Verify each document link is functional and leads to the correct resource
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is on the I-9 landing page
- Required documents section is visible
- All document links are configured in the system
- Target document resources are available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Identify all clickable document links in the Required Documents section | All document links are visually identifiable (underlined, colored, or with icons) |
| 2 | Click on the first document link in the list | Link is clickable and initiates navigation or download action |
| 3 | Verify the document opens or downloads correctly | Correct document opens in a new tab/window or downloads to the device with proper filename |
| 4 | Return to the I-9 landing page and repeat steps 2-3 for each remaining document link | Each document link successfully opens or downloads the corresponding correct document |
| 5 | Verify that no broken links (404 errors) are present | All links resolve successfully without error messages |
| 6 | Check that external links open in new tabs/windows | External document links open in new browser tabs, preserving the original I-9 landing page |

**Postconditions:**
- All document links have been verified as functional
- User can successfully access all required document resources
- Original I-9 landing page remains accessible

---

### Test Case: Verify users can easily understand the categories of documents required
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is on the I-9 landing page
- User has no prior knowledge of I-9 document requirements
- Required Documents section is fully loaded
- Document categories are configured in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the Required Documents section on the I-9 landing page | Required Documents section is displayed with clear heading |
| 2 | Review the document category structure (List A, List B, List C) | Document categories are clearly labeled with distinct headings or visual separators |
| 3 | Read the explanation or description provided for each document category | Each category includes a clear explanation of what types of documents belong to that category and their purpose |
| 4 | Verify that List A explanation indicates documents that establish both identity and employment authorization | List A description clearly states these documents prove both identity and work authorization |
| 5 | Verify that List B explanation indicates documents that establish identity only | List B description clearly states these documents prove identity only |
| 6 | Verify that List C explanation indicates documents that establish employment authorization only | List C description clearly states these documents prove employment authorization only |
| 7 | Check for instructions on which combination of documents is acceptable | Clear instructions state that employees must provide either one List A document OR one List B document AND one List C document |
| 8 | Look for any visual aids (icons, colors, diagrams) that help distinguish categories | Visual elements are present and enhance understanding of document categories |

**Postconditions:**
- User understands the three document categories
- User knows which combination of documents they need to provide
- User can make informed decisions about which documents to prepare

---

### Test Case: Verify user can download necessary forms from the Required Documents section
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 6 mins

**Preconditions:**
- User is on the I-9 landing page
- Required Documents section is accessible
- Downloadable forms are available in the system
- User has appropriate browser permissions for downloads

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the Required Documents section | Required Documents section is displayed with all available forms |
| 2 | Identify forms that are available for download (e.g., I-9 form, instructions) | Downloadable forms are clearly marked with download icons or labels |
| 3 | Click on the download link for the I-9 form | Download initiates immediately or download dialog appears |
| 4 | Verify the downloaded file is saved to the default download location | File is successfully downloaded with correct filename (e.g., 'I-9_Form.pdf') |
| 5 | Open the downloaded form | Form opens correctly in appropriate application (PDF reader) and is readable and complete |
| 6 | Return to the page and download any additional available forms | All additional forms download successfully with correct filenames and content |

**Postconditions:**
- User has successfully downloaded all necessary forms
- Downloaded forms are accessible and usable
- User can proceed with form completion offline if needed

---

### Test Case: Verify Required Documents section is accessible from the I-9 landing page navigation
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 3 mins

**Preconditions:**
- User is on the I-9 landing page
- Page has fully loaded
- Required Documents section exists on the page

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Load the I-9 landing page | I-9 landing page displays with all sections visible |
| 2 | Locate the 'Required Documents' section link or button in the navigation or page content | 'Required Documents' link/button is clearly visible and labeled |
| 3 | Click on the 'Required Documents' section link | Page scrolls to or navigates to the Required Documents section smoothly |
| 4 | Verify the Required Documents section content is fully displayed | Complete list of required documents with categories and explanations is visible |

**Postconditions:**
- User is viewing the Required Documents section
- All document information is accessible

---

### Test Case: Verify document links remain functional after page refresh
- **ID:** tc-006
- **Type:** edge-case
- **Priority:** Medium
- **Estimated Time:** 5 mins

**Preconditions:**
- User is on the I-9 landing page
- Required Documents section is visible
- Browser supports page refresh functionality

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the Required Documents section | Required Documents section is displayed with all document links |
| 2 | Click on any document link to verify it works | Document link opens or downloads successfully |
| 3 | Refresh the browser page (F5 or refresh button) | Page reloads successfully and Required Documents section is still visible |
| 4 | Click on the same document link again | Document link still functions correctly and opens/downloads the document |
| 5 | Test multiple document links after refresh | All document links remain functional after page refresh |

**Postconditions:**
- All document links are functional after page refresh
- Page state is maintained correctly

---

### Test Case: Verify error handling when document link is broken or unavailable
- **ID:** tc-007
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is on the I-9 landing page
- Test environment allows simulation of broken links
- At least one document link is configured to be broken or unavailable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the Required Documents section | Required Documents section is displayed |
| 2 | Click on a broken or unavailable document link | System detects the broken link |
| 3 | Observe the error message or notification displayed | User-friendly error message is displayed indicating the document is temporarily unavailable |
| 4 | Verify that the error message provides alternative actions or contact information | Error message includes helpful information such as 'Please contact HR' or 'Try again later' |
| 5 | Verify that the page does not crash or become unresponsive | Page remains functional and other document links are still accessible |

**Postconditions:**
- User is informed of the issue
- User can continue accessing other documents
- Page remains stable

---

### Test Case: Verify Required Documents section displays correctly on mobile devices
- **ID:** tc-008
- **Type:** edge-case
- **Priority:** Medium
- **Estimated Time:** 8 mins

**Preconditions:**
- User has access to a mobile device or mobile emulator
- I-9 landing page is responsive
- User can access the I-9 landing page on mobile

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open the I-9 landing page on a mobile device (or use browser mobile emulation) | Page loads and adapts to mobile screen size |
| 2 | Scroll to the Required Documents section | Required Documents section is visible and properly formatted for mobile view |
| 3 | Verify that all document names are readable without horizontal scrolling | Text wraps appropriately and is fully readable on mobile screen |
| 4 | Verify that document categories are clearly separated and distinguishable | Category headers and document lists are properly formatted with adequate spacing |
| 5 | Tap on a document link | Link is easily tappable (adequate touch target size) and opens/downloads the document |
| 6 | Test multiple document links on mobile | All links are functional and accessible on mobile device |

**Postconditions:**
- Required Documents section is fully functional on mobile
- User experience is optimized for mobile viewing

---

### Test Case: Verify document list updates reflect the latest acceptable documents from HR
- **ID:** tc-009
- **Type:** edge-case
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- HR has provided an updated list of acceptable I-9 documents
- Updated document list has been loaded into the system
- User has access to the I-9 landing page
- Previous version of document list is known for comparison

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Obtain the latest list of acceptable I-9 documents from HR | Current official list of acceptable documents is available for reference |
| 2 | Navigate to the Required Documents section on the I-9 landing page | Required Documents section is displayed |
| 3 | Compare each document listed on the page with the official HR list | All documents on the page match the official HR list exactly |
| 4 | Verify that no outdated or deprecated documents are listed | Only current, acceptable documents are displayed |
| 5 | Check that any newly added acceptable documents are included | All new documents from the updated HR list are present on the page |
| 6 | Verify document descriptions match current HR guidelines | All document descriptions and category assignments are accurate and current |

**Postconditions:**
- Document list is current and compliant with HR requirements
- No outdated information is displayed to users

---

### Test Case: Verify accessibility of Required Documents section for users with disabilities
- **ID:** tc-010
- **Type:** edge-case
- **Priority:** Medium
- **Estimated Time:** 15 mins

**Preconditions:**
- User has access to screen reader software or accessibility testing tools
- I-9 landing page is loaded
- Accessibility standards (WCAG 2.1) are defined as requirements

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Enable screen reader software (e.g., JAWS, NVDA) | Screen reader is active and functioning |
| 2 | Navigate to the I-9 landing page using keyboard only (Tab key) | Page is navigable using keyboard without requiring mouse |
| 3 | Tab to the Required Documents section | Screen reader announces the Required Documents section heading clearly |
| 4 | Navigate through the document list using keyboard | Each document link is reachable via Tab key and screen reader announces link text |
| 5 | Verify that document categories are announced by screen reader | Screen reader clearly announces category headings (List A, List B, List C) |
| 6 | Press Enter on a document link using keyboard | Document opens or downloads successfully using keyboard interaction only |
| 7 | Check color contrast of text and links using accessibility tools | All text meets WCAG 2.1 AA contrast ratio requirements (4.5:1 for normal text) |
| 8 | Verify that all images or icons have appropriate alt text | Screen reader announces meaningful alt text for all visual elements |

**Postconditions:**
- Required Documents section is fully accessible to users with disabilities
- Section meets WCAG 2.1 accessibility standards

---

