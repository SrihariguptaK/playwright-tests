# Manual Test Cases

## Story: As Quote Manager, I want to open existing quotes for editing to update quote details accurately
**Story ID:** story-11

### Test Case: Validate successful loading and editing of existing quote
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User has valid Quote Manager credentials
- At least one existing quote is available in the system
- User has edit permissions for quotes
- System is accessible and operational
- Browser is supported and up to date

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the quoting system login page and enter valid Quote Manager credentials | User is successfully authenticated and redirected to the dashboard |
| 2 | Navigate to the quote search page from the dashboard menu | Quote search page is displayed with search fields and filters available |
| 3 | Enter a valid quote ID or customer name in the search field and click Search button | Search results are displayed showing matching quotes with relevant details |
| 4 | Select an existing quote from the search results by clicking on it | Quote details load into editable form within 2 seconds with all fields pre-populated with existing data |
| 5 | Verify all quote fields are displayed correctly including customer information, line items, pricing, and terms | All quote data is accurately displayed in editable form fields |
| 6 | Modify one or more quote fields with valid data (e.g., update pricing, change quantity, modify terms) | Modified fields accept the new values and display real-time validation feedback |
| 7 | Click the Submit or Save button to save the changes | System displays a change summary showing all modifications made to the quote |
| 8 | Review the change summary and confirm the changes | Changes are saved successfully, a new version is created with incremented version number, and a confirmation message is displayed |
| 9 | Verify the new version number is displayed on the quote | Quote shows updated version number and timestamp of the modification |

**Postconditions:**
- Quote is updated with new data
- New version of the quote is created in the database
- Original quote version is preserved
- User remains logged in
- Confirmation message is visible to the user

---

### Test Case: Verify validation prevents saving with missing mandatory fields
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in as Quote Manager with edit permissions
- An existing quote is available for editing
- User has navigated to the quote editing interface
- Quote form contains mandatory fields

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Search for and select an existing quote to open for editing | Quote details load successfully into the editable form with all fields populated |
| 2 | Verify the editable form is displayed with all quote fields accessible | Editable form is displayed with all fields including mandatory field indicators (e.g., asterisks or labels) |
| 3 | Identify a mandatory field (e.g., Customer Name, Quote Amount, or Expiration Date) and clear its content | Field content is cleared and field is now empty |
| 4 | Attempt to save the quote by clicking the Save or Submit button | Validation error message is displayed indicating the mandatory field is required, and save operation is prevented |
| 5 | Verify the error message clearly identifies which mandatory field is missing | Error message specifically names the missing mandatory field and provides guidance on how to correct it |
| 6 | Fill the mandatory field with valid data that meets all validation requirements | Field accepts the valid data and validation error message disappears or changes to success indicator |
| 7 | Click the Save or Submit button again to save the quote | Save operation succeeds, new version is created, and confirmation message is displayed |

**Postconditions:**
- Quote is saved with all mandatory fields populated
- New version of the quote exists in the system
- Validation rules are enforced
- User receives confirmation of successful save

---

### Test Case: Ensure unauthorized users cannot access quote editing
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User account exists without quote edit permissions
- User has valid login credentials for a non-Quote Manager role
- At least one quote exists in the system
- Role-based access control is configured and active
- Direct URL to quote editing interface is known

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the login page and enter credentials for a user without edit permissions (e.g., Viewer role) | User is successfully authenticated and logged into the system with limited permissions |
| 2 | Navigate to the quotes section or dashboard | User can view the quotes section but edit options are not visible or are disabled |
| 3 | Attempt to access the quote editing interface through the normal user interface | Access to quote editing interface is denied, edit buttons are disabled or not displayed |
| 4 | Copy or manually enter the direct URL to the quote editing interface (e.g., /quotes/edit/12345) in the browser address bar | System detects unauthorized access attempt |
| 5 | Press Enter to navigate to the direct URL | Access denied error page is displayed with message indicating insufficient permissions |
| 6 | Verify the error message provides appropriate feedback without exposing sensitive system information | Error message clearly states access is denied due to insufficient permissions without revealing system architecture details |
| 7 | Verify user is not able to view or modify any quote data through the denied interface | No quote data is displayed and no editing functionality is accessible |

**Postconditions:**
- Unauthorized user remains unable to edit quotes
- Security logs record the unauthorized access attempt
- User session remains active but with restricted permissions
- No quote data is modified or exposed

---

## Story: As Quote Manager, I want to receive notifications when a quote is successfully updated to confirm changes
**Story ID:** story-15

### Test Case: Validate success notification after quote update
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in as Quote Manager with edit permissions
- An existing quote is loaded in the editing interface
- User has made valid changes to the quote
- Notification component is functional
- Browser supports notification display

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Make valid edits to the quote fields (e.g., update pricing, modify terms, change quantities) | Modified fields display the updated values and pass real-time validation |
| 2 | Click the Save or Submit button to save the quote edits | System processes the changes and saves the updated quote to the database |
| 3 | Observe the screen immediately after the save operation completes | A clear success notification is displayed prominently on the screen within 1-2 seconds |
| 4 | Verify the notification contains a success indicator (e.g., green checkmark, success icon, or positive color scheme) | Notification displays visual success indicators that clearly communicate successful completion |
| 5 | Read the notification content to verify it includes a summary of the changes made | Notification displays a summary listing the specific fields that were modified (e.g., 'Quote updated successfully: Price changed from $1000 to $1200, Quantity changed from 5 to 10') |
| 6 | Verify that no sensitive information such as internal IDs, system paths, or confidential data is exposed in the notification | Notification contains only appropriate user-facing information without exposing sensitive system details |
| 7 | Locate and click the dismiss button (X icon, Close button, or similar) on the notification | Notification smoothly disappears from the screen without causing any errors or page refresh |
| 8 | Verify the page remains functional after dismissing the notification | Page continues to function normally, quote data remains displayed, and no JavaScript errors occur |

**Postconditions:**
- Quote is successfully saved with new version
- Notification has been displayed and dismissed
- User has confirmation of successful update
- Notification event is logged for audit purposes
- User interface remains in stable state

---

## Story: As Quote Manager, I want the system to prevent concurrent edits on the same quote to avoid conflicts
**Story ID:** story-17

### Test Case: Verify quote locking prevents concurrent edits
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Two users (User A and User B) are logged into the system with Quote Manager permissions
- A valid quote exists in the system and is available for editing
- Quote is currently unlocked and not being edited by any user
- Both users have network connectivity and active sessions
- Locking mechanism is enabled and functioning in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | User A navigates to the quote list and selects a specific quote to edit | Quote details page loads successfully for User A |
| 2 | User A clicks the 'Edit' button on the quote | Quote enters edit mode for User A, edit form is displayed with all quote fields editable, and system locks the quote record immediately (within 1 second) |
| 3 | Verify lock status in the system database or admin panel | Quote record shows as locked with User A as the lock owner and timestamp of lock acquisition |
| 4 | User B navigates to the same quote and attempts to click the 'Edit' button | System prevents User B from entering edit mode and displays a notification message indicating the quote is currently locked by User A with information about who is editing and when the lock was acquired |
| 5 | User B verifies the quote remains in read-only mode | All quote fields are displayed but not editable for User B, edit button is disabled or shows locked status |
| 6 | User A makes changes to the quote fields (e.g., updates pricing, terms, or line items) | Changes are reflected in the edit form for User A, no errors occur during editing |
| 7 | User A clicks the 'Save' button to save the changes | Changes are saved successfully, confirmation message is displayed, and lock is released automatically within 1 second |
| 8 | Verify lock status in the system after User A saves | Quote record shows as unlocked, no lock owner is assigned, lock release timestamp is recorded |
| 9 | User B refreshes the quote page or attempts to edit the quote again | User B can now successfully click the 'Edit' button and enter edit mode without any lock notification |
| 10 | User B enters edit mode and verifies the quote is locked for their session | Quote is locked for User B, edit form is displayed, and system shows User B as the current lock owner |

**Postconditions:**
- Quote is unlocked and available for editing by other users
- All changes made by User A are saved and persisted in the database
- User B has successfully acquired the lock and is in edit mode
- Lock history is recorded in the system audit logs
- No data conflicts or integrity issues exist

---

