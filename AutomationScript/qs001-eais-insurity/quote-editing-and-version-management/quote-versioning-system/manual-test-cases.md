# Manual Test Cases

## Story: As Quote Manager, I want the system to automatically create a new version when I edit a quote to maintain version history
**Story ID:** story-12

### Test Case: Verify new version creation on quote edit
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as Quote Manager with edit permissions
- At least one existing quote is available in the system
- Quote versions table is accessible and functioning
- API endpoint PUT /api/quotes/{id} is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the quotes list and select an existing quote to edit | Quote details page opens with editable fields displayed |
| 2 | Modify one or more fields in the quote (e.g., price, description, terms) | Modified fields show updated values in the form |
| 3 | Click the 'Save' or 'Submit' button to save the changes | System processes the edit request and displays a success confirmation message indicating version creation |
| 4 | Verify that a new version record is created with an incremented version number | New version record exists with version number incremented by 1 from the previous version (e.g., v1 to v2) |
| 5 | Navigate to the version history section or execute GET /api/quotes/{id}/versions to retrieve version history for the quote | All versions including the newly created one are listed with correct version numbers, timestamps, and user information |
| 6 | Select a previous version record from the version history | Previous version details are displayed in read-only mode |
| 7 | Attempt to edit any field in the previous version record | Editing is prevented, fields are disabled or locked, and system displays message indicating version is read-only |

**Postconditions:**
- New version record is stored in the quote versions table
- Previous version remains intact and read-only
- Version history shows complete audit trail
- Current quote displays the latest edited values

---

### Test Case: Ensure version creation latency is within SLA
- **ID:** tc-002
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as Quote Manager with edit permissions
- At least one existing quote is available in the system
- Performance monitoring tools or timer are available to measure latency
- API endpoint PUT /api/quotes/{id} is operational
- System is under normal load conditions

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to an existing quote and open it for editing | Quote details page opens with editable fields |
| 2 | Make a modification to one or more fields in the quote | Fields are updated with new values |
| 3 | Start a timer and click 'Save' or 'Submit' to submit the quote edit | System begins processing the edit request |
| 4 | Monitor the time taken from submission until the system confirms version creation completion | Version creation completes and confirmation message is displayed within 1 second of submission |
| 5 | Verify that the new version record is successfully created in the database | New version record exists with correct version number and timestamp matching the submission time |

**Postconditions:**
- Version creation latency is recorded and meets SLA requirement of under 1 second
- New version is successfully stored in the system
- User receives timely confirmation of the save operation

---

## Story: As Quote Manager, I want to view previous versions of a quote to compare changes over time
**Story ID:** story-14

### Test Case: Verify version history list and detail view
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in as Quote Manager with appropriate permissions
- At least one quote exists with multiple versions in the system
- Quote versions table contains historical version data
- API endpoint GET /api/quotes/{id}/versions is operational
- Version history UI component is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the quotes list and select a quote that has multiple versions | Quote details page opens displaying the current version of the quote |
| 2 | Click on the 'Version History' tab or button to navigate to version history | Version history section loads and displays within 2 seconds |
| 3 | Review the list of versions displayed in the version history | List shows all previous versions with version number, date/timestamp, and editor name for each version in chronological order |
| 4 | Verify that the version list loaded within the 2-second performance requirement | Version history list was displayed within 2 seconds from the time of navigation |
| 5 | Select a previous version from the list by clicking on it | Selected version details are displayed showing all quote fields and data as they existed in that version |
| 6 | Verify that the version details are displayed in read-only mode | All fields are displayed as read-only with no edit buttons or editable input fields visible |
| 7 | Attempt to click on or modify any field in the historical version view | Fields remain uneditable, cursor does not change to edit mode, and no modification is possible |
| 8 | Attempt to locate and click any 'Edit' or 'Save' buttons for the historical version | No edit or save buttons are available, or if present, they are disabled and non-functional |
| 9 | Select another previous version from the list | New version details are displayed in read-only mode, replacing the previous view |

**Postconditions:**
- User has successfully viewed version history without making any changes
- Historical versions remain unchanged and read-only
- User can navigate back to current quote version
- No data integrity issues with historical versions

---

## Story: As Quote Manager, I want to revert a quote to a previous version to correct errors or restore prior terms
**Story ID:** story-19

### Test Case: Verify successful revert to previous quote version
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as Quote Manager with revert permissions
- A quote exists with at least 2 versions in version history
- User has access to view and modify the quote
- Quote is in a state that allows revert operations
- API endpoint POST /api/quotes/{id}/revert is available and functional

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the quote details page for the target quote | Quote details page loads successfully displaying current version information |
| 2 | Click on 'Version History' button or link to view all quote versions | Version history panel/page opens showing list of all previous versions with timestamps, version numbers, and user who made changes |
| 3 | Review the list of previous versions and select a specific previous version to revert to | Selected version is highlighted and revert option becomes available for that version |
| 4 | Click the 'Revert' button for the selected previous version | Confirmation dialog is displayed with message asking user to confirm revert action, showing details of the version being reverted to |
| 5 | Review the confirmation dialog details and click 'Confirm' or 'Yes' button | System processes the revert request and creates a new version identical to the selected previous version |
| 6 | Wait for system processing to complete | Success confirmation message is displayed indicating the quote has been successfully reverted |
| 7 | View current quote details on the quote details page | Quote reflects all data from the reverted version including pricing, terms, line items, and all other fields |
| 8 | Check version history again | A new version entry appears in version history showing the revert action with current timestamp and user information |
| 9 | Verify that the new version data matches exactly with the selected previous version data | All fields in the new current version are identical to the selected previous version that was reverted to |

**Postconditions:**
- A new version is created in the quote version history
- Current quote state matches the selected previous version exactly
- Version history shows the revert action as the latest entry
- All business validation rules remain satisfied
- Quote remains accessible for further modifications if needed
- Audit trail records the revert operation with user and timestamp

---

