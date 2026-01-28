# Manual Test Cases

## Story: As HR Manager, I want to prevent deletion of shift templates assigned to active schedules to achieve data integrity
**Story ID:** db-story-story-6

### Test Case: Verify system blocks deletion of shift template assigned to active schedules
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as HR Manager with delete permissions
- At least one shift template exists in the system
- The shift template is assigned to one or more active schedules
- User is on the Shift Templates management page

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the Shift Templates management page | Shift Templates page loads successfully displaying list of all shift templates |
| 2 | Identify a shift template that is assigned to active schedules | Shift template is visible in the list with assignment indicator |
| 3 | Click on the delete button/icon for the selected shift template | System initiates deletion process and checks for active schedule assignments |
| 4 | Observe the system response | System displays a warning message stating 'This shift template cannot be deleted as it is assigned to active schedules' or similar clear message |
| 5 | Verify the deletion is blocked | Delete operation is prevented and the shift template remains in the system |
| 6 | Click OK or Close on the warning message | Warning dialog closes and user returns to Shift Templates page with template still present |

**Postconditions:**
- Shift template remains in the system unchanged
- Active schedules continue to reference the shift template
- Deletion attempt is logged in the audit trail
- No data integrity issues occur

---

### Test Case: Verify system allows deletion of shift template not assigned to any schedules
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as HR Manager with delete permissions
- At least one shift template exists that is NOT assigned to any schedules
- User is on the Shift Templates management page

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the Shift Templates management page | Shift Templates page loads successfully displaying list of all shift templates |
| 2 | Identify a shift template that is not assigned to any schedules | Shift template is visible in the list without any assignment indicator |
| 3 | Click on the delete button/icon for the unassigned shift template | System initiates deletion process and checks for active schedule assignments |
| 4 | Observe the system response | System displays a confirmation dialog asking 'Are you sure you want to delete this shift template?' |
| 5 | Click 'Confirm' or 'Yes' on the confirmation dialog | System processes the deletion request via DELETE /api/shifttemplates/{id} endpoint |
| 6 | Observe the deletion result | System displays success message 'Shift template deleted successfully' and removes the template from the list |
| 7 | Verify the template is no longer in the list | Deleted shift template is not visible in the Shift Templates list |

**Postconditions:**
- Shift template is permanently removed from the system
- Shift Templates list is updated and does not show the deleted template
- Deletion is logged in the audit trail with success status
- No schedules are affected as template was unassigned

---

### Test Case: Verify system logs deletion attempts for templates assigned to active schedules
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in as HR Manager with delete permissions
- At least one shift template exists that is assigned to active schedules
- User has access to audit logs or system logs
- User is on the Shift Templates management page

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the Shift Templates management page | Shift Templates page loads successfully |
| 2 | Note the current timestamp and the shift template ID to be deleted | Template ID and timestamp are recorded for audit verification |
| 3 | Attempt to delete a shift template that is assigned to active schedules | System blocks deletion and displays warning message |
| 4 | Close the warning message | User returns to Shift Templates page |
| 5 | Navigate to the audit logs or system logs section | Audit logs page loads successfully |
| 6 | Search for the deletion attempt using the template ID and timestamp | Log entry is found for the deletion attempt |
| 7 | Verify the log entry contains: timestamp, user ID, template ID, action attempted (DELETE), outcome (BLOCKED), and reason | Log entry shows all required information including 'BLOCKED - Template assigned to active schedules' |

**Postconditions:**
- Deletion attempt is recorded in audit logs
- Log entry contains complete information for audit purposes
- Audit trail maintains data integrity

---

### Test Case: Verify system logs successful deletion of unassigned templates
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in as HR Manager with delete permissions
- At least one shift template exists that is NOT assigned to any schedules
- User has access to audit logs or system logs
- User is on the Shift Templates management page

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the Shift Templates management page | Shift Templates page loads successfully |
| 2 | Note the current timestamp and the shift template ID to be deleted | Template ID and timestamp are recorded for audit verification |
| 3 | Delete a shift template that is not assigned to any schedules | System allows deletion and displays success message |
| 4 | Navigate to the audit logs or system logs section | Audit logs page loads successfully |
| 5 | Search for the deletion event using the template ID and timestamp | Log entry is found for the deletion event |
| 6 | Verify the log entry contains: timestamp, user ID, template ID, action performed (DELETE), and outcome (SUCCESS) | Log entry shows all required information including 'SUCCESS - Template deleted' |

**Postconditions:**
- Successful deletion is recorded in audit logs
- Log entry contains complete information for compliance
- Audit trail is complete and accurate

---

### Test Case: Verify warning message clarity when attempting to delete assigned template
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in as HR Manager with delete permissions
- At least one shift template exists that is assigned to active schedules
- User is on the Shift Templates management page

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the Shift Templates management page | Shift Templates page loads successfully |
| 2 | Attempt to delete a shift template assigned to active schedules | System displays a warning dialog |
| 3 | Read and verify the warning message content | Warning message clearly states: 1) Template cannot be deleted, 2) Reason is assignment to active schedules, 3) Suggests alternative actions if applicable |
| 4 | Verify the warning dialog has appropriate buttons (OK, Close, or Cancel) | Dialog has clear dismissal option without proceeding with deletion |
| 5 | Check if the warning message includes the number of active schedules using the template | Message optionally displays count of affected schedules for user awareness |

**Postconditions:**
- User understands why deletion was blocked
- User awareness of deletion restrictions is achieved
- Template remains in the system

---

### Test Case: Verify real-time usage check performance when deleting template
- **ID:** tc-006
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in as HR Manager with delete permissions
- Multiple shift templates exist in the system
- Some templates are assigned to active schedules, some are not
- User is on the Shift Templates management page

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the Shift Templates management page | Shift Templates page loads successfully |
| 2 | Note the current time and click delete on a shift template assigned to active schedules | System initiates real-time usage check |
| 3 | Measure the time taken for the system to display the warning message | Warning message appears within 2-3 seconds indicating real-time performance |
| 4 | Close the warning dialog | Dialog closes and user returns to template list |
| 5 | Note the current time and click delete on an unassigned shift template | System initiates real-time usage check |
| 6 | Measure the time taken for the system to display the confirmation dialog | Confirmation dialog appears within 2-3 seconds indicating real-time performance |

**Postconditions:**
- System performs usage checks in real-time without delays
- User experience is not impacted by performance issues
- Both assigned and unassigned templates are checked efficiently

---

### Test Case: Verify role-based access control for template deletion
- **ID:** tc-007
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with a role other than HR Manager (e.g., Employee, Supervisor)
- Shift templates exist in the system
- User navigates to Shift Templates page or attempts to access deletion functionality

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Login with a user account that does not have HR Manager role | User successfully logs into the system |
| 2 | Attempt to navigate to the Shift Templates management page | Either page is not accessible or delete functionality is not visible/enabled |
| 3 | If page is accessible, verify that delete buttons/icons are not present or are disabled | Delete functionality is not available to unauthorized users |
| 4 | If attempting direct API call, send DELETE request to /api/shifttemplates/{id} | System returns 403 Forbidden or 401 Unauthorized error |
| 5 | Verify error message indicates insufficient permissions | Clear error message states 'You do not have permission to delete shift templates' or similar |

**Postconditions:**
- Unauthorized user cannot delete shift templates
- Security is maintained through role-based access control
- Unauthorized attempt is logged in audit trail

---

### Test Case: Verify system behavior when template becomes assigned between check and deletion
- **ID:** tc-008
- **Type:** edge-case
- **Priority:** Medium
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as HR Manager with delete permissions
- At least one shift template exists that is currently unassigned
- Another HR Manager or system process can assign templates to schedules
- User is on the Shift Templates management page

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the Shift Templates management page | Shift Templates page loads successfully |
| 2 | Identify an unassigned shift template and initiate deletion | System displays confirmation dialog for deletion |
| 3 | Before confirming deletion, have another user assign this template to an active schedule | Template is now assigned to an active schedule in the database |
| 4 | Click 'Confirm' on the deletion dialog | System performs final usage check before executing deletion |
| 5 | Observe the system response | System detects the template is now assigned and blocks deletion with appropriate warning message |
| 6 | Verify the template remains in the system | Template is not deleted and remains assigned to the active schedule |

**Postconditions:**
- Template remains in the system despite initial unassigned status
- Data integrity is maintained through final usage check
- No schedule inconsistencies occur

---

### Test Case: Verify system behavior when attempting to delete multiple templates simultaneously
- **ID:** tc-009
- **Type:** edge-case
- **Priority:** Low
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as HR Manager with delete permissions
- Multiple shift templates exist in the system
- Some templates are assigned to active schedules, some are not
- System supports bulk deletion or multiple selection
- User is on the Shift Templates management page

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the Shift Templates management page | Shift Templates page loads successfully |
| 2 | Select multiple shift templates including both assigned and unassigned templates | Multiple templates are selected as indicated by checkboxes or highlighting |
| 3 | Click the bulk delete button or delete action | System initiates usage check for all selected templates |
| 4 | Observe the system response | System displays a message indicating which templates can be deleted and which cannot, with reasons |
| 5 | Verify the message lists assigned templates that will be skipped | Clear list shows templates blocked from deletion due to active schedule assignments |
| 6 | Confirm the bulk deletion | System deletes only the unassigned templates and preserves assigned ones |
| 7 | Verify the results in the template list | Unassigned templates are removed, assigned templates remain in the list |

**Postconditions:**
- Only unassigned templates are deleted
- Assigned templates remain in the system
- All deletion attempts are logged in audit trail
- Data integrity is maintained

---

### Test Case: Verify system behavior when template is assigned to inactive schedules
- **ID:** tc-010
- **Type:** boundary
- **Priority:** Medium
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in as HR Manager with delete permissions
- At least one shift template exists that is assigned only to inactive/past schedules
- No active schedules are using this template
- User is on the Shift Templates management page

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the Shift Templates management page | Shift Templates page loads successfully |
| 2 | Identify a shift template that is assigned only to inactive or past schedules | Template is visible in the list |
| 3 | Click on the delete button for this template | System checks for active schedule assignments only |
| 4 | Observe the system response | System allows deletion since template is not assigned to any ACTIVE schedules and displays confirmation dialog |
| 5 | Confirm the deletion | System successfully deletes the template and displays success message |
| 6 | Verify the template is removed from the list | Template no longer appears in the Shift Templates list |

**Postconditions:**
- Template assigned only to inactive schedules is successfully deleted
- Inactive schedules maintain historical reference if needed
- Deletion is logged in audit trail
- System correctly distinguishes between active and inactive schedule assignments

---

### Test Case: Verify API endpoint returns correct error code when deleting assigned template
- **ID:** tc-011
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User has valid authentication token with HR Manager role
- At least one shift template exists that is assigned to active schedules
- API endpoint DELETE /api/shifttemplates/{id} is accessible
- User has API testing tool (Postman, curl, etc.)

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Identify the ID of a shift template assigned to active schedules | Template ID is obtained from the system |
| 2 | Send DELETE request to /api/shifttemplates/{id} with valid authentication token | API receives the request and processes it |
| 3 | Verify the HTTP response status code | API returns 409 Conflict or 400 Bad Request status code |
| 4 | Verify the response body contains error details | Response includes error message explaining template is assigned to active schedules |
| 5 | Verify the response includes appropriate error code or identifier | Response contains structured error information (e.g., errorCode: 'TEMPLATE_IN_USE') |
| 6 | Verify the template still exists in the database | Template is not deleted and remains in the system |

**Postconditions:**
- Template remains in the system
- API returns appropriate error response
- Deletion attempt is logged
- Data integrity is maintained

---

### Test Case: Verify API endpoint returns success when deleting unassigned template
- **ID:** tc-012
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User has valid authentication token with HR Manager role
- At least one shift template exists that is NOT assigned to any schedules
- API endpoint DELETE /api/shifttemplates/{id} is accessible
- User has API testing tool (Postman, curl, etc.)

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Identify the ID of a shift template not assigned to any schedules | Template ID is obtained from the system |
| 2 | Send DELETE request to /api/shifttemplates/{id} with valid authentication token | API receives the request and processes it |
| 3 | Verify the HTTP response status code | API returns 200 OK or 204 No Content status code |
| 4 | Verify the response body contains success confirmation | Response includes success message or empty body for 204 status |
| 5 | Send GET request to retrieve the deleted template | API returns 404 Not Found confirming template no longer exists |
| 6 | Verify the template is removed from the database | Template cannot be found in the system |

**Postconditions:**
- Template is permanently deleted from the system
- API returns successful response
- Deletion is logged in audit trail
- Template is no longer accessible via API

---

