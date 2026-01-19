# Manual Test Cases

## Story: As Workflow Administrator, I want to create approval workflow templates to achieve standardized schedule change approvals
**Story ID:** story-8

### Test Case: Validate successful creation of workflow template
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Workflow Administrator role
- User has permissions to access workflow management features
- WorkflowTemplates and ApprovalSteps tables are accessible
- At least one valid approver role or user exists in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the workflow management page from the main menu or dashboard | Workflow management UI is displayed showing existing workflow templates list and 'Create New Workflow' button |
| 2 | Click on 'Create New Workflow' button | Workflow template creation form is displayed with fields for workflow name, description, and approval steps section |
| 3 | Enter unique workflow name 'Schedule Change Approval - Level 1' in the workflow name field | Workflow name is accepted and displayed in the input field |
| 4 | Enter workflow description 'Standard approval process for schedule changes requiring manager approval' | Description is accepted and displayed in the description field |
| 5 | Click 'Add Approval Step' button to add the first approval step | First approval step section is displayed with fields for step name, approver assignment, and escalation rules |
| 6 | Enter step name 'Manager Approval' and assign approver by selecting 'Manager' role from the dropdown | Step name and approver role are saved, and the approver assignment is displayed correctly |
| 7 | Configure escalation rule by setting escalation time to '24 hours' and escalation approver to 'Senior Manager' role | Escalation rules are configured and displayed in the approval step |
| 8 | Click 'Add Approval Step' button to add a second approval step | Second approval step section is displayed below the first step |
| 9 | Enter step name 'Director Approval' and assign approver by selecting specific user 'John Director' from the user dropdown | Second step is configured with individual approver assignment displayed correctly |
| 10 | Click 'Save and Activate' button at the bottom of the form | System validates the workflow configuration, saves the workflow template to WorkflowTemplates and ApprovalSteps tables, and displays success confirmation message 'Workflow template created and activated successfully' |
| 11 | Verify the workflow appears in the list of templates by scrolling through or searching for 'Schedule Change Approval - Level 1' | New workflow template 'Schedule Change Approval - Level 1' is listed in the workflow templates table with status 'Active', showing 2 approval steps and correct approver assignments |

**Postconditions:**
- New workflow template is saved in the database with status 'Active'
- Workflow template appears in the workflow templates list
- Workflow is available for assignment to schedule change requests
- Audit log records workflow creation with administrator details and timestamp

---

### Test Case: Verify validation prevents saving invalid workflow
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in with Workflow Administrator role
- User has permissions to access workflow management features
- Workflow management page is accessible
- Validation rules are configured for workflow templates

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the workflow management page | Workflow management UI is displayed with 'Create New Workflow' option |
| 2 | Click 'Create New Workflow' button | Workflow template creation form is displayed |
| 3 | Enter workflow name 'Incomplete Workflow Test' in the workflow name field | Workflow name is accepted and displayed |
| 4 | Click 'Add Approval Step' button to add an approval step | Approval step section is displayed with empty approver assignment field |
| 5 | Enter step name 'Manager Review' but leave the approver assignment field empty | Step name is entered but approver field remains empty |
| 6 | Click 'Save and Activate' button without assigning an approver | System displays validation error message 'Approver assignment is required for all approval steps' and prevents saving. The workflow template is not saved to the database |
| 7 | Review the error message and identify the missing approver assignment highlighted in red on the form | The approval step with missing approver is highlighted with red border and error indicator |
| 8 | Correct the approver assignment by selecting 'Manager' role from the approver dropdown for the first approval step | Approver 'Manager' role is assigned and displayed in the approval step, error highlighting is removed |
| 9 | Click 'Save and Activate' button again with valid approver assignment | System validates successfully, saves the workflow template, and displays confirmation message 'Workflow template created and activated successfully' |
| 10 | Verify the workflow 'Incomplete Workflow Test' appears in the workflow templates list | Workflow template is listed with status 'Active' and correct approver assignment displayed |

**Postconditions:**
- Invalid workflow configuration was prevented from being saved
- Corrected workflow template is saved successfully in the database
- Validation error messages are cleared after successful save
- Workflow is available for use with valid configuration

---

### Test Case: Ensure editing and deleting workflows works correctly
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in with Workflow Administrator role
- At least one existing workflow template 'Test Workflow for Edit' exists in the system
- User has permissions to edit and delete workflow templates
- Workflow management page is accessible
- Database supports concurrent edits with locking mechanism

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the workflow management page | Workflow management UI is displayed showing list of existing workflow templates including 'Test Workflow for Edit' |
| 2 | Locate 'Test Workflow for Edit' in the workflow templates list and click the 'Edit' button or icon next to it | Workflow edit form is displayed with all existing workflow details pre-populated including workflow name, description, and current approval steps with assigned approvers |
| 3 | Verify that all existing approval steps are loaded correctly in the edit form | All approval steps are displayed with correct step names, approver assignments, and escalation rules matching the saved configuration |
| 4 | Modify the first approval step by changing the approver from 'Manager' role to 'Senior Manager' role | Approver assignment is updated to 'Senior Manager' role and displayed in the approval step |
| 5 | Click 'Add Approval Step' button to add a new third approval step | New approval step section is added to the workflow configuration |
| 6 | Configure the new approval step with name 'Final Review' and assign approver 'VP Operations' individual user | Third approval step is configured and displayed with correct details |
| 7 | Click 'Save Changes' button to save the modified workflow | System validates the changes, updates the workflow in WorkflowTemplates and ApprovalSteps tables, and displays confirmation message 'Workflow template updated successfully' |
| 8 | Verify the changes are reflected in the workflow list by locating 'Test Workflow for Edit' and checking the approval steps count | Workflow template shows 3 approval steps and the modified approver assignments are displayed correctly in the list view |
| 9 | Locate a workflow template to delete (e.g., 'Obsolete Workflow Template') and click the 'Delete' button or icon | System displays confirmation dialog with message 'Are you sure you want to delete this workflow template? This action cannot be undone.' with 'Cancel' and 'Confirm Delete' buttons |
| 10 | Click 'Cancel' button in the confirmation dialog | Confirmation dialog closes and the workflow template remains in the list, no deletion occurs |
| 11 | Click the 'Delete' button again for the same workflow template | Confirmation dialog is displayed again |
| 12 | Click 'Confirm Delete' button in the confirmation dialog | System removes the workflow template from the database, displays success message 'Workflow template deleted successfully', and the workflow is removed from the templates list |
| 13 | Verify the deleted workflow no longer appears in the workflow templates list | Deleted workflow template is not visible in the list and the total count of workflows is decreased by one |

**Postconditions:**
- Modified workflow template is updated in the database with new approval steps and approver assignments
- Deleted workflow template is removed from the database and no longer available for use
- Workflow templates list reflects all changes accurately
- Audit log records edit and delete operations with administrator details and timestamps
- No orphaned approval steps remain in the ApprovalSteps table after deletion

---

