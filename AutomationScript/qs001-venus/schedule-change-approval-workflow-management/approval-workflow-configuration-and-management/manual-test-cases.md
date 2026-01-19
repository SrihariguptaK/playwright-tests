# Manual Test Cases

## Story: As Administrator, I want to configure approval workflows to achieve flexible and compliant schedule change approvals
**Story ID:** story-2

### Test Case: Validate creation of multi-step approval workflow
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Administrator role
- ApprovalWorkflows and WorkflowSteps tables are accessible
- At least three valid approver roles exist in the system
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Administrator navigates to workflow configuration page from the main menu | Workflow configuration UI is displayed with options to create new workflow, view existing workflows, and configuration controls |
| 2 | Administrator clicks 'Create New Workflow' button | New workflow creation form is displayed with fields for workflow name, description, and step configuration |
| 3 | Administrator enters workflow name 'Schedule Change Approval Process' and description 'Three-tier approval for schedule modifications' | Workflow name and description are accepted and displayed in the form |
| 4 | Administrator creates first workflow step with order number 1, step name 'Manager Approval', and assigns 'Manager' role as approver | First workflow step is created and displayed with order 1, step name, and assigned approver role |
| 5 | Administrator creates second workflow step with order number 2, step name 'Department Head Approval', and assigns 'Department Head' role as approver | Second workflow step is created and displayed with order 2, step name, and assigned approver role in correct sequence |
| 6 | Administrator creates third workflow step with order number 3, step name 'HR Approval', and assigns 'HR Manager' role as approver | Third workflow step is created and displayed with order 3, step name, and assigned approver role. All three steps are displayed in correct order (1, 2, 3) |
| 7 | Administrator clicks 'Save and Activate' button | Workflow is persisted to ApprovalWorkflows and WorkflowSteps tables, success message is displayed confirming 'Workflow activated successfully', and workflow appears in active workflows list |
| 8 | Administrator verifies the workflow appears in the active workflows list with all three steps visible | Workflow 'Schedule Change Approval Process' is listed with status 'Active' and shows 3 steps in correct order with assigned approvers |

**Postconditions:**
- New workflow is saved in ApprovalWorkflows table
- Three workflow steps are saved in WorkflowSteps table with correct order
- Workflow status is set to 'Active'
- Configuration changes are reflected within 1 minute
- Workflow is available for assignment to schedule change requests

---

### Test Case: Verify validation prevents duplicate step orders
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with Administrator role
- Workflow configuration page is accessible
- System validation rules are active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Administrator navigates to workflow configuration page | Workflow configuration UI is displayed |
| 2 | Administrator clicks 'Create New Workflow' button | New workflow creation form is displayed |
| 3 | Administrator enters workflow name 'Test Duplicate Steps Workflow' | Workflow name is accepted and displayed |
| 4 | Administrator creates first workflow step with order number 1, step name 'First Approval', and assigns 'Manager' role | First workflow step is created with order 1 |
| 5 | Administrator attempts to create second workflow step with the same order number 1, step name 'Second Approval', and assigns 'Department Head' role | Validation error is displayed with message 'Duplicate step order detected. Each step must have a unique order number.' and the step is not added to the workflow |
| 6 | Administrator attempts to click 'Save' button | Save operation is blocked and validation error message persists, preventing workflow from being saved with duplicate step orders |
| 7 | Administrator corrects the second step order number to 2 | Validation error clears and second step is successfully added with order 2 |

**Postconditions:**
- Workflow with duplicate step orders is not saved to database
- Data integrity is maintained in WorkflowSteps table
- Administrator is informed of validation error
- Corrected workflow can be saved successfully

---

### Test Case: Ensure only administrators can access workflow configuration
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Test user account exists with non-administrator role (e.g., 'Employee' or 'Manager')
- User is logged in with non-admin credentials
- Role-based access control is enabled
- Workflow configuration module requires Admin role

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Non-admin user attempts to navigate to workflow configuration page by entering the URL directly or clicking menu option (if visible) | Access is denied immediately with HTTP 403 Forbidden status or appropriate error page is displayed |
| 2 | System displays error message to the user | Error message states 'Access Denied: You do not have permission to access workflow configuration. Administrator role required.' or similar appropriate message |
| 3 | Non-admin user attempts to access workflow configuration API endpoint directly (POST /api/approval-workflows) | API returns 403 Forbidden status with error response indicating insufficient permissions |
| 4 | Verify user is redirected to appropriate page (dashboard or previous page) | User is redirected to their dashboard or previous authorized page, workflow configuration page remains inaccessible |
| 5 | Log out non-admin user and log in with Administrator credentials | Administrator successfully logs in |
| 6 | Administrator navigates to workflow configuration page | Workflow configuration page loads successfully with full access to all configuration features |

**Postconditions:**
- Non-admin user access attempt is logged in security audit logs
- No unauthorized changes are made to workflow configurations
- System security integrity is maintained
- Administrator can access workflow configuration without issues

---

## Story: As Administrator, I want to audit approval workflows and decisions to achieve compliance and accountability
**Story ID:** story-6

### Test Case: Validate audit logs record workflow configuration changes
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in with Administrator role
- At least one active approval workflow exists in the system
- AuditLogs table is accessible and functioning
- Audit logging is enabled system-wide
- System timestamp is accurate

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Administrator navigates to workflow configuration page | Workflow configuration page is displayed with list of existing workflows |
| 2 | Administrator selects an existing workflow 'Schedule Change Approval Process' and clicks 'Edit' | Workflow edit form is displayed with current configuration details |
| 3 | Administrator modifies the workflow by changing step 2 approver from 'Department Head' to 'Senior Manager' role | Change is reflected in the workflow configuration form |
| 4 | Administrator clicks 'Save Changes' button | Workflow modification is saved successfully and confirmation message is displayed |
| 5 | Administrator navigates to the audit log viewer module from the main menu | Audit log viewer interface is displayed with search and filter options |
| 6 | Administrator applies filter for 'Workflow Configuration' event type and current date | Filter is applied and audit log entries matching the criteria are displayed |
| 7 | Administrator locates the most recent audit entry for 'Schedule Change Approval Process' workflow | Audit log entry is displayed showing: Event Type: 'Workflow Modified', Workflow Name: 'Schedule Change Approval Process', User: current administrator username, Timestamp: current date and time (within last few minutes), Change Details: 'Step 2 approver changed from Department Head to Senior Manager' |
| 8 | Administrator clicks on the audit entry to view full details | Detailed audit information is displayed including before/after values, IP address, session ID, and complete change history |

**Postconditions:**
- Audit log entry is permanently stored in AuditLogs table
- Audit entry contains complete user identification and timestamp
- Workflow modification is traceable through audit trail
- Audit data is available for compliance reporting

---

### Test Case: Verify audit logs record approval decisions and comments
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User with Approver role is logged in
- At least one pending approval request exists in the system
- Approval workflow is active and assigned to the request
- AuditLogs and ApprovalDecisions tables are accessible
- Administrator account is available for audit log review

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Approver navigates to pending approvals queue | List of pending approval requests is displayed |
| 2 | Approver selects a pending schedule change request and clicks 'Review' | Approval request details are displayed with options to Approve or Reject and comment field |
| 3 | Approver enters comment 'Approved due to business critical requirement. Verified with department head.' in the comments field | Comment text is entered and displayed in the comment field |
| 4 | Approver clicks 'Approve' button | Approval decision is submitted successfully, confirmation message is displayed, and request status is updated |
| 5 | Log out approver and log in with Administrator credentials | Administrator is successfully logged in |
| 6 | Administrator navigates to audit log viewer module | Audit log viewer interface is displayed |
| 7 | Administrator applies filter for 'Approval Decision' event type and selects the specific request ID | Audit log entries for the approval decision are displayed |
| 8 | Administrator reviews the audit entry for the approval decision | Audit log entry shows: Event Type: 'Approval Decision', Decision: 'Approved', Approver: approver username, Timestamp: decision submission time, Comments: 'Approved due to business critical requirement. Verified with department head.', Request ID: specific request identifier |
| 9 | Administrator selects 'Export' option and chooses 'PDF' format | Export dialog is displayed with PDF format selected |
| 10 | Administrator clicks 'Generate Report' button | Audit report is generated in PDF format and download begins automatically or download link is provided |
| 11 | Administrator opens the downloaded PDF file | PDF audit report contains the approval decision entry with all details including user, timestamp, decision, and comments in readable format |
| 12 | Administrator returns to audit log viewer and selects 'Export' with 'CSV' format | CSV export is generated and downloaded successfully |
| 13 | Administrator opens the CSV file in spreadsheet application | CSV file contains audit log data in structured columns including Event Type, User, Timestamp, Decision, Comments, and Request ID |

**Postconditions:**
- Approval decision is recorded in ApprovalDecisions table
- Complete audit trail is stored in AuditLogs table
- Audit reports are generated in both PDF and CSV formats
- All approval comments are preserved in audit logs
- Exported files are available for compliance review

---

### Test Case: Ensure only administrators can access audit logs
- **ID:** tc-006
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Test user account exists with non-administrator role (e.g., 'Employee', 'Manager', or 'Approver')
- User is logged in with non-admin credentials
- Audit logs contain data in the system
- Role-based access control is enabled
- Audit log viewer requires Admin role

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Non-admin user attempts to navigate to audit log viewer module by entering URL directly or clicking menu option (if visible) | Access is denied with HTTP 403 Forbidden status or error page is displayed |
| 2 | System displays error message to the user | Error message states 'Access Denied: Audit logs are restricted to administrators only. You do not have sufficient permissions.' or similar appropriate message |
| 3 | Non-admin user attempts to access audit logs API endpoint directly (GET /api/audit-logs) | API returns 403 Forbidden status with JSON error response indicating insufficient permissions and no audit data is returned |
| 4 | Non-admin user attempts to access audit export functionality directly | Access is denied and no audit data export is generated |
| 5 | Verify the access denial attempt is logged | Security event is logged recording the unauthorized access attempt with user ID, timestamp, and attempted resource |
| 6 | Log out non-admin user and log in with Administrator credentials | Administrator successfully logs in |
| 7 | Administrator navigates to audit log viewer module | Audit log viewer loads successfully with full access to all audit logs and filtering options |
| 8 | Administrator verifies the unauthorized access attempt is logged in security audit | Audit log contains entry showing non-admin user's failed access attempt to audit log viewer with timestamp and user details |

**Postconditions:**
- Non-admin user access attempt is logged in security audit
- No audit data is exposed to unauthorized users
- System security and data confidentiality is maintained
- Administrator can access audit logs without restrictions
- Compliance requirements for audit log access control are met

---

