# Manual Test Cases

## Story: As Employee, I want to submit schedule change requests to achieve formal processing and approval
**Story ID:** story-23

### Test Case: Validate successful schedule change request submission with valid data
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee has valid login credentials
- Employee is authenticated in the scheduling system
- Employee has permission to submit schedule change requests
- Supporting document (PDF/DOC) under 10MB is available for upload
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to schedule change request submission page | Submission form is displayed with all mandatory fields including employee name, current schedule, requested schedule, reason for change, effective date, and attachment option |
| 2 | Enter valid employee name in the employee name field | Employee name is accepted and displayed in the field without validation errors |
| 3 | Enter current schedule details (e.g., Monday-Friday, 9:00 AM - 5:00 PM) | Current schedule details are accepted and displayed correctly |
| 4 | Enter requested schedule details (e.g., Tuesday-Saturday, 10:00 AM - 6:00 PM) | Requested schedule details are accepted and displayed correctly |
| 5 | Enter a valid reason for the schedule change (e.g., 'Personal commitment requiring schedule adjustment') | Reason is accepted and displayed in the text field |
| 6 | Select a valid effective date (future date) using the date picker | Date is selected and displayed in correct format (MM/DD/YYYY or DD/MM/YYYY based on locale) |
| 7 | Click on the attachment button and select a valid document (e.g., medical certificate, 2MB PDF) | Document is uploaded successfully, file name and size are displayed, no error messages appear |
| 8 | Review all entered data for accuracy | All fields display the entered information correctly |
| 9 | Click the Submit button | Request is saved to ScheduleChangeRequests table, approval workflow is initiated automatically, confirmation message is displayed with unique request ID (e.g., 'Your request #SCR-12345 has been submitted successfully'), response time is under 2 seconds |

**Postconditions:**
- Schedule change request is saved in the database with status 'Pending Approval'
- Approval workflow is initiated and assigned to appropriate approver
- Attached document is stored in DocumentStorage and linked to the request
- Request ID is generated and associated with the submission
- Employee can view the submitted request in their request history

---

### Test Case: Verify rejection of submission with missing mandatory fields
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- Employee has valid login credentials
- Employee is authenticated in the scheduling system
- Employee has navigated to the schedule change request submission page
- All mandatory fields are clearly marked with asterisks or 'required' labels

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to submission page | Form is displayed with all mandatory fields marked as required (employee name, current schedule, requested schedule, reason, effective date) |
| 2 | Leave the employee name field empty | Field remains empty, no data is entered |
| 3 | Enter valid data in current schedule field | Current schedule data is accepted |
| 4 | Leave the requested schedule field empty | Field remains empty, no data is entered |
| 5 | Enter valid reason for change | Reason is accepted and displayed |
| 6 | Leave the effective date field empty | Field remains empty, no date is selected |
| 7 | Click outside the empty mandatory fields or tab to next field | Real-time validation highlights missing fields with red borders or error icons, inline error messages appear (e.g., 'This field is required') |
| 8 | Attempt to submit the form by clicking the Submit button | Submission is blocked, form does not submit, error summary message is displayed at the top of the form (e.g., 'Please complete all required fields'), focus is set to the first missing mandatory field |
| 9 | Verify that all empty mandatory fields are highlighted with error messages | All missing mandatory fields (employee name, requested schedule, effective date) display individual error messages and visual indicators |

**Postconditions:**
- No request is saved to the database
- No approval workflow is initiated
- Form remains on the submission page with entered data preserved
- Error messages are clearly visible to guide user correction

---

### Test Case: Test attachment upload size limit enforcement
- **ID:** tc-003
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Employee has valid login credentials
- Employee is authenticated in the scheduling system
- Test file larger than 10MB (e.g., 12MB PDF) is prepared
- Test file within size limit (e.g., 5MB PDF) is prepared
- Employee has navigated to the schedule change request submission page

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to submission form | Form is displayed with all fields including attachment upload option, size limit information is visible (e.g., 'Maximum file size: 10MB') |
| 2 | Click on the attachment upload button | File browser dialog opens allowing file selection |
| 3 | Select a document larger than 10MB (e.g., 12MB PDF file) | File selection dialog closes and system begins validation |
| 4 | Observe the upload attempt | Upload is rejected immediately, error message is displayed (e.g., 'File size exceeds maximum limit of 10MB. Please select a smaller file'), no file is attached to the form, attachment field remains empty |
| 5 | Click on the attachment upload button again | File browser dialog opens again for new selection |
| 6 | Select a valid size document (e.g., 5MB PDF file) | File is uploaded successfully, file name and size are displayed in the attachment field (e.g., 'medical_certificate.pdf (5MB)'), no error messages appear |
| 7 | Complete all other mandatory fields with valid data (employee name, current schedule, requested schedule, reason, effective date) | All fields accept valid data without errors |
| 8 | Click the Submit button | Submission succeeds, request is saved with attachment linked, approval workflow is initiated, confirmation message with request ID is displayed, attached document is stored in DocumentStorage API |

**Postconditions:**
- Schedule change request is saved in the database with valid attachment
- Attachment file is stored in DocumentStorage and associated with the request ID
- Approval workflow is initiated successfully
- Employee receives confirmation with request ID
- Oversized file is not stored in the system

---

