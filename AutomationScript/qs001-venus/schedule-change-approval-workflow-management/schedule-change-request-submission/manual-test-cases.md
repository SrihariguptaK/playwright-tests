# Manual Test Cases

## Story: As Employee, I want to submit schedule change requests to achieve timely updates to my work schedule
**Story ID:** story-1

### Test Case: Validate successful schedule change request submission with valid data
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee is logged into the system with valid credentials
- Employee has necessary permissions to submit schedule change requests
- Schedule change request page is accessible
- Test attachment file (PDF, 5MB) is prepared for upload

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule change request page from the main dashboard or menu | Schedule change request form is displayed with all mandatory fields visible including: Employee Name, Current Schedule, Requested Schedule, Reason for Change, Effective Date, and Attachment Upload option |
| 2 | Enter valid data in Employee Name field (e.g., 'John Smith') | Employee Name field accepts the input without any validation errors |
| 3 | Enter valid Current Schedule details (e.g., 'Monday-Friday, 9:00 AM - 5:00 PM') | Current Schedule field accepts the input without any validation errors |
| 4 | Enter valid Requested Schedule details (e.g., 'Monday-Friday, 10:00 AM - 6:00 PM') | Requested Schedule field accepts the input without any validation errors |
| 5 | Enter valid Reason for Change (e.g., 'Need to accommodate childcare schedule') | Reason for Change field accepts the input without any validation errors |
| 6 | Select valid Effective Date using date picker (e.g., a date 7 days in the future) | Effective Date field accepts the selected date in correct format without validation errors |
| 7 | Click on the attachment upload button and select a valid file (PDF, 5MB) | File upload progress indicator appears, file is successfully uploaded, file name is displayed with file size, no error messages appear |
| 8 | Review all entered data for accuracy | All fields display the entered data correctly |
| 9 | Click the 'Submit' button | System processes the request within 2 seconds, request is saved to ScheduleChangeRequests table, status is automatically set to 'Pending Approval', confirmation message is displayed stating 'Your schedule change request has been submitted successfully. Request ID: [ID]', page redirects to confirmation page or displays success notification |
| 10 | Verify the request appears in the employee's request history or dashboard | Submitted request is visible with status 'Pending Approval' and all entered details are correctly displayed |

**Postconditions:**
- Schedule change request is saved in the database with unique request ID
- Request status is set to 'Pending Approval'
- Uploaded attachment is stored and linked to the request
- Employee can view the submitted request in their request history
- Request is available in the approval workflow queue

---

### Test Case: Verify rejection of submission with missing mandatory fields
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Employee is logged into the system with valid credentials
- Employee has necessary permissions to access schedule change request page
- Schedule change request page is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule change request page from the main dashboard or menu | Schedule change request form is displayed with all mandatory fields marked with asterisks (*) or 'Required' labels |
| 2 | Leave the Employee Name field empty | Field remains empty without immediate validation error (validation occurs on blur or submit) |
| 3 | Leave the Current Schedule field empty | Field remains empty without immediate validation error |
| 4 | Leave the Requested Schedule field empty | Field remains empty without immediate validation error |
| 5 | Leave the Reason for Change field empty | Field remains empty without immediate validation error |
| 6 | Leave the Effective Date field empty | Field remains empty without immediate validation error |
| 7 | Click the 'Submit' button without filling any mandatory fields | Form submission is blocked, page does not refresh or navigate away, inline validation error messages appear next to each empty mandatory field (e.g., 'Employee Name is required', 'Current Schedule is required', 'Requested Schedule is required', 'Reason for Change is required', 'Effective Date is required'), empty fields are highlighted with red borders or error styling, focus moves to the first invalid field |
| 8 | Fill in only the Employee Name field with valid data (e.g., 'Jane Doe') and attempt to submit again | Form submission is still blocked, error messages remain for all other empty mandatory fields, Employee Name field error is cleared and field shows valid styling |
| 9 | Progressively fill in each mandatory field one by one and observe validation behavior | As each field is filled with valid data, its corresponding error message disappears and field styling changes to valid state, remaining empty fields continue to show error messages |
| 10 | Verify that the Submit button remains disabled or submission continues to be blocked until all mandatory fields are completed | Submit button functionality prevents submission until all mandatory field validations pass |

**Postconditions:**
- No data is saved to the database
- User remains on the schedule change request form
- Form retains any valid data entered by the user
- Error messages are clearly visible for all validation failures

---

### Test Case: Test attachment upload validation
- **ID:** tc-003
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Employee is logged into the system with valid credentials
- Employee has necessary permissions to submit schedule change requests
- Schedule change request page is accessible
- Test files are prepared: one file exceeding 10MB size limit (e.g., 12MB PDF), one invalid file type (e.g., .exe or .bat file), one valid file (e.g., 5MB PDF)

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule change request page from the main dashboard or menu | Schedule change request form is displayed with attachment upload section visible, accepted file types and size limits are displayed (e.g., 'Accepted formats: PDF, DOC, DOCX, JPG, PNG. Maximum size: 10MB') |
| 2 | Click on the attachment upload button | File browser dialog opens allowing file selection |
| 3 | Select a file that exceeds the 10MB size limit (e.g., 12MB PDF file) | File upload is rejected, validation error message is displayed stating 'File size exceeds the maximum limit of 10MB', file is not uploaded, no file name appears in the attachment area |
| 4 | Click on the attachment upload button again | File browser dialog opens again for new file selection |
| 5 | Select a file with an invalid file type (e.g., .exe or .bat file) | File upload is rejected, validation error message is displayed stating 'Invalid file type. Accepted formats are: PDF, DOC, DOCX, JPG, PNG', file is not uploaded, no file name appears in the attachment area |
| 6 | Clear any error messages and click on the attachment upload button again | File browser dialog opens, previous error messages are cleared |
| 7 | Select a valid file that meets all requirements (e.g., 5MB PDF file named 'schedule_justification.pdf') | File upload begins with progress indicator displayed, upload completes successfully within reasonable time, file name 'schedule_justification.pdf' is displayed in the attachment area, file size '5MB' is shown next to the file name, no error messages appear, a remove/delete icon appears next to the uploaded file |
| 8 | Verify the uploaded file can be previewed or downloaded (if functionality exists) | File preview or download link is functional and displays/downloads the correct file |
| 9 | Click the remove/delete icon next to the uploaded file | File is removed from the attachment area, upload section returns to initial state allowing new file upload |
| 10 | Upload the valid file again and fill in all mandatory fields with valid data, then submit the form | Form submits successfully with the attached file, confirmation message is displayed, attachment is saved and linked to the schedule change request |

**Postconditions:**
- Only valid attachments within size and type constraints are accepted
- Invalid attachments are rejected with clear error messages
- Valid attachment is stored and associated with the schedule change request
- System maintains data integrity by enforcing attachment validation rules

---

