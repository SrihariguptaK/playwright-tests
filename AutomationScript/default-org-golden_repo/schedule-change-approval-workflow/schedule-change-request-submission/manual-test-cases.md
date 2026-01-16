# Manual Test Cases

## Story: As Employee, I want to submit schedule change requests to achieve timely updates to my work schedule
**Story ID:** story-11

### Test Case: Validate successful schedule change request submission with valid data
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee has valid login credentials and is authenticated in the system
- Employee has active employment status in the system
- Schedule change request form is accessible and functional
- Database connection to ScheduleChangeRequests table is active
- Approval workflow service is running and available
- Employee has a valid document file (PDF, DOC, or DOCX) under 5MB ready for upload

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Employee logs into the scheduling system using valid credentials | Employee is successfully authenticated and redirected to the dashboard |
| 2 | Employee navigates to the schedule change request form from the main menu or dashboard | Schedule change request form is displayed with all mandatory fields visible including: date range, change type, reason, and file upload option |
| 3 | Employee enters valid start date in the 'From Date' field using the date picker or manual entry | Date is accepted and displayed in the correct format (MM/DD/YYYY or system default format) |
| 4 | Employee enters valid end date in the 'To Date' field that is equal to or after the start date | Date is accepted and displayed in the correct format without validation errors |
| 5 | Employee selects a change type from the dropdown menu (e.g., Shift Change, Time Off, Schedule Swap) | Selected change type is displayed in the dropdown field |
| 6 | Employee enters a detailed reason for the schedule change in the text area field (minimum 10 characters) | Text is accepted and displayed in the reason field without character limit errors |
| 7 | Employee clicks on the 'Upload Document' button and selects a valid supporting document (PDF, 3MB) | File upload progress indicator appears, file is successfully uploaded, and file name is displayed with a success icon |
| 8 | Employee reviews all entered information for accuracy | All fields display the entered data correctly with no validation error messages visible |
| 9 | Employee clicks the 'Submit' button to submit the schedule change request | System processes the submission, displays a loading indicator, and then shows a success confirmation message with a unique request reference number (e.g., REQ-2024-001234) |
| 10 | Verify the confirmation message contains all required information | Confirmation message displays: success status, request reference number, submission timestamp, and next steps information indicating approval workflow has been initiated |

**Postconditions:**
- Schedule change request is saved in the ScheduleChangeRequests table with status 'Pending Approval'
- Approval workflow is automatically triggered and assigned to appropriate approver
- Employee receives confirmation notification via system notification or email
- Request reference number is generated and associated with the submission
- Uploaded document is stored in the system and linked to the request
- Employee can view the submitted request in their request history

---

### Test Case: Verify rejection of submission with missing mandatory fields
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Employee has valid login credentials and is authenticated in the system
- Employee has active employment status in the system
- Schedule change request form is accessible and functional
- Client-side and server-side validation rules are active
- All mandatory fields are properly configured in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Employee logs into the scheduling system using valid credentials | Employee is successfully authenticated and redirected to the dashboard |
| 2 | Employee navigates to the schedule change request form from the main menu | Schedule change request form is displayed with all mandatory fields marked with asterisks (*) or 'Required' labels |
| 3 | Employee leaves the 'From Date' field empty and attempts to move to the next field | Real-time validation triggers and displays an inline error message 'From Date is required' in red text below or next to the field |
| 4 | Employee enters a valid 'From Date' but leaves the 'To Date' field empty | Inline error message 'To Date is required' appears below the To Date field when focus moves away |
| 5 | Employee enters both dates but leaves the 'Change Type' dropdown unselected | Change Type field is highlighted with an error indicator and message 'Please select a change type' appears |
| 6 | Employee selects a change type but leaves the 'Reason' text area empty | Reason field displays validation error 'Reason is required' when focus moves away from the field |
| 7 | Employee attempts to click the 'Submit' button with one or more mandatory fields still empty | Submit button is either disabled (grayed out) or submission is blocked with a summary error message at the top of the form stating 'Please complete all required fields before submitting' |
| 8 | Verify all empty mandatory fields are highlighted simultaneously | All incomplete mandatory fields are highlighted with red borders or error indicators, and inline error messages are displayed for each missing field |
| 9 | Employee fills in all mandatory fields except the 'Reason' field with only 5 characters (below minimum requirement) | Validation error appears stating 'Reason must be at least 10 characters' and submission remains blocked |
| 10 | Employee attempts to bypass client-side validation by directly calling the API endpoint without required fields | Server-side validation rejects the request and returns a 400 Bad Request error with detailed validation error messages |

**Postconditions:**
- No schedule change request is created in the ScheduleChangeRequests table
- No approval workflow is initiated
- Form remains on the screen with all entered data preserved
- All validation error messages remain visible to guide the employee
- No confirmation message or reference number is generated
- Employee can correct the errors and resubmit without losing entered data

---

### Test Case: Test file upload validation for invalid file types and sizes
- **ID:** tc-003
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Employee has valid login credentials and is authenticated in the system
- Employee has active employment status in the system
- Schedule change request form is accessible with file upload functionality enabled
- File upload validation rules are configured: maximum size 5MB, allowed types PDF, DOC, DOCX
- Test files are prepared: one file exceeding 5MB (e.g., 6MB PDF), one unsupported file type (e.g., .exe or .zip), and one valid file (e.g., 3MB PDF)

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Employee logs into the scheduling system and navigates to the schedule change request form | Schedule change request form is displayed with the file upload section visible |
| 2 | Employee clicks on the 'Upload Document' button and selects a file that exceeds the 5MB size limit (e.g., 6MB PDF file) | System immediately displays a validation error message 'File size exceeds the maximum limit of 5MB. Please upload a smaller file.' and the file is not uploaded |
| 3 | Verify that no file name appears in the upload field after the size validation error | Upload field remains empty with no file name displayed, and the error message persists until a valid file is selected |
| 4 | Employee dismisses the error and clicks 'Upload Document' again, this time selecting an unsupported file type (e.g., .exe, .zip, or .jpg file) | System displays validation error message 'Invalid file type. Only PDF, DOC, and DOCX files are allowed.' and prevents the upload |
| 5 | Verify the upload field status after file type validation error | No file is attached, upload field shows empty state or placeholder text, and error message is clearly visible |
| 6 | Employee attempts to submit the form without any file uploaded (assuming file upload is optional) | If file upload is optional: form submission proceeds without errors. If mandatory: validation error 'Supporting document is required' is displayed |
| 7 | Employee clicks 'Upload Document' and selects a valid file within size and type limits (e.g., 3MB PDF file) | File upload progress indicator appears, file is successfully uploaded, file name is displayed with file size, and a success icon or checkmark appears next to the file name |
| 8 | Verify the uploaded file details are correctly displayed | File name, file size (e.g., 3.0 MB), and file type icon are displayed in the upload section with an option to remove or replace the file |
| 9 | Employee fills in all other mandatory fields with valid data (From Date, To Date, Change Type, Reason) | All fields accept the data without validation errors and display the entered information correctly |
| 10 | Employee clicks the 'Submit' button to submit the form with the valid uploaded file | Form is successfully submitted, system displays confirmation message with request reference number, and the uploaded file is associated with the request |
| 11 | Verify the file upload at exactly 5MB boundary (edge case) | File of exactly 5.0MB is accepted and uploaded successfully without validation errors |
| 12 | Test file upload with 5.1MB file (just over the limit) | System rejects the file with error message 'File size exceeds the maximum limit of 5MB' |

**Postconditions:**
- Only valid files (correct type and size) are successfully uploaded and stored in the system
- Invalid file upload attempts are logged for security monitoring
- Schedule change request with valid file is saved in ScheduleChangeRequests table
- Uploaded valid file is stored in the file storage system and linked to the request record
- Approval workflow is initiated only when valid file and all required data are submitted
- Confirmation message with request reference number is displayed only after successful submission
- Employee can view the uploaded document in their submitted request details

---

