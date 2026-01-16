# Manual Test Cases

## Story: As Exposure Data Specialist, I want to input property exposure details to achieve comprehensive exposure capture
**Story ID:** story-3

### Test Case: Validate successful property exposure data submission
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is authenticated and authorized as Exposure Data Specialist
- Property exposure data entry form is accessible
- Valid supporting documents are prepared (PDF, JPG, PNG format, under size limit)
- Database connection is active and PropertyExposure table is available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to property exposure data entry form | Form is displayed with all mandatory fields including property type, location, value, usage, and document attachment section clearly visible |
| 2 | Enter valid property type (e.g., Commercial Building) | Property type is accepted and no validation error is displayed |
| 3 | Enter valid location details (e.g., 123 Main Street, New York, NY 10001) | Location details are accepted and no validation error is displayed |
| 4 | Enter valid property value (e.g., 1500000) | Property value is accepted, formatted correctly, and no validation error is displayed |
| 5 | Enter valid property usage (e.g., Office Space) | Property usage is accepted and no validation error is displayed |
| 6 | Click on document attachment button and select valid supporting documents (PDF file, 2MB) | Document is uploaded successfully and file name is displayed in the attachment section |
| 7 | Review all entered data for accuracy | All entered data is displayed correctly in the form fields |
| 8 | Click the Submit button | Form is submitted successfully, confirmation message is displayed, and response time is under 2 seconds |
| 9 | Verify the confirmation message details | Confirmation message displays submission success with reference number or timestamp |

**Postconditions:**
- Property exposure data is saved in PropertyExposure table
- Supporting documents are stored securely
- User receives confirmation of successful submission
- Data is available for review and further processing

---

### Test Case: Verify rejection of submission with invalid exposure data
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is authenticated and authorized as Exposure Data Specialist
- Property exposure data entry form is accessible
- Validation rules are configured for mandatory fields and numeric ranges

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to property exposure data entry form | Form is displayed with all mandatory fields marked appropriately |
| 2 | Leave property type field empty | Field remains empty without immediate error (validation on blur or submit) |
| 3 | Enter invalid numeric value in property value field (e.g., -50000 or alphabetic characters) | Inline validation error is displayed indicating invalid numeric value or out of range |
| 4 | Leave location field empty | Field remains empty without immediate error |
| 5 | Enter property value exceeding maximum allowed range (e.g., 999999999999) | Inline validation error is displayed indicating value exceeds maximum limit |
| 6 | Click the Submit button | Submission is blocked and form remains on the same page |
| 7 | Verify error messages displayed on the form | Clear error messages are shown for each invalid or empty mandatory field, including property type, location, and property value |
| 8 | Verify that no data is saved to the database | No new record is created in PropertyExposure table |

**Postconditions:**
- Form remains in edit mode with validation errors displayed
- No data is saved to the database
- User can correct errors and resubmit
- System maintains data integrity

---

### Test Case: Test document attachment restrictions
- **ID:** tc-003
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is authenticated and authorized as Exposure Data Specialist
- Property exposure data entry form is accessible
- Test files are prepared: oversized file (>10MB), unsupported format (.exe, .zip), and valid files (PDF, JPG, PNG under size limit)
- File type and size restrictions are configured in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to property exposure data entry form | Form is displayed with document attachment section visible |
| 2 | Click on document attachment button and select a file exceeding size limit (e.g., 15MB PDF) | System rejects the file and displays error message indicating file size exceeds maximum allowed limit |
| 3 | Verify the file is not added to the attachment list | File is not displayed in the attachment section and no upload progress is shown |
| 4 | Click on document attachment button and select an unsupported file format (e.g., .exe file) | System rejects the file and displays error message indicating unsupported file format |
| 5 | Verify the unsupported file is not added to the attachment list | File is not displayed in the attachment section |
| 6 | Click on document attachment button and select a valid file (e.g., 2MB PDF) | File is accepted and upload progress is displayed |
| 7 | Verify the valid file appears in the attachment list | File name and size are displayed in the attachment section with option to remove |
| 8 | Fill in all mandatory property exposure fields with valid data | All fields are populated without validation errors |
| 9 | Click the Submit button | Form is submitted successfully with confirmation message displayed |
| 10 | Verify the valid file is saved with the property exposure data | Confirmation indicates both data and attachment were saved successfully |

**Postconditions:**
- Only valid files within size and format restrictions are saved
- Invalid files are rejected with appropriate error messages
- Property exposure data with valid attachments is stored in the database
- System maintains file upload security and integrity

---

## Story: As Exposure Data Specialist, I want to review and update exposure information to achieve data completeness and accuracy
**Story ID:** story-6

### Test Case: Validate successful exposure data update
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is authenticated and authorized as Exposure Data Specialist
- Existing exposure data record is available in ExposureInformation table
- Exposure data edit form is accessible
- User has permission to update exposure data

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to exposure data review page | Exposure data review page is displayed with list of existing exposure records |
| 2 | Select an existing exposure record to edit | Exposure data edit form is displayed with all existing data pre-populated in the respective fields |
| 3 | Verify all existing data is correctly displayed in the form | All fields show current values including property type, location, value, and usage |
| 4 | Modify property value field with valid updated value (e.g., change from 1500000 to 1750000) | Updated value is accepted and no validation error is displayed |
| 5 | Modify property usage field with valid updated information (e.g., change from Office Space to Mixed Use) | Updated usage is accepted and no validation error is displayed |
| 6 | Review all modified fields for accuracy | All updated data is displayed correctly in the form fields |
| 7 | Click the Save or Update button | Form is submitted successfully and response time is under 2 seconds |
| 8 | Verify confirmation message is displayed | Success confirmation message is displayed indicating exposure data has been updated successfully |
| 9 | Navigate back to exposure data review page and locate the updated record | Updated record is displayed with the new values for property value and usage |

**Postconditions:**
- Exposure data is updated in ExposureInformation table
- Audit log entry is created with update details
- Updated data is available for review and further processing
- User receives confirmation of successful update

---

### Test Case: Verify rejection of update with invalid exposure data
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is authenticated and authorized as Exposure Data Specialist
- Existing exposure data record is available in ExposureInformation table
- Exposure data edit form is accessible
- Validation rules are configured for mandatory fields and numeric ranges

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to exposure data review page | Exposure data review page is displayed with list of existing exposure records |
| 2 | Select an existing exposure record to edit | Exposure data edit form is displayed with all existing data pre-populated |
| 3 | Clear the mandatory property type field | Field becomes empty and may show inline validation error on blur |
| 4 | Enter invalid numeric value in property value field (e.g., -100000 or text characters) | Inline validation error is displayed indicating invalid numeric value |
| 5 | Clear the mandatory location field | Field becomes empty and may show inline validation error on blur |
| 6 | Click the Save or Update button | Save operation is blocked and form remains in edit mode |
| 7 | Verify error messages are displayed for all invalid fields | Clear error messages are shown for property type (required), property value (invalid), and location (required) |
| 8 | Verify no changes are saved to the database | Original data remains unchanged in ExposureInformation table |
| 9 | Navigate back to exposure data review page and verify the record | Record displays original values without any updates |

**Postconditions:**
- Form remains in edit mode with validation errors displayed
- No data is updated in the database
- Original exposure data remains intact
- User can correct errors and attempt to save again

---

### Test Case: Check audit log creation after successful exposure update
- **ID:** tc-006
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 8 mins

**Preconditions:**
- User is authenticated and authorized as Exposure Data Specialist
- Existing exposure data record is available in ExposureInformation table
- Audit logging is enabled and functional
- User has permission to view audit logs

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to exposure data review page | Exposure data review page is displayed with list of existing exposure records |
| 2 | Select an existing exposure record to edit and note the current values | Exposure data edit form is displayed with existing data pre-populated |
| 3 | Modify property value field with valid updated value (e.g., change from 1500000 to 1800000) | Updated value is accepted without validation errors |
| 4 | Modify property usage field with valid updated information | Updated usage is accepted without validation errors |
| 5 | Click the Save or Update button | Update is processed successfully and confirmation message is displayed |
| 6 | Note the timestamp and confirmation details of the update | Confirmation message includes timestamp or reference number for the update |
| 7 | Navigate to audit logs section or access audit logs for the updated exposure record | Audit logs interface is displayed with search or filter options |
| 8 | Search for audit log entries related to the updated exposure record using record ID or timestamp | Audit log entry for the update is displayed in the results |
| 9 | Verify audit log entry contains update details | Audit log shows user ID, timestamp, record ID, fields modified (property value, property usage), old values, and new values |
| 10 | Verify the audit log timestamp matches the update confirmation timestamp | Timestamps are consistent and accurately reflect when the update occurred |

**Postconditions:**
- Exposure data is successfully updated in ExposureInformation table
- Complete audit log entry exists with all change details
- Audit trail is maintained for compliance and tracking
- Audit log is accessible for future reference and reporting

---

## Story: As Exposure Data Specialist, I want to validate exposure data inputs to achieve data accuracy and compliance
**Story ID:** story-9

### Test Case: Validate acceptance of correct exposure data inputs
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as Exposure Data Specialist
- User has access to exposure data entry form
- ExposureInformation tables are accessible
- API endpoint POST /api/applicants/exposures is available
- User has valid applicant record to attach exposure data

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the exposure data entry form | Exposure data entry form is displayed with all mandatory fields visible |
| 2 | Enter valid exposure type from the dropdown list | Exposure type is selected and no validation error is displayed |
| 3 | Enter valid numeric value in the exposure amount field (e.g., 50000) | Numeric value is accepted and no validation error is displayed |
| 4 | Enter valid date in the exposure date field | Date is accepted in correct format and no validation error is displayed |
| 5 | Fill in all remaining mandatory exposure fields with valid data | All fields accept valid data and no validation errors are displayed anywhere on the form |
| 6 | Click the Submit button | Form submission is processed successfully with confirmation message displayed |
| 7 | Verify the exposure data is saved in the system | Data is saved successfully and can be retrieved from ExposureInformation tables |

**Postconditions:**
- Exposure data is stored in ExposureInformation tables
- Success confirmation message is displayed to user
- Form is cleared or redirected to confirmation page
- Audit log records the data entry action

---

### Test Case: Verify rejection of invalid exposure data inputs
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in as Exposure Data Specialist
- User has access to exposure data entry form
- Validation rules are configured for mandatory fields and numeric ranges
- API endpoint POST /api/applicants/exposures is available
- Real-time validation is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the exposure data entry form | Exposure data entry form is displayed with all fields empty |
| 2 | Leave the mandatory exposure type field empty and move to next field | Inline validation error message is displayed indicating exposure type is required |
| 3 | Enter alphabetic characters (e.g., 'ABC') in the numeric exposure amount field | Inline validation error message is displayed indicating numeric value is required |
| 4 | Enter a numeric value outside the acceptable range (e.g., -1000 or exceeding maximum limit) | Inline validation error message is displayed indicating value must be within acceptable range |
| 5 | Leave other mandatory fields empty | Inline validation error messages are displayed for each empty mandatory field |
| 6 | Attempt to click the Submit button with validation errors present | Form submission is blocked and error summary message is displayed indicating all errors must be corrected |
| 7 | Correct all validation errors by entering valid data in all fields | All inline error messages disappear and Submit button becomes enabled |
| 8 | Click the Submit button after correcting all errors | Form is submitted successfully and confirmation message is displayed |

**Postconditions:**
- Invalid data is not saved to ExposureInformation tables
- User is informed of all validation errors
- Form remains on screen with user-entered data until errors are corrected
- After correction, valid data is saved successfully

---

### Test Case: Test validation for multiple exposure types
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in as Exposure Data Specialist
- User has access to exposure data entry form
- Multiple exposure types are configured in the system (e.g., Property, Liability, Auto, Workers Compensation)
- Validation rules are defined for each exposure type
- API endpoint POST /api/applicants/exposures is available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the exposure data entry form | Exposure data entry form is displayed with exposure type dropdown available |
| 2 | Select 'Property' exposure type from the dropdown | Property exposure type is selected and relevant fields for property exposure are displayed |
| 3 | Enter valid data for all mandatory property exposure fields | All property exposure fields accept valid data with no validation errors displayed |
| 4 | Click Submit button | Property exposure data is saved successfully with confirmation message |
| 5 | Navigate back to exposure data entry form and select 'Liability' exposure type | Liability exposure type is selected and relevant fields for liability exposure are displayed |
| 6 | Enter valid data for all mandatory liability exposure fields | All liability exposure fields accept valid data with no validation errors displayed |
| 7 | Click Submit button | Liability exposure data is saved successfully with confirmation message |
| 8 | Navigate back to exposure data entry form and select 'Auto' exposure type | Auto exposure type is selected and relevant fields for auto exposure are displayed |
| 9 | Enter valid data for all mandatory auto exposure fields | All auto exposure fields accept valid data with no validation errors displayed |
| 10 | Click Submit button | Auto exposure data is saved successfully with confirmation message |
| 11 | Verify all submitted exposure records are stored in the system | All three exposure types (Property, Liability, Auto) are successfully saved and retrievable from ExposureInformation tables |

**Postconditions:**
- Multiple exposure type records are stored in ExposureInformation tables
- Each exposure type maintains its specific validation rules
- All submitted data passes validation for respective exposure types
- Success confirmation is displayed for each submission
- Audit log records all exposure data entries

---

