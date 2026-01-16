# Manual Test Cases

## Story: As Applicant Data Entry Specialist, I want to input applicant personal details to achieve accurate demographic data capture
**Story ID:** story-1

### Test Case: Validate successful demographic data submission with valid input
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is authenticated with valid OAuth2 credentials
- User has Data Entry Specialist role permissions
- Demographic data entry form is accessible
- ApplicantDemographics table is available and operational
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to demographic data entry form | Form is displayed with all mandatory fields including name, date of birth, gender, and contact information clearly labeled with asterisks or 'required' indicators |
| 2 | Enter valid first name (e.g., 'John') in the First Name field | First Name field accepts the input without validation errors |
| 3 | Enter valid last name (e.g., 'Smith') in the Last Name field | Last Name field accepts the input without validation errors |
| 4 | Enter valid date of birth (e.g., '01/15/1985') in the Date of Birth field | Date of Birth field accepts the input in correct format without validation errors |
| 5 | Select gender (e.g., 'Male') from the Gender dropdown | Gender selection is accepted and displayed in the field |
| 6 | Enter valid email address (e.g., 'john.smith@email.com') in the Email field | Email field accepts the input and validates format in real-time without errors |
| 7 | Enter valid phone number (e.g., '555-123-4567') in the Phone Number field | Phone Number field accepts the input without validation errors |
| 8 | Click the Submit button | Form submission is processed, data is saved successfully to ApplicantDemographics table, and confirmation message 'Demographic data saved successfully' is displayed within 2 seconds |

**Postconditions:**
- Demographic data is stored in ApplicantDemographics table
- Data is encrypted during transmission and at rest
- User receives confirmation of successful submission
- Form is cleared or redirected to confirmation page
- New applicant record is created with unique identifier

---

### Test Case: Verify rejection of submission with missing mandatory fields
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is authenticated with valid OAuth2 credentials
- User has Data Entry Specialist role permissions
- Demographic data entry form is accessible
- Real-time validation is enabled on the form

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to demographic data entry form | Form is displayed with all mandatory fields clearly marked as required |
| 2 | Enter valid first name (e.g., 'Jane') in the First Name field | First Name field accepts the input without validation errors |
| 3 | Leave the Last Name field empty | Real-time validation highlights the Last Name field with red border or error indicator |
| 4 | Enter valid date of birth (e.g., '03/20/1990') in the Date of Birth field | Date of Birth field accepts the input without validation errors |
| 5 | Leave the Gender field unselected | Real-time validation highlights the Gender field as missing |
| 6 | Leave the Email field empty | Real-time validation highlights the Email field with error indicator |
| 7 | Enter valid phone number (e.g., '555-987-6543') in the Phone Number field | Phone Number field accepts the input without validation errors |
| 8 | Click the Submit button | Submission is blocked and inline error messages are displayed next to each missing mandatory field (Last Name, Gender, Email) stating 'This field is required' or similar message |
| 9 | Verify that focus is set to the first invalid field | Cursor is positioned at the first missing mandatory field to guide user correction |

**Postconditions:**
- No data is saved to ApplicantDemographics table
- Form remains on the same page with entered data preserved
- Error messages are clearly visible to the user
- Submit button remains enabled for retry after corrections

---

### Test Case: Test saving draft with incomplete demographic data
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 4 mins

**Preconditions:**
- User is authenticated with valid OAuth2 credentials
- User has Data Entry Specialist role permissions
- Demographic data entry form is accessible
- Draft save functionality is enabled
- ApplicantDemographics table supports draft status

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to demographic data entry form | Form is displayed with all fields available for input and 'Save as Draft' button is visible |
| 2 | Enter valid first name (e.g., 'Michael') in the First Name field | First Name field accepts the input without validation errors |
| 3 | Enter valid last name (e.g., 'Johnson') in the Last Name field | Last Name field accepts the input without validation errors |
| 4 | Leave the Date of Birth field empty | Date of Birth field remains empty without triggering blocking validation errors |
| 5 | Leave the Gender field unselected | Gender field remains unselected without triggering blocking validation errors |
| 6 | Enter partial email address (e.g., 'michael.johnson') in the Email field | Email field accepts the partial data without blocking the draft save operation |
| 7 | Click the 'Save as Draft' button | Draft is saved successfully to ApplicantDemographics table with draft status, and notification message 'Draft saved' or 'Draft saved successfully' is displayed within 2 seconds |
| 8 | Verify the draft record is retrievable | Draft record can be accessed for future editing with all partial data preserved |

**Postconditions:**
- Partial demographic data is stored in ApplicantDemographics table with draft status
- Data is encrypted during transmission and at rest
- User receives confirmation notification of draft save
- Draft can be retrieved and edited later
- No validation errors prevent draft save operation

---

## Story: As Applicant Data Entry Specialist, I want to edit and update applicant demographics to achieve data accuracy
**Story ID:** story-4

### Test Case: Validate successful demographic data update
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is authenticated with valid OAuth2 credentials
- User has Data Entry Specialist role permissions with edit authorization
- At least one applicant demographic record exists in ApplicantDemographics table
- Demographic data edit form is accessible
- Network connectivity is stable
- Audit logging system is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to demographic data edit form for an existing applicant record | Form is displayed with all existing demographic data pre-populated in respective fields including name, date of birth, gender, email, and phone number |
| 2 | Verify that all existing data is correctly displayed in the form fields | All previously saved demographic information is accurately displayed and editable |
| 3 | Modify the Last Name field to a new valid value (e.g., change 'Smith' to 'Johnson') | Last Name field accepts the modified input without validation errors and displays the new value |
| 4 | Modify the Email field to a new valid email address (e.g., change to 'updated.email@example.com') | Email field accepts the modified input, validates format in real-time, and displays no validation errors |
| 5 | Modify the Phone Number field to a new valid phone number (e.g., '555-111-2222') | Phone Number field accepts the modified input without validation errors |
| 6 | Leave other fields (First Name, Date of Birth, Gender) unchanged | Unchanged fields retain their original values without modification |
| 7 | Click the Submit or Save button to save the updated data | Data is updated successfully in ApplicantDemographics table via PUT /api/applicants/demographics/{id} endpoint within 2 seconds, and confirmation message 'Demographic data updated successfully' is displayed |
| 8 | Verify the updated data is reflected in the system | Updated demographic information is saved and retrievable with all modifications preserved |

**Postconditions:**
- Demographic data is updated in ApplicantDemographics table
- Updated data is encrypted during transmission and at rest
- Audit log entry is created with timestamp, user ID, and changed fields
- User receives confirmation of successful update
- Previous data version is maintained in audit trail

---

### Test Case: Verify rejection of update with invalid data
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is authenticated with valid OAuth2 credentials
- User has Data Entry Specialist role permissions with edit authorization
- At least one applicant demographic record exists in ApplicantDemographics table
- Demographic data edit form is accessible
- Real-time validation is enabled on the form

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to demographic data edit form for an existing applicant record | Form is displayed with all existing demographic data pre-populated in respective fields |
| 2 | Clear the Last Name field to make it empty | Real-time validation highlights the Last Name field with red border or error indicator and displays inline error message 'This field is required' |
| 3 | Modify the Email field to an invalid format (e.g., 'invalidemail.com') | Real-time validation highlights the Email field with error indicator and displays inline error message 'Please enter a valid email address' |
| 4 | Modify the Date of Birth field to an invalid format (e.g., '99/99/9999') | Real-time validation highlights the Date of Birth field with error indicator and displays inline error message 'Please enter a valid date' |
| 5 | Leave other mandatory fields with valid data | Valid fields display no validation errors |
| 6 | Attempt to click the Submit or Save button | Save operation is blocked and prevented from executing |
| 7 | Verify error messages are displayed for all invalid fields | Inline error messages are shown next to each invalid or empty mandatory field (Last Name, Email, Date of Birth) with clear descriptions of the validation failures |
| 8 | Verify that focus is set to the first invalid field | Cursor is positioned at the first invalid field to guide user correction |

**Postconditions:**
- No data is updated in ApplicantDemographics table
- Original demographic data remains unchanged
- Form remains on the same page with entered data preserved
- Error messages are clearly visible to the user
- No audit log entry is created for failed update attempt
- Save button remains enabled for retry after corrections

---

### Test Case: Check audit log creation after successful update
- **ID:** tc-006
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 6 mins

**Preconditions:**
- User is authenticated with valid OAuth2 credentials
- User has Data Entry Specialist role permissions with edit authorization
- At least one applicant demographic record exists in ApplicantDemographics table
- Demographic data has been successfully updated in a previous step
- Audit logging system is operational and accessible
- User has permissions to access audit logs

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to demographic data edit form for an existing applicant record | Form is displayed with existing demographic data pre-populated |
| 2 | Modify one or more demographic fields with valid data (e.g., change Email from 'old@email.com' to 'new@email.com') | Modified fields accept the new valid data without validation errors |
| 3 | Click the Submit or Save button to update the demographic data | Data is updated successfully and confirmation message 'Demographic data updated successfully' is displayed |
| 4 | Note the timestamp and applicant ID of the update | Update timestamp and applicant identifier are available for audit log verification |
| 5 | Navigate to the audit logs section or access audit logs for the updated applicant record | Audit logs interface is displayed and accessible |
| 6 | Search or filter audit logs by applicant ID and recent timestamp | Audit log entries for the specific applicant are displayed |
| 7 | Verify that an audit log entry exists for the recent update | Audit log entry is present with correct timestamp matching the update time |
| 8 | Verify audit log contains details of changes including field names, old values, and new values | Audit log entry displays complete details: user ID who made the change, timestamp, changed field names (e.g., 'Email'), old value (e.g., 'old@email.com'), new value (e.g., 'new@email.com'), and action type (e.g., 'UPDATE') |
| 9 | Verify audit log entry is immutable and cannot be edited | Audit log entry is read-only and maintains data integrity |

**Postconditions:**
- Audit log entry is permanently stored in audit logging system
- Audit trail maintains 100% of demographic data changes
- Audit log is available for compliance and reporting purposes
- Audit log entry includes all required metadata (user, timestamp, changes)
- Data integrity of audit logs is maintained

---

## Story: As Applicant Data Entry Specialist, I want to validate demographic data formats to achieve data integrity
**Story ID:** story-7

### Test Case: Validate acceptance of correct email formats
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as Applicant Data Entry Specialist
- Demographic data entry form is accessible
- ApplicantDemographics table is available
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the demographic data entry form | Demographic form loads successfully with all required fields visible |
| 2 | Enter a valid email address in standard format (e.g., user@example.com) in the email field | Email is accepted without any validation errors, no error messages displayed |
| 3 | Enter another valid email with subdomain (e.g., user.name@mail.example.com) | Email is accepted without any validation errors, no error messages displayed |
| 4 | Enter a valid email with numbers (e.g., user123@example.org) | Email is accepted without any validation errors, no error messages displayed |
| 5 | Complete all other required demographic fields with valid data | All fields accept valid data without errors |
| 6 | Click the 'Submit' button | Form is submitted successfully, confirmation message is displayed, and data is saved to ApplicantDemographics table |

**Postconditions:**
- Demographic data is stored in ApplicantDemographics table
- User receives success confirmation
- Form is cleared or redirected to confirmation page
- No validation errors remain on the form

---

### Test Case: Verify rejection of invalid email formats
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as Applicant Data Entry Specialist
- Demographic data entry form is accessible
- Real-time validation is enabled
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the demographic data entry form | Demographic form loads successfully with all required fields visible |
| 2 | Enter an email address missing the '@' symbol (e.g., userexample.com) in the email field | Inline error message is displayed indicating invalid email format (e.g., 'Please enter a valid email address with @') |
| 3 | Clear the email field and enter an email with invalid domain (e.g., user@domain) | Inline error message is displayed indicating invalid email domain format |
| 4 | Clear the email field and enter an email with special characters (e.g., user@@example.com) | Inline error message is displayed indicating invalid email format |
| 5 | Clear the email field and enter an email without domain extension (e.g., user@example) | Inline error message is displayed indicating invalid email format |
| 6 | Complete all other required demographic fields with valid data | All other fields accept valid data without errors |
| 7 | Attempt to click the 'Submit' button while email error is still present | Form submission is blocked, error message persists, and user is prompted to correct the email field before submission |
| 8 | Correct the email field with a valid email address (e.g., user@example.com) | Error message disappears and email field shows valid state |
| 9 | Click the 'Submit' button | Form is submitted successfully after all errors are corrected |

**Postconditions:**
- Invalid email formats are rejected and not stored
- User is informed of specific validation errors
- Form submission only succeeds after corrections
- Valid data is stored in ApplicantDemographics table after correction

---

### Test Case: Validate phone number format validation
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in as Applicant Data Entry Specialist
- Demographic data entry form is accessible
- Phone number validation supports international formats
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the demographic data entry form | Demographic form loads successfully with phone number field visible |
| 2 | Enter a valid phone number with country code (e.g., +1-555-123-4567) in the phone field | Phone number is accepted without validation errors, no error messages displayed |
| 3 | Clear the phone field and enter a valid phone number without country code (e.g., 555-123-4567) | Phone number is accepted without validation errors, no error messages displayed |
| 4 | Clear the phone field and enter an international phone number (e.g., +44-20-7123-4567) | Phone number is accepted without validation errors, no error messages displayed |
| 5 | Clear the phone field and enter an invalid phone number with letters (e.g., 555-ABC-1234) | Inline error message is displayed indicating invalid phone number format |
| 6 | Clear the phone field and enter an invalid phone number with insufficient digits (e.g., 123-45) | Inline error message is displayed indicating invalid phone number format |
| 7 | Correct the phone field with a valid phone number (e.g., +1-555-987-6543) | Error message disappears and phone field shows valid state |
| 8 | Complete all other required demographic fields with valid data | All fields accept valid data without errors |
| 9 | Click the 'Submit' button | Form submission succeeds only with valid phone number, confirmation message is displayed, and data is saved to ApplicantDemographics table |

**Postconditions:**
- Valid phone numbers with and without country codes are accepted and stored
- Invalid phone number formats are rejected
- Demographic data with valid phone number is stored in ApplicantDemographics table
- User receives success confirmation after valid submission

---

## Story: As Applicant Data Entry Specialist, I want to save demographic data drafts to achieve flexible data entry
**Story ID:** story-10

### Test Case: Validate saving of demographic data draft
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as Applicant Data Entry Specialist with valid authentication
- Demographic data entry form is accessible
- ApplicantDemographicsDrafts table is available
- Network connectivity is stable
- User has permissions to save drafts

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the demographic data entry form | Demographic form loads successfully with all fields visible and 'Save Draft' button is present |
| 2 | Enter partial demographic data including first name and email address only | Data is entered successfully in the respective fields without validation errors for incomplete form |
| 3 | Leave other required fields (e.g., last name, phone number, date of birth) empty | Fields remain empty without triggering validation errors since this is a draft save |
| 4 | Click the 'Save Draft' button | Draft save request is initiated and processing indicator is displayed |
| 5 | Wait for the save operation to complete | Draft is saved successfully within 2 seconds, confirmation message is displayed (e.g., 'Draft saved successfully'), and draft ID is generated |
| 6 | Verify the confirmation notification details | Confirmation message includes timestamp and draft status indicator |

**Postconditions:**
- Partial demographic data is stored in ApplicantDemographicsDrafts table
- Draft is associated with the authenticated user's account
- User receives confirmation of successful draft save
- Draft can be retrieved for future editing
- Save operation completed within 2 seconds

---

### Test Case: Verify retrieval and editing of saved draft
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in as Applicant Data Entry Specialist with valid authentication
- A demographic data draft has been previously saved for this user
- ApplicantDemographicsDrafts table contains the saved draft
- Network connectivity is stable
- User has permissions to access and edit drafts

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the drafts list or demographic data entry section | Drafts list is displayed showing previously saved demographic drafts with timestamps |
| 2 | Select and click on the saved demographic draft to access it | Draft is retrieved from ApplicantDemographicsDrafts table and loaded into the demographic form |
| 3 | Verify that all previously entered data is accurately displayed in the form fields | All partial data (first name, email) is correctly populated in the respective fields exactly as saved |
| 4 | Add additional demographic information to the draft (e.g., enter last name and phone number) | New data is entered successfully in the additional fields without errors |
| 5 | Modify existing draft data (e.g., update the email address) | Existing data is updated successfully in the form field |
| 6 | Click the 'Save Draft' button again to save the updated draft | Updated draft is saved successfully within 2 seconds, confirmation message is displayed (e.g., 'Draft updated successfully') |
| 7 | Navigate away from the form and then retrieve the draft again | Draft is retrieved with all updated changes intact, including both original and newly added data |

**Postconditions:**
- Updated draft data is stored in ApplicantDemographicsDrafts table
- All modifications are persisted accurately
- Draft remains accessible for future editing
- User receives confirmation of successful update
- No data loss occurs during the edit and save process

---

### Test Case: Test draft access restriction to authenticated users
- **ID:** tc-006
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Demographic data drafts exist in ApplicantDemographicsDrafts table
- User is initially not authenticated or session has expired
- Authentication system is functioning properly
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Ensure user is logged out or session is not authenticated | User session is in unauthenticated state |
| 2 | Attempt to access the drafts list or a specific draft URL directly without authentication | Access is denied immediately, user is not able to view drafts list or draft data |
| 3 | Verify the error response or redirect behavior | Appropriate error message is displayed (e.g., 'Authentication required' or 'Access denied'), and user is redirected to login page |
| 4 | Attempt to access draft via API endpoint POST /api/applicants/demographics/drafts without authentication token | API returns 401 Unauthorized status code with appropriate error message |
| 5 | Log in with valid Applicant Data Entry Specialist credentials | User is successfully authenticated and session is established |
| 6 | Attempt to access the drafts list again after authentication | Access is granted, drafts list is displayed showing only drafts belonging to the authenticated user |
| 7 | Attempt to access a draft belonging to a different user by manipulating the draft ID | Access is denied with appropriate error message (e.g., 'Unauthorized access to this draft'), ensuring data privacy |

**Postconditions:**
- Unauthenticated users cannot access any draft data
- Authentication is enforced for all draft operations
- User privacy and data security are maintained
- Only authenticated users can view and edit their own drafts
- Appropriate error messages guide users to authenticate

---

