# Manual Test Cases

## Story: As Insurance Agent, I want to enter applicant personal details to achieve accurate identification of the applicant
**Story ID:** story-1

### Test Case: Validate successful applicant data entry with valid inputs
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as an authorized insurance agent
- User has active internet connection
- Applicant data entry page is accessible
- Database is available and responsive

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to applicant data entry page | Applicant form is displayed with all mandatory fields including name, date of birth, gender, and contact details. Form loads within 2 seconds |
| 2 | Enter valid first name (e.g., 'John') in the First Name field | First name is accepted without validation errors. Field displays entered text |
| 3 | Enter valid last name (e.g., 'Smith') in the Last Name field | Last name is accepted without validation errors. Field displays entered text |
| 4 | Enter valid date of birth (e.g., '01/15/1985') in the Date of Birth field | Date is auto-formatted correctly. No validation errors are shown. Age is calculated automatically if applicable |
| 5 | Select gender from the dropdown (e.g., 'Male') | Gender is selected and displayed in the field. No validation errors are shown |
| 6 | Enter valid phone number (e.g., '5551234567') in the Phone Number field | Phone number is auto-formatted to standard format (e.g., '(555) 123-4567'). No validation errors are shown |
| 7 | Verify all mandatory fields are completed and no validation errors are present | All fields show valid data. No error messages are displayed. Submit button is enabled |
| 8 | Click the Submit button | Form is submitted successfully. Applicant data is saved to the database. Confirmation message is displayed (e.g., 'Applicant data saved successfully'). Unique applicant ID is generated and displayed |

**Postconditions:**
- Applicant record is created in the database with unique ID
- All entered data is persisted and retrievable
- Agent can proceed to next step in the workflow
- Audit log entry is created for the data entry action

---

### Test Case: Verify rejection of form submission with missing mandatory fields
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in as an authorized insurance agent
- User has active internet connection
- Applicant data entry page is accessible
- Real-time validation is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to applicant data entry page | Applicant form is displayed with all mandatory fields clearly marked (e.g., with asterisk or 'Required' label) |
| 2 | Enter valid first name (e.g., 'Jane') in the First Name field | First name is accepted. Field shows valid state |
| 3 | Leave the Last Name field empty and move focus to the next field | Real-time validation triggers. Inline error message is displayed below or next to the Last Name field (e.g., 'Last Name is required'). Field is highlighted in red or error color |
| 4 | Enter valid date of birth (e.g., '03/20/1990') in the Date of Birth field | Date is accepted and auto-formatted. No validation errors for this field |
| 5 | Leave the Gender field unselected | Gender field remains empty. Error state may be indicated |
| 6 | Enter valid phone number (e.g., '5559876543') in the Phone Number field | Phone number is accepted and auto-formatted. No validation errors for this field |
| 7 | Attempt to click the Submit button | Form submission is blocked. Submit button may be disabled or clicking it triggers validation. Error summary message is displayed at the top of the form (e.g., 'Please correct the errors below before submitting') |
| 8 | Verify all missing mandatory fields are highlighted with error messages | Last Name field shows error message 'Last Name is required'. Gender field shows error message 'Gender is required'. All error fields are highlighted. Form focus moves to the first error field |
| 9 | Verify that no data is submitted to the database | No applicant record is created. No API call to POST /api/applicants is made or it returns validation error response |

**Postconditions:**
- No applicant record is created in the database
- Form remains on the same page with entered data preserved
- Error messages are clearly visible to the agent
- Agent can correct errors and resubmit

---

### Test Case: Ensure draft save and resume functionality works correctly
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as an authorized insurance agent
- User has active internet connection
- Applicant data entry page is accessible
- Draft save functionality is enabled
- Session management is configured correctly

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to applicant data entry page | Applicant form is displayed with all fields empty. 'Save as Draft' button is visible and enabled |
| 2 | Enter partial applicant data: First Name 'Robert', Last Name 'Johnson', Date of Birth '05/10/1988' | All entered fields accept the data without errors. Fields display the entered information |
| 3 | Leave Gender and Phone Number fields empty | Fields remain empty. No validation errors are shown for draft save |
| 4 | Click the 'Save as Draft' button | Draft is saved successfully. Confirmation message is displayed (e.g., 'Draft saved successfully'). Draft ID is generated and displayed or stored in session. No mandatory field validation is enforced for draft save |
| 5 | Note the draft ID or confirmation details, then close the browser or navigate away from the page | Page closes or navigates away. Draft data is persisted in the database or session storage |
| 6 | Reopen the browser and log in again as the same insurance agent | User is successfully logged in and authenticated |
| 7 | Navigate back to the applicant data entry page or access the saved draft from drafts list | Form is displayed with previously saved draft data loaded. First Name shows 'Robert', Last Name shows 'Johnson', Date of Birth shows '05/10/1988'. Gender and Phone Number fields remain empty as they were not filled |
| 8 | Complete the remaining mandatory fields: Select Gender as 'Male' and enter Phone Number '5551112222' | Gender is selected successfully. Phone number is entered and auto-formatted to '(555) 111-2222'. All mandatory fields are now complete. No validation errors are shown |
| 9 | Click the Submit button to finalize the applicant data | Form is submitted successfully. Draft status is changed to completed. Applicant data is saved permanently to the database. Confirmation message is displayed (e.g., 'Applicant data saved successfully'). Unique applicant ID is generated |
| 10 | Verify the applicant record is retrievable and complete | Applicant record can be retrieved using GET /api/applicants/{id}. All data fields are correctly saved and match the entered information |

**Postconditions:**
- Draft is converted to a completed applicant record
- All applicant data is persisted in the database
- Draft entry is removed from drafts list or marked as completed
- Agent can proceed with the insurance quote process
- Audit trail shows draft creation, save, and final submission

---

## Story: As Insurance Agent, I want to input applicant contact information to achieve reliable communication channels
**Story ID:** story-2

### Test Case: Validate acceptance of correctly formatted contact information
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as an authorized insurance agent
- User has active internet connection
- Contact information section is accessible
- Applicant record exists or is being created
- Database is available and responsive

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to contact information section of the applicant form | Contact form is displayed with fields for phone number, email address, and mailing address. All fields are empty and ready for input. Validation response time is under 1 second |
| 2 | Enter valid phone number '5551234567' in the Phone Number field | Phone number is accepted and auto-formatted to standard format '(555) 123-4567'. No validation errors are shown. Field displays green checkmark or valid state indicator |
| 3 | Enter valid email address 'john.smith@example.com' in the Email Address field | Email address is accepted. Real-time validation confirms correct format. No validation errors are shown. Field displays valid state indicator |
| 4 | Enter valid mailing address: Street '123 Main Street', City 'Springfield', State 'IL', ZIP '62701' | All address fields accept the data. No validation errors are shown. ZIP code may be auto-formatted if applicable |
| 5 | Verify all contact fields show valid data with no error messages | All fields display entered data correctly. No error messages are present. Save button is enabled |
| 6 | Click the Save button to save the contact information | Contact information is saved successfully to the database via POST /api/applicants/contact. Confirmation message is displayed (e.g., 'Contact information saved successfully'). Data is persisted and linked to the applicant record |

**Postconditions:**
- Contact information is saved in the applicant contact info tables
- Data is retrievable and correctly associated with the applicant
- Agent can proceed to next section or submit the complete application
- Audit log entry is created for the contact information save action

---

### Test Case: Verify rejection of invalid phone and email formats
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in as an authorized insurance agent
- User has active internet connection
- Contact information section is accessible
- Real-time validation with regex is enabled
- Validation response time is under 1 second

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to contact information section of the applicant form | Contact form is displayed with empty fields for phone number, email address, and mailing address |
| 2 | Enter invalid phone number '123' in the Phone Number field and move focus to next field | Real-time validation triggers within 1 second. Inline validation error message is displayed (e.g., 'Please enter a valid 10-digit phone number'). Field is highlighted in red or error color. Error icon is displayed next to the field |
| 3 | Enter invalid email address 'invalidemail@' in the Email Address field and move focus to next field | Real-time validation triggers within 1 second. Inline validation error message is displayed (e.g., 'Please enter a valid email address'). Field is highlighted in red or error color. Error icon is displayed next to the field |
| 4 | Enter valid mailing address: Street '456 Oak Avenue', City 'Chicago', State 'IL', ZIP '60601' | Address fields accept the data. No validation errors for address fields |
| 5 | Attempt to click the Save button | Save action is blocked. Button may be disabled or clicking triggers validation summary. Error summary message is displayed at the top (e.g., 'Please correct the errors below before saving'). Form does not submit |
| 6 | Verify that both phone and email fields display error messages | Phone Number field shows error: 'Please enter a valid 10-digit phone number'. Email Address field shows error: 'Please enter a valid email address'. Both fields remain highlighted in error state |
| 7 | Correct the phone number to valid format '5559876543' | Phone number is accepted and auto-formatted to '(555) 987-6543'. Error message for phone field disappears. Field changes to valid state with green indicator |
| 8 | Correct the email address to valid format 'jane.doe@example.com' | Email address is accepted. Error message for email field disappears. Field changes to valid state with green indicator |
| 9 | Verify all validation errors are cleared and Save button is enabled | No error messages are displayed. All fields show valid state. Save button is enabled and clickable |
| 10 | Click the Save button | Contact information is saved successfully. Confirmation message is displayed. Data is persisted to the database |

**Postconditions:**
- Contact information is saved only after all validation errors are corrected
- Invalid data is not persisted to the database
- Agent understands the correct format requirements
- Form maintains data integrity with proper validation

---

### Test Case: Ensure contact information persistence after form reload
- **ID:** tc-006
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as an authorized insurance agent
- User has active internet connection
- Contact information section is accessible
- Applicant record exists in the database
- Data persistence mechanism is functioning correctly

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to contact information section of the applicant form | Contact form is displayed with empty fields ready for input |
| 2 | Enter valid phone number '5552223333' in the Phone Number field | Phone number is accepted and auto-formatted to '(555) 222-3333'. No validation errors |
| 3 | Enter valid email address 'michael.brown@example.com' in the Email Address field | Email address is accepted. Real-time validation confirms correct format. No validation errors |
| 4 | Enter valid mailing address: Street '789 Elm Street', City 'Boston', State 'MA', ZIP '02101' | All address fields accept the data. No validation errors |
| 5 | Click the Save button to save the contact information | Contact information is saved successfully. Confirmation message is displayed (e.g., 'Contact information saved successfully'). Data is persisted to the database via POST /api/applicants/contact |
| 6 | Note the applicant ID or record identifier for reference | Applicant ID is visible and noted for retrieval |
| 7 | Refresh the browser page or navigate away and return to the contact information section | Page reloads successfully. Contact information form is displayed again |
| 8 | Verify that previously saved contact information is displayed in the form fields | Phone Number field displays '(555) 222-3333'. Email Address field displays 'michael.brown@example.com'. Mailing address fields display: Street '789 Elm Street', City 'Boston', State 'MA', ZIP '02101'. All data matches what was previously saved |
| 9 | Edit the phone number to '5554445555' and email to 'michael.brown.updated@example.com' | Phone number is updated and auto-formatted to '(555) 444-5555'. Email address is updated and validated. No validation errors are shown |
| 10 | Click the Save button to save the updated contact information | Updated contact information is saved successfully. Confirmation message is displayed (e.g., 'Contact information updated successfully'). Changes are persisted to the database |
| 11 | Reload the form page again to verify the updates persisted | Page reloads. Contact information form displays the updated data: Phone Number '(555) 444-5555', Email 'michael.brown.updated@example.com', and unchanged address. All updates are correctly reflected |

**Postconditions:**
- Contact information is persistently stored in the database
- Data retrieval works correctly across sessions
- Updates to contact information are saved and reflected accurately
- Data integrity is maintained through save and reload cycles
- Audit trail shows initial save and subsequent update actions

---

## Story: As Insurance Agent, I want to enter applicant history details to achieve comprehensive risk profiling
**Story ID:** story-3

### Test Case: Validate successful entry of multiple applicant history records
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as an Insurance Agent with valid credentials
- User has appropriate permissions to access applicant history section
- Applicant profile exists in the system
- Database connection is active and stable
- Browser is compatible and up to date

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the applicant history section from the main dashboard or applicant profile page | History entry form is displayed with all required fields visible including previous claims, coverage periods, and insurers fields |
| 2 | Enter first history record with valid data: Previous insurer name 'ABC Insurance', coverage period from '01/01/2020' to '12/31/2020', claim amount '$5,000', claim date '06/15/2020', and claim type 'Property Damage' | First history record is accepted without validation errors, all fields display entered data correctly |
| 3 | Click 'Add Another Record' button to add a second history entry | A new blank history entry form appears below the first record |
| 4 | Enter second history record with valid data: Previous insurer name 'XYZ Insurance', coverage period from '01/01/2021' to '12/31/2021', claim amount '$3,500', claim date '09/20/2021', and claim type 'Liability' | Second history record is accepted without validation errors, no error messages are shown, both records are visible on the form |
| 5 | Click 'Add Another Record' button to add a third history entry | A third blank history entry form appears below the second record |
| 6 | Enter third history record with valid data: Previous insurer name 'DEF Insurance', coverage period from '01/01/2022' to '12/31/2022', no claims filed | Third history record is accepted, optional claim fields can be left blank without errors |
| 7 | Review all three entered history records for accuracy and completeness | All three records are displayed correctly with all entered information visible and properly formatted |
| 8 | Click the 'Save' button to submit the history data | System processes the save request, loading indicator appears briefly, success confirmation message is displayed stating 'Applicant history saved successfully', page response time is under 2 seconds |
| 9 | Verify the saved data by refreshing the page or navigating away and returning to the applicant history section | All three history records are retrieved and displayed correctly with all previously entered data intact |

**Postconditions:**
- Three applicant history records are saved in the database
- Data is associated with the correct applicant profile
- Audit log records the data entry action with timestamp and user information
- History data is available for risk profiling and quote generation
- User remains on the applicant history page or is redirected to applicant summary

---

### Test Case: Verify rejection of incomplete or invalid history data
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in as an Insurance Agent with valid credentials
- User has appropriate permissions to access applicant history section
- Applicant profile exists in the system
- Validation rules are configured correctly in the system
- Browser JavaScript is enabled for client-side validation

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the applicant history section from the main dashboard or applicant profile page | History entry form is displayed with all required fields marked with asterisks or 'Required' labels |
| 2 | Leave the mandatory 'Previous Insurer Name' field blank and enter valid data in other fields: coverage period from '01/01/2020' to '12/31/2020' | Inline validation error message appears near the 'Previous Insurer Name' field stating 'This field is required' or similar message |
| 3 | Enter 'ABC Insurance' in the 'Previous Insurer Name' field, but leave the mandatory 'Coverage Start Date' field blank | Previous error clears, new inline validation error appears near the 'Coverage Start Date' field stating 'Coverage start date is required' |
| 4 | Enter an invalid date format '13/45/2020' in the 'Coverage Start Date' field | Inline validation error appears stating 'Invalid date format. Please use MM/DD/YYYY' or similar message |
| 5 | Enter valid 'Coverage Start Date' as '01/01/2020' but enter 'Coverage End Date' as '12/31/2019' (end date before start date) | Inline validation error appears stating 'Coverage end date must be after start date' or similar message |
| 6 | Correct the 'Coverage End Date' to '12/31/2020', then enter a 'Claim Date' as '06/15/2019' (outside coverage period) | Inline validation error appears stating 'Claim date must fall within the coverage period' or similar message |
| 7 | Enter a negative value '-1000' in the 'Claim Amount' field | Inline validation error appears stating 'Claim amount must be a positive number' or similar message |
| 8 | Enter non-numeric characters 'ABC' in the 'Claim Amount' field | Inline validation error appears stating 'Claim amount must be a valid number' or field prevents non-numeric input |
| 9 | Attempt to click the 'Save' button while validation errors are still present on the form | Save action is blocked, button may be disabled or clicking produces no action, error summary message appears at top of form stating 'Please correct the errors below before saving', form does not submit |
| 10 | Correct all validation errors by entering valid data in all mandatory fields with proper formats and date ranges | All validation error messages disappear, 'Save' button becomes enabled or clickable |
| 11 | Click the 'Save' button after correcting all errors | Form submits successfully, success confirmation message is displayed, data is saved to the database |

**Postconditions:**
- No invalid data is saved to the database
- Form validation rules are enforced consistently
- User is informed of all validation errors clearly
- Only corrected valid data is persisted in the system
- Data integrity is maintained in the applicant history tables

---

### Test Case: Ensure editing and deletion of history entries function correctly
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- User is logged in as an Insurance Agent with valid credentials
- User has appropriate permissions to edit and delete applicant history
- Applicant profile exists in the system
- At least one applicant history record already exists in the database
- Database supports update and delete operations

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the applicant history section and click 'Add New Record' button | Blank history entry form is displayed with all required fields |
| 2 | Enter first history record with valid data: Previous insurer 'ABC Insurance', coverage period '01/01/2020' to '12/31/2020', claim amount '$5,000', claim date '06/15/2020' | Data is entered without validation errors |
| 3 | Click 'Add Another Record' and enter second history record: Previous insurer 'XYZ Insurance', coverage period '01/01/2021' to '12/31/2021', claim amount '$3,500', claim date '09/20/2021' | Second record is added without validation errors |
| 4 | Click the 'Save' button to save both history records | Success message is displayed stating 'Records saved successfully', both records are persisted in the database and displayed in the history list |
| 5 | Locate the first history record (ABC Insurance) in the saved records list and click the 'Edit' button or icon next to it | The history record opens in edit mode with all fields populated with the existing data, fields are editable |
| 6 | Modify the claim amount from '$5,000' to '$6,500' and change the claim date from '06/15/2020' to '07/20/2020' | Changes are accepted in the form fields without validation errors, modified values are displayed correctly |
| 7 | Click the 'Save Changes' or 'Update' button to save the edited record | Success message is displayed stating 'Record updated successfully', form returns to view mode or list view |
| 8 | Verify the edited record by viewing it in the history list or reopening it | The first record now shows updated claim amount '$6,500' and claim date '07/20/2020', all other fields remain unchanged, changes are reflected correctly |
| 9 | Refresh the page or navigate away and return to the applicant history section | The edited data persists after page refresh, updated values are still displayed correctly |
| 10 | Locate the second history record (XYZ Insurance) in the saved records list and click the 'Delete' button or icon next to it | Confirmation dialog appears asking 'Are you sure you want to delete this history record?' with 'Cancel' and 'Delete' options |
| 11 | Click 'Cancel' in the confirmation dialog | Dialog closes, record is not deleted, second record remains in the history list |
| 12 | Click the 'Delete' button again for the second history record (XYZ Insurance) | Confirmation dialog appears again |
| 13 | Click 'Delete' or 'Confirm' in the confirmation dialog | Success message is displayed stating 'Record deleted successfully', the second record (XYZ Insurance) is removed from the history list immediately |
| 14 | Verify that only the first record (ABC Insurance with updated data) remains in the history list | Only one history record is displayed showing ABC Insurance with claim amount '$6,500' and claim date '07/20/2020' |
| 15 | Refresh the page or navigate away and return to verify deletion persistence | After page refresh, only the first record remains, the deleted record does not reappear, changes are persisted in the database |

**Postconditions:**
- Edited history record contains updated information in the database
- Deleted history record is permanently removed from the database
- Remaining history records are intact and unaffected
- Audit log records both edit and delete actions with timestamps and user information
- Data integrity is maintained after edit and delete operations
- Only one history record (ABC Insurance with updated data) exists for the applicant

---

