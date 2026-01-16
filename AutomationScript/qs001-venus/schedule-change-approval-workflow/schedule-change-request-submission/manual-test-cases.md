# Manual Test Cases

## Story: As Employee, I want to submit schedule change requests to achieve timely updates to my work schedule
**Story ID:** story-1

### Test Case: Validate successful schedule change request submission with valid input
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee has valid login credentials
- Employee is logged into the scheduling system
- Schedule change request page is accessible
- Test file (PDF/DOC) under 5MB is available for attachment
- Database connection is active and ScheduleChangeRequests table is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to schedule change request page from the main dashboard | Schedule change request form is displayed with all mandatory fields visible: Date, Time, Reason, and optional file attachment field. All fields are empty and ready for input |
| 2 | Enter a valid future date in the Date field (e.g., tomorrow's date) | Date is accepted and displayed in the correct format without validation errors |
| 3 | Enter a valid time in the Time field (e.g., 09:00 AM) | Time is accepted and displayed in the correct format without validation errors |
| 4 | Enter a valid reason in the Reason field (e.g., 'Medical appointment') | Reason text is accepted and displayed in the field without validation errors |
| 5 | Click on the file attachment button and select a valid file (PDF/DOC) under 5MB | File is successfully attached, file name is displayed, and no error messages appear |
| 6 | Click the 'Submit' button | Form is submitted successfully, confirmation message is displayed (e.g., 'Your schedule change request has been submitted successfully'), and the page shows submission timestamp |
| 7 | Verify the request is logged in the system by checking the submission history or database | Request appears in the submission log with correct timestamp, employee ID, and all submitted data including attached file |

**Postconditions:**
- Schedule change request is saved in ScheduleChangeRequests table
- Request has a unique ID and timestamp
- Request status is set to 'Submitted'
- Request is forwarded to approval workflow
- Employee can view the submitted request in their request history
- System response time is under 2 seconds

---

### Test Case: Verify rejection of submission with missing mandatory fields
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Employee has valid login credentials
- Employee is logged into the scheduling system
- Schedule change request page is accessible
- Form validation rules are configured correctly

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to schedule change request page from the main dashboard | Schedule change request form is displayed with all mandatory fields visible and empty |
| 2 | Leave the Date field empty and click outside the field or tab to the next field | Real-time validation triggers and highlights the Date field with a red border or indicator, displaying error message 'Date is required' |
| 3 | Leave the Time field empty and click outside the field or tab to the next field | Real-time validation triggers and highlights the Time field with a red border or indicator, displaying error message 'Time is required' |
| 4 | Leave the Reason field empty and click outside the field | Real-time validation triggers and highlights the Reason field with a red border or indicator, displaying error message 'Reason is required' |
| 5 | Click the 'Submit' button with all mandatory fields still empty | Form submission is blocked and prevented. Descriptive error messages are displayed at the top of the form and/or next to each empty mandatory field stating 'Please complete all required fields before submitting' |
| 6 | Verify that no data is saved to the database | No new record is created in the ScheduleChangeRequests table and no submission log entry exists |
| 7 | Fill in only the Date field with a valid date and attempt to submit again | Submission is still blocked with error messages displayed for the remaining empty mandatory fields (Time and Reason) |

**Postconditions:**
- No schedule change request is created in the database
- Form remains on the screen with entered data preserved
- Error messages are clearly visible to the user
- User can correct the errors and resubmit
- No partial or incomplete data is logged

---

### Test Case: Ensure draft save functionality works correctly
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 7 mins

**Preconditions:**
- Employee has valid login credentials
- Employee is logged into the scheduling system
- Schedule change request page is accessible
- Draft save functionality is enabled
- Database supports draft storage

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to schedule change request page from the main dashboard | Schedule change request form is displayed with all fields empty and ready for input |
| 2 | Enter a valid future date in the Date field (e.g., next week's date) | Date is accepted and displayed without validation errors |
| 3 | Enter a valid time in the Time field (e.g., 02:00 PM) | Time is accepted and displayed without validation errors |
| 4 | Leave the Reason field empty (partial data entry) | Reason field remains empty without triggering validation errors since draft save does not require all mandatory fields |
| 5 | Click the 'Save Draft' button | Draft is saved successfully and a confirmation notification is displayed (e.g., 'Draft saved successfully' or 'Your changes have been saved as draft') |
| 6 | Verify the draft timestamp is displayed on the form | Last saved timestamp is visible on the form (e.g., 'Draft saved at 10:30 AM') |
| 7 | Navigate away from the schedule change request page to another section of the application | User successfully navigates to another page without losing draft data |
| 8 | Return to the schedule change request page | Form is displayed and automatically loads the previously saved draft data |
| 9 | Verify that the Date field contains the previously entered date | Date field displays the exact date that was entered before saving the draft |
| 10 | Verify that the Time field contains the previously entered time | Time field displays the exact time that was entered before saving the draft |
| 11 | Verify that the Reason field is still empty as it was not filled | Reason field remains empty, confirming partial data was correctly saved and restored |

**Postconditions:**
- Draft is saved in the database with status 'Draft'
- Draft has a unique ID and timestamp
- Previously entered data is preserved and retrievable
- User can continue editing the draft or submit it after completion
- Draft does not appear in the approval workflow until submitted
- User can have multiple drafts if system allows

---

