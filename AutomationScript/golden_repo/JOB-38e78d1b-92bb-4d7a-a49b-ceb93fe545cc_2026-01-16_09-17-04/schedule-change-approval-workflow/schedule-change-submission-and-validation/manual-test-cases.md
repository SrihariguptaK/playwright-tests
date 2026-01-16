# Manual Test Cases

## Story: As Schedule Coordinator, I want to submit schedule change requests to achieve accurate and timely schedule updates
**Story ID:** story-1

### Test Case: Validate successful schedule change submission with valid data
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as Schedule Coordinator
- User has necessary permissions to submit schedule change requests
- Schedule change submission page is accessible
- Test attachment file (PDF/DOC, under 10MB) is prepared

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to schedule change submission page | Submission form is displayed with all mandatory fields including date, time, reason, and attachment upload option |
| 2 | Enter valid schedule change date (future date in format MM/DD/YYYY) | Date field accepts the input without validation errors |
| 3 | Enter valid schedule change time (in format HH:MM AM/PM) | Time field accepts the input without validation errors |
| 4 | Enter valid reason for schedule change in the reason field (minimum 10 characters) | Reason field accepts the input without validation errors |
| 5 | Click on attachment upload button and select a valid document file (PDF, 5MB) | File is uploaded successfully and file name is displayed in the attachment section |
| 6 | Review all entered data for accuracy | All fields display the entered data correctly with no validation error messages |
| 7 | Click the Submit button | Request is accepted and processed within 2 seconds |
| 8 | Verify the confirmation message displayed on screen | Confirmation message is displayed with a unique request ID in the format SCR-XXXXXX |

**Postconditions:**
- Schedule change request is saved in ScheduleChangeRequests table
- Request status is set to 'Submitted'
- Unique request ID is generated and associated with the request
- User remains on confirmation page or is redirected to request list

---

### Test Case: Verify rejection of submission with missing mandatory fields
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in as Schedule Coordinator
- User has necessary permissions to submit schedule change requests
- Schedule change submission page is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to schedule change submission page | Submission form is displayed with all mandatory fields marked with asterisk (*) |
| 2 | Leave the date field empty | Field remains empty without pre-filled data |
| 3 | Leave the time field empty | Field remains empty without pre-filled data |
| 4 | Leave the reason field empty | Field remains empty without pre-filled data |
| 5 | Click outside the mandatory fields to trigger real-time validation | Real-time validation highlights missing fields with red border and displays inline error messages such as 'Date is required', 'Time is required', 'Reason is required' |
| 6 | Attempt to click the Submit button | Submission is blocked and Submit button either remains disabled or prevents form submission |
| 7 | Verify error messages displayed at the top of the form or near each field | Clear error messages are displayed indicating which mandatory fields are missing: 'Please complete all required fields before submitting' |
| 8 | Fill in only the date field with valid data and attempt to submit again | Submission is still blocked with error messages for remaining mandatory fields (time and reason) |

**Postconditions:**
- No record is created in ScheduleChangeRequests table
- User remains on the submission form page
- All validation error messages are visible to the user
- Form data is retained for user to complete

---

### Test Case: Ensure duplicate schedule change requests are prevented
- **ID:** tc-003
- **Type:** edge-case
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as Schedule Coordinator
- User has necessary permissions to submit schedule change requests
- Schedule change submission page is accessible
- Database is accessible for verification
- No existing schedule change request exists for the test schedule and time period

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to schedule change submission page | Submission form is displayed with all mandatory fields |
| 2 | Enter schedule change date as '12/15/2024' | Date field accepts the input |
| 3 | Enter schedule change time as '10:00 AM' | Time field accepts the input |
| 4 | Enter reason as 'Equipment maintenance required' | Reason field accepts the input |
| 5 | Click Submit button | Request is accepted and confirmation message with unique request ID (e.g., SCR-001234) is displayed |
| 6 | Note the request ID and navigate back to schedule change submission page | New blank submission form is displayed |
| 7 | Enter the same schedule change date as '12/15/2024' | Date field accepts the input |
| 8 | Enter the same schedule change time as '10:00 AM' | Time field accepts the input |
| 9 | Enter reason as 'Additional maintenance work' | Reason field accepts the input |
| 10 | Click Submit button | System rejects the duplicate request and displays error message: 'A schedule change request already exists for this schedule and time period. Request ID: SCR-001234' |
| 11 | Access the database and query ScheduleChangeRequests table for schedule date '12/15/2024' and time '10:00 AM' | Database query returns only one record with request ID SCR-001234 |
| 12 | Verify the count of records for the specific schedule and time combination | Count equals 1, confirming only a single unique request exists |

**Postconditions:**
- Only one schedule change request exists in the database for the specified schedule and time
- Duplicate request was not saved to the database
- User is informed of the existing request with its ID
- Data integrity is maintained in ScheduleChangeRequests table

---

## Story: As Schedule Coordinator, I want to save schedule change requests as drafts to achieve flexibility in submission
**Story ID:** story-8

### Test Case: Validate saving and retrieving schedule change drafts
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in as Schedule Coordinator
- User has necessary permissions to create and save drafts
- Schedule change request form is accessible
- ScheduleChangeDrafts table is accessible and empty for this user

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to schedule change request form page | Form is displayed with all fields empty and Save Draft button is visible |
| 2 | Enter partial data: schedule change date as '01/20/2025' | Date field accepts and displays the entered value |
| 3 | Enter partial data: schedule change time as '02:00 PM' | Time field accepts and displays the entered value |
| 4 | Leave the reason field empty (mandatory field intentionally left blank) | Reason field remains empty without validation errors |
| 5 | Click the Save Draft button | Draft is saved within 2 seconds and confirmation message is displayed: 'Draft saved successfully' with timestamp |
| 6 | Navigate away from the form page to dashboard or another page | User is navigated to the selected page without data loss warning |
| 7 | Navigate back to schedule change request form or access 'My Drafts' section | List of saved drafts is displayed showing the recently saved draft with date/time information |
| 8 | Click on the saved draft to retrieve and edit it | Draft is loaded within 2 seconds and form is displayed |
| 9 | Verify the date field contains the previously entered value '01/20/2025' | Date field is pre-filled with '01/20/2025' |
| 10 | Verify the time field contains the previously entered value '02:00 PM' | Time field is pre-filled with '02:00 PM' |
| 11 | Verify the reason field is empty as it was not filled during draft save | Reason field is empty, confirming draft data is loaded correctly |

**Postconditions:**
- Draft is saved in ScheduleChangeDrafts table with user association
- Draft data is accurately retrieved and pre-filled in the form
- User can continue editing the draft
- Draft remains in saved state until submitted or deleted

---

### Test Case: Verify validation is bypassed on draft save
- **ID:** tc-005
- **Type:** edge-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in as Schedule Coordinator
- User has necessary permissions to create and save drafts
- Schedule change request form is accessible
- User understands mandatory field requirements for final submission

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to schedule change request form page | Form is displayed with all mandatory fields marked with asterisk (*) |
| 2 | Leave all mandatory fields empty (date, time, reason) | All fields remain empty |
| 3 | Click the Save Draft button without filling any mandatory fields | Draft is saved successfully within 2 seconds without any validation errors or warnings |
| 4 | Verify confirmation message is displayed | Confirmation message 'Draft saved successfully' is displayed |
| 5 | Retrieve the saved draft from 'My Drafts' section | Draft is loaded with all fields empty as saved |
| 6 | Without filling any mandatory fields, click the Submit button | Submission is blocked immediately |
| 7 | Verify validation error messages are displayed | Validation errors are displayed for all missing mandatory fields: 'Date is required', 'Time is required', 'Reason is required' |
| 8 | Fill in only the date field with '02/10/2025' and attempt to submit again | Submission is still blocked with validation errors for time and reason fields |
| 9 | Click Save Draft button with only date field filled | Draft is saved successfully without validation errors, confirming validation is bypassed on draft save |

**Postconditions:**
- Draft with partial/missing data is saved in ScheduleChangeDrafts table
- Validation rules are enforced only on final submission attempt
- User can save incomplete drafts multiple times without validation blocking
- Draft remains editable until final submission

---

### Test Case: Ensure auto-save triggers every 2 minutes
- **ID:** tc-006
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in as Schedule Coordinator
- User has necessary permissions to create drafts
- Schedule change request form is accessible
- Auto-save functionality is enabled in system settings
- Timer or clock is available to track 2-minute intervals

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to schedule change request form page and note the current time | Form is displayed with all fields empty and current time is recorded (e.g., 10:00:00 AM) |
| 2 | Enter schedule change date as '03/15/2025' | Date field accepts and displays the entered value |
| 3 | Wait for 2 minutes without any user interaction (do not click Save Draft or Submit) | After exactly 2 minutes (at 10:02:00 AM), auto-save triggers automatically |
| 4 | Observe for auto-save notification or indicator on the screen | Auto-save notification is displayed: 'Draft auto-saved at [timestamp]' or auto-save indicator shows successful save |
| 5 | Enter additional data: schedule change time as '03:30 PM' | Time field accepts and displays the entered value |
| 6 | Wait for another 2 minutes without any user interaction | After 2 minutes (at 10:04:00 AM), auto-save triggers again automatically |
| 7 | Observe for second auto-save notification | Auto-save notification is displayed with updated timestamp confirming second auto-save |
| 8 | Navigate away from the form without manually saving | User can navigate away, and data is preserved due to auto-save |
| 9 | Return to the form or access 'My Drafts' section | Draft is available in the drafts list |
| 10 | Open the auto-saved draft and verify the data | Draft contains the latest entered data: date '03/15/2025' and time '03:30 PM', confirming auto-save persisted the data correctly |
| 11 | Check the draft timestamp in the database or UI | Draft timestamp matches the last auto-save time (approximately 10:04:00 AM) |

**Postconditions:**
- Draft is auto-saved in ScheduleChangeDrafts table every 2 minutes
- Latest entered data is persisted without manual save action
- Auto-save functionality operates independently of user actions
- User can recover work even if they navigate away without manual save

---

