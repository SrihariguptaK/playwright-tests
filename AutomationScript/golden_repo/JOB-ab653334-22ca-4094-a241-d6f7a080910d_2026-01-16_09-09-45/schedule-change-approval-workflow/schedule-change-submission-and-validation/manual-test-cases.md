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
- Test attachment file (PDF, 5MB) is prepared
- Valid schedule data is available for testing

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to schedule change submission page | Submission form is displayed with all mandatory fields including date, time, reason, schedule ID, and attachment upload section |
| 2 | Enter valid schedule ID in the schedule field | Schedule ID is accepted and field shows no validation errors |
| 3 | Select a future date from the date picker | Date is populated in correct format and accepted by the system |
| 4 | Enter valid time in the time field | Time is accepted in proper format (HH:MM) without validation errors |
| 5 | Enter a valid reason for schedule change in the reason field (minimum 10 characters) | Reason text is accepted and character count is displayed |
| 6 | Click on attachment upload button and select a valid PDF file (5MB) | File upload progress is shown, file is successfully attached, and file name is displayed with size information |
| 7 | Review all entered data for accuracy | All fields display entered data correctly without any validation error messages |
| 8 | Click the Submit button | Request is accepted, confirmation message is displayed with unique request ID in format SCR-XXXXXX, and submission timestamp is shown |
| 9 | Copy the request ID and verify it is unique | Request ID is successfully copied and can be used for tracking |

**Postconditions:**
- Schedule change request is saved in ScheduleChangeRequests table
- Request status is set to 'Submitted'
- Request ID is generated and associated with the submission
- Attachment is stored in the system
- User is redirected to confirmation page or dashboard
- Request appears in the user's submitted requests list

---

### Test Case: Verify rejection of submission with missing mandatory fields
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in as Schedule Coordinator
- User has necessary permissions to submit schedule change requests
- Schedule change submission page is accessible
- All mandatory fields are identified: schedule ID, date, time, reason

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to schedule change submission page | Submission form is displayed with all mandatory fields marked with asterisk (*) or 'Required' label |
| 2 | Leave the schedule ID field empty | Field remains empty without any data |
| 3 | Click or tab away from the schedule ID field | Real-time validation triggers and displays error message 'Schedule ID is required' in red text below the field |
| 4 | Leave the date field empty | Date field shows placeholder text but no selected date |
| 5 | Leave the time field empty | Time field remains empty |
| 6 | Leave the reason field empty | Reason field contains no text |
| 7 | Attempt to click the Submit button | Submission is blocked, Submit button may be disabled or clicking produces no submission action |
| 8 | Observe all mandatory fields | All empty mandatory fields are highlighted with red borders and display specific error messages: 'Schedule ID is required', 'Date is required', 'Time is required', 'Reason is required' |
| 9 | Verify a summary error message is displayed at the top of the form | Error summary message displays 'Please complete all required fields before submitting' or similar message |
| 10 | Verify the form remains on the submission page | User remains on the same page with form data preserved and no navigation occurs |

**Postconditions:**
- No record is created in ScheduleChangeRequests table
- Form remains in editable state
- All validation error messages are visible
- User can correct errors and resubmit
- No request ID is generated

---

### Test Case: Ensure duplicate schedule change requests are prevented
- **ID:** tc-003
- **Type:** edge-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in as Schedule Coordinator
- User has necessary permissions to submit schedule change requests
- Schedule change submission page is accessible
- Test schedule ID 'SCH-12345' is available
- Test date and time '2024-02-15 10:00 AM' is available
- Database access is available to verify request records

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to schedule change submission page | Submission form is displayed with all required fields |
| 2 | Enter schedule ID 'SCH-12345' in the schedule field | Schedule ID is accepted and displayed in the field |
| 3 | Select date '2024-02-15' from the date picker | Date is populated and displayed correctly |
| 4 | Enter time '10:00 AM' in the time field | Time is accepted and displayed in correct format |
| 5 | Enter reason 'Equipment maintenance required' in the reason field | Reason text is accepted and displayed |
| 6 | Click the Submit button | Request is accepted, confirmation message is displayed with unique request ID (e.g., SCR-001234), and success message appears |
| 7 | Note the request ID and navigate back to schedule change submission page | New blank submission form is displayed |
| 8 | Enter the same schedule ID 'SCH-12345' in the schedule field | Schedule ID is accepted in the field |
| 9 | Select the same date '2024-02-15' from the date picker | Date is populated in the field |
| 10 | Enter the same time '10:00 AM' in the time field | Time is accepted in the field |
| 11 | Enter reason 'Additional changes needed' in the reason field | Reason text is accepted |
| 12 | Click the Submit button | System rejects the duplicate request and displays error message 'A schedule change request already exists for this schedule and time period. Request ID: SCR-001234' in red text |
| 13 | Verify no new request ID is generated | No confirmation message or new request ID is displayed |
| 14 | Query the database for schedule ID 'SCH-12345' with date '2024-02-15' and time '10:00 AM' | Database query returns exactly one record with request ID SCR-001234, confirming no duplicate was created |

**Postconditions:**
- Only one schedule change request exists in ScheduleChangeRequests table for the specified schedule and time
- Original request remains unchanged
- No duplicate request ID is generated
- User remains on submission page with error message visible
- Form data is preserved for user to modify

---

## Story: As Schedule Coordinator, I want to save schedule change requests as drafts to achieve flexibility in submission
**Story ID:** story-8

### Test Case: Validate saving and retrieving schedule change drafts
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as Schedule Coordinator
- User has necessary permissions to create and save drafts
- Schedule change request form is accessible
- ScheduleChangeDrafts table is accessible
- No existing drafts for the test scenario

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to schedule change request form page | Form is displayed with all fields empty and both 'Save Draft' and 'Submit' buttons are visible |
| 2 | Enter partial data: schedule ID 'SCH-67890' in the schedule field | Schedule ID is accepted and displayed in the field |
| 3 | Enter date '2024-03-20' in the date field | Date is populated and displayed correctly |
| 4 | Leave time and reason fields empty intentionally | Time and reason fields remain empty without triggering validation errors |
| 5 | Click the 'Save Draft' button | Draft is saved successfully, confirmation message 'Draft saved successfully' is displayed, and a draft ID is generated |
| 6 | Note the draft ID or timestamp and navigate away from the form page | User is able to navigate to another page or dashboard without data loss warning |
| 7 | Navigate to 'My Drafts' or 'Saved Drafts' section | List of saved drafts is displayed showing the recently saved draft with schedule ID 'SCH-67890' and save timestamp |
| 8 | Click on the saved draft to open it | Schedule change request form opens with the draft data pre-filled |
| 9 | Verify schedule ID field contains 'SCH-67890' | Schedule ID field displays 'SCH-67890' correctly |
| 10 | Verify date field contains '2024-03-20' | Date field displays '2024-03-20' correctly |
| 11 | Verify time and reason fields are empty as originally saved | Time and reason fields are empty, matching the original draft state |
| 12 | Verify 'Save Draft' and 'Submit' buttons are available for further actions | Both buttons are visible and enabled for user to continue editing or submit |

**Postconditions:**
- Draft is saved in ScheduleChangeDrafts table with partial data
- Draft is associated with the logged-in user
- Draft can be retrieved and edited by the same user
- No validation errors are triggered on draft save
- Draft remains in 'Draft' status and not submitted

---

### Test Case: Verify validation is bypassed on draft save
- **ID:** tc-005
- **Type:** edge-case
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as Schedule Coordinator
- User has necessary permissions to create drafts and submit requests
- Schedule change request form is accessible
- Mandatory fields are: schedule ID, date, time, reason
- Validation rules are active for final submission

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to schedule change request form page | Form is displayed with all fields empty and mandatory fields marked with asterisk (*) |
| 2 | Enter only schedule ID 'SCH-11111' leaving all other mandatory fields empty | Schedule ID is accepted, other fields remain empty |
| 3 | Click the 'Save Draft' button without filling date, time, or reason | Draft is saved successfully without any validation errors, confirmation message 'Draft saved successfully' is displayed |
| 4 | Verify no error messages are displayed for missing mandatory fields | No validation error messages appear, form shows success state |
| 5 | Verify draft is saved by checking the drafts list | Draft appears in 'My Drafts' section with schedule ID 'SCH-11111' and incomplete status indicator |
| 6 | Retrieve the saved draft by clicking on it from the drafts list | Form opens with schedule ID 'SCH-11111' pre-filled and other fields empty |
| 7 | Without adding any additional data, click the 'Submit' button | Submission is blocked and validation is triggered |
| 8 | Observe validation error messages for missing mandatory fields | Error messages are displayed: 'Date is required', 'Time is required', 'Reason is required' with fields highlighted in red |
| 9 | Verify a summary error message appears at the top of the form | Error summary displays 'Please complete all required fields before submitting' or similar message |
| 10 | Verify the Submit button action is prevented | No submission occurs, no request ID is generated, and user remains on the form page |

**Postconditions:**
- Draft remains saved in ScheduleChangeDrafts table with partial data
- No record is created in ScheduleChangeRequests table
- Validation errors are displayed on submission attempt
- Form remains editable for user to complete required fields
- Draft status remains as 'Draft' and not 'Submitted'

---

### Test Case: Ensure auto-save triggers every 2 minutes
- **ID:** tc-006
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as Schedule Coordinator
- User has necessary permissions to create drafts
- Schedule change request form is accessible
- Auto-save functionality is enabled and configured for 2-minute intervals
- Timer or clock is available to track 2-minute intervals
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to schedule change request form page and note the current time | Form is displayed with all fields empty, current time is recorded (e.g., 10:00:00 AM) |
| 2 | Enter schedule ID 'SCH-99999' in the schedule field | Schedule ID is accepted and displayed in the field |
| 3 | Enter date '2024-04-10' in the date field | Date is populated and displayed correctly |
| 4 | Wait for 2 minutes without any user interaction (do not click any buttons) | After 2 minutes (at 10:02:00 AM), auto-save triggers automatically |
| 5 | Observe for auto-save indicator or notification | Auto-save notification appears briefly (e.g., 'Draft auto-saved at 10:02:00 AM' or spinning icon), confirming automatic save occurred |
| 6 | Enter time '02:30 PM' in the time field after auto-save | Time is accepted and displayed in the field |
| 7 | Wait for another 2 minutes without clicking any buttons | After 2 minutes (at 10:04:00 AM), second auto-save triggers automatically |
| 8 | Observe for second auto-save indicator or notification | Auto-save notification appears again (e.g., 'Draft auto-saved at 10:04:00 AM'), confirming second automatic save |
| 9 | Navigate away from the form without manually saving | User can navigate away without data loss warning since auto-save has persisted the data |
| 10 | Navigate to 'My Drafts' section | Drafts list displays the auto-saved draft with schedule ID 'SCH-99999' |
| 11 | Open the auto-saved draft | Form opens with all entered data pre-filled: schedule ID 'SCH-99999', date '2024-04-10', time '02:30 PM' |
| 12 | Verify draft data contains the latest entered information including time field | All fields display the most recent data entered before the last auto-save, confirming draft contains latest entered data |

**Postconditions:**
- Draft is auto-saved in ScheduleChangeDrafts table at 2-minute intervals
- Latest form data is persisted without user manual action
- Auto-save timestamp is recorded with each save
- User can retrieve draft with most recent data
- No data loss occurs if user navigates away
- Auto-save does not trigger validation errors

---

