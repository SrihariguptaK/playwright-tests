# Manual Test Cases

## Story: As Scheduling Manager, I want to assign shift templates to employees to create schedules
**Story ID:** story-4

### Test Case: Assign shift template to employee successfully
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as a Scheduling Manager with valid credentials
- At least one employee exists in the system
- At least one shift template is configured and available
- User has authorization to create employee schedules
- Schedule creation page is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule creation page from the main menu | Schedule creation form is displayed with options to select employees and shift templates |
| 2 | Click on the employee selection dropdown and select a specific employee from the list | Selected employee is highlighted and displayed in the employee field |
| 3 | Click on the shift template dropdown and select a valid shift template | Selected shift template is displayed with its details (start time, end time, duration) |
| 4 | Select a valid start date and end date for the shift assignment using the date picker | Dates are populated in the date fields with no validation errors shown |
| 5 | Review the assignment details to ensure employee, shift template, and dates are correct | All assignment details are correctly displayed with no validation errors or warnings |
| 6 | Click the 'Submit' or 'Save' button to save the schedule assignment | Schedule is successfully saved to the database and a confirmation message is displayed (e.g., 'Schedule assigned successfully') |
| 7 | Verify the assigned schedule appears in the employee's schedule view | The newly assigned shift is visible in the employee's schedule with correct dates and shift template details |

**Postconditions:**
- Employee schedule is saved in the EmployeeSchedules table
- Schedule assignment is visible in the employee's schedule view
- No overlapping shifts exist for the employee
- System logs the schedule creation action with timestamp and manager details

---

### Test Case: Prevent overlapping shift assignments
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in as a Scheduling Manager
- An employee already has a shift assigned for a specific date and time range
- User has authorization to create employee schedules
- Schedule creation page is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule creation page | Schedule creation form is displayed |
| 2 | Select the employee who already has an existing shift assignment | Employee is selected and displayed in the employee field |
| 3 | Select a shift template that overlaps with the employee's existing shift (same date, overlapping time range) | Shift template is selected and displayed |
| 4 | Enter dates that create an overlap with the existing shift assignment | Dates are entered in the date fields |
| 5 | Click the 'Submit' or 'Save' button to attempt saving the overlapping schedule | System displays a validation error message indicating shift overlap (e.g., 'Error: This shift overlaps with an existing assignment for this employee') |
| 6 | Verify that the overlapping schedule is not saved to the database | The overlapping shift does not appear in the employee's schedule and the original shift remains unchanged |
| 7 | Attempt to close or dismiss the error message | Error message is dismissed and user remains on the schedule creation form to make corrections |

**Postconditions:**
- No overlapping shift is saved in the EmployeeSchedules table
- Original employee schedule remains intact
- Validation error is logged in the system
- User remains on the schedule creation page to correct the assignment

---

## Story: As Scheduling Manager, I want to validate employee schedules to ensure compliance with labor rules
**Story ID:** story-5

### Test Case: Validate schedule against maximum working hours
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in as a Scheduling Manager
- Labor rules are configured with maximum daily working hours limit (e.g., 12 hours per day)
- At least one employee and shift template exist in the system
- User has authorization to create and modify schedules

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule creation page | Schedule creation form is displayed |
| 2 | Select an employee from the employee dropdown | Employee is selected and displayed |
| 3 | Assign multiple shift templates or a single long shift that exceeds the maximum daily working hours limit | Shifts are added to the schedule form showing total hours exceeding the limit |
| 4 | Click the 'Submit' or 'Save' button to attempt saving the schedule | System displays a validation error message (e.g., 'Error: Schedule exceeds maximum daily working hours of 12 hours') and prevents saving |
| 5 | Verify that the schedule is not saved to the database | The violating schedule does not appear in the employee's schedule view |
| 6 | Adjust the schedule by removing or shortening shifts to comply with maximum working hours | Total working hours are now within the allowed limit and no validation errors are displayed |
| 7 | Click the 'Submit' or 'Save' button again | Schedule saves successfully and a confirmation message is displayed (e.g., 'Schedule saved successfully') |
| 8 | Verify the compliant schedule appears in the employee's schedule view | The adjusted schedule is visible with correct shift details and complies with labor rules |

**Postconditions:**
- Only compliant schedule is saved in the EmployeeSchedules table
- No labor rule violations exist in the saved schedule
- Validation attempt is logged in the system
- Employee schedule reflects only the compliant assignments

---

### Test Case: Enforce minimum rest period between shifts
- **ID:** tc-004
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as a Scheduling Manager
- Labor rules are configured with minimum rest period between shifts (e.g., 8 hours)
- At least one employee exists in the system
- User has authorization to create schedules

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule creation page | Schedule creation form is displayed |
| 2 | Select an employee from the employee dropdown | Employee is selected and displayed |
| 3 | Assign a first shift template with specific end time (e.g., ending at 10:00 PM) | First shift is added to the schedule |
| 4 | Assign a second shift template that starts before the minimum rest period has elapsed (e.g., starting at 4:00 AM the next day, only 6 hours rest) | Second shift is added to the schedule form |
| 5 | Click the 'Submit' or 'Save' button to attempt saving the schedule | System displays a warning or error message (e.g., 'Warning: Insufficient rest period between shifts. Minimum 8 hours required, only 6 hours provided') |
| 6 | Verify that the system prevents saving or displays a clear warning requiring acknowledgment | Schedule is either blocked from saving or requires manager acknowledgment of the violation before proceeding |

**Postconditions:**
- Schedule with insufficient rest period is not saved without proper acknowledgment
- Validation warning/error is logged in the system
- Manager is informed of the labor rule violation
- Employee schedule remains compliant or violation is documented

---

### Test Case: Override validation with justification
- **ID:** tc-005
- **Type:** edge-case
- **Priority:** Medium
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in as an authorized Scheduling Manager with override permissions
- Labor rules are configured and active
- A schedule exists that violates one or more labor rules
- Override functionality is enabled for authorized users

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule creation page and create a schedule that violates labor rules (e.g., exceeds maximum hours or insufficient rest period) | Schedule is created with labor rule violations |
| 2 | Click the 'Submit' or 'Save' button to attempt saving the violating schedule | System displays validation error or warning message with details of the violation |
| 3 | Click on the 'Override' button or checkbox to indicate intention to override the validation | System prompts for justification with a text input field or dialog box (e.g., 'Please provide justification for overriding this labor rule violation') |
| 4 | Enter a valid business justification in the justification field (e.g., 'Emergency coverage required due to staff shortage') | Justification text is entered and displayed in the input field |
| 5 | Click the 'Confirm' or 'Save with Override' button to finalize the override | Schedule is saved successfully despite the labor rule violation, and a confirmation message is displayed (e.g., 'Schedule saved with override') |
| 6 | Verify that the override and justification are logged in the system audit trail | System logs show the override action with timestamp, manager details, violation type, and justification text |
| 7 | Navigate to the employee's schedule view to verify the schedule is saved | The schedule with override is visible in the employee's schedule, potentially marked with an indicator showing it was saved with an override |

**Postconditions:**
- Schedule is saved in EmployeeSchedules table despite labor rule violation
- Override action is logged with justification, timestamp, and manager identity
- Schedule is marked or flagged as having an approved override
- Audit trail contains complete override documentation for compliance review

---

