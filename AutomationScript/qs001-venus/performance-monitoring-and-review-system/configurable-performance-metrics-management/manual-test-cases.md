# Manual Test Cases

## Story: As Performance Manager, I want to create new performance metrics to achieve tailored evaluation criteria for different roles
**Story ID:** story-13

### Test Case: Validate successful metric creation with valid input
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- User is logged in as Performance Manager
- User has permissions to create performance metrics
- Metrics Management page is accessible
- No existing metric with the same name exists for the target role

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to Metrics Management page from the main dashboard | Metrics Management page loads successfully and displays the current metrics list with 'Add Metric' button visible |
| 2 | Click the 'Add Metric' button | Add Metric form is displayed with empty fields for Name, Description, Type, Target, Weight, and Role/Department assignment |
| 3 | Enter valid metric name (e.g., 'Sales Target Achievement') | Metric name field accepts the input without validation errors |
| 4 | Enter valid description (e.g., 'Measures quarterly sales target completion percentage') | Description field accepts the input without validation errors |
| 5 | Select metric type from dropdown (e.g., 'Percentage') | Type dropdown displays available options and accepts the selection |
| 6 | Enter valid target value (e.g., '100') | Target field accepts the numeric input without validation errors |
| 7 | Enter valid weight value (e.g., '0.3') | Weight field accepts the numeric input without validation errors |
| 8 | Select role or department from assignment dropdown (e.g., 'Sales Team') | Role/Department dropdown displays available options and accepts the selection |
| 9 | Click the 'Submit' or 'Save' button | Form is submitted successfully, confirmation message 'Metric created successfully' is displayed, and user is redirected to the metrics list |
| 10 | Verify the newly created metric appears in the metrics list | The new metric 'Sales Target Achievement' is visible in the metrics overview with all entered details displayed correctly |

**Postconditions:**
- New metric is saved in PerformanceMetrics table
- Metric appears in the metrics list immediately
- Metric is available for assignment to performance reviews
- System logs the metric creation action

---

### Test Case: Reject metric creation with invalid numeric fields
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in as Performance Manager
- User has permissions to create performance metrics
- Metrics Management page is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to Metrics Management page | Metrics Management page loads successfully with 'Add Metric' button visible |
| 2 | Click the 'Add Metric' button | Add Metric form is displayed with all required fields empty |
| 3 | Enter valid metric name (e.g., 'Customer Satisfaction Score') | Metric name field accepts the input |
| 4 | Enter valid description | Description field accepts the input |
| 5 | Select metric type from dropdown | Type is selected successfully |
| 6 | Enter invalid negative value in target field (e.g., '-50') | Inline validation error message is displayed below the target field indicating 'Target value must be a positive number' |
| 7 | Enter invalid negative value in weight field (e.g., '-0.5') | Inline validation error message is displayed below the weight field indicating 'Weight must be between 0 and 1' |
| 8 | Attempt to click the 'Submit' button | Submit button is disabled or submission is blocked, and error messages remain visible highlighting the invalid fields |
| 9 | Correct the target field to a valid positive number (e.g., '80') | Validation error for target field disappears |
| 10 | Correct the weight field to a valid value (e.g., '0.25') | Validation error for weight field disappears and Submit button becomes enabled |

**Postconditions:**
- No metric is created in the database
- Form remains open with corrected values
- User can proceed with valid data submission

---

### Test Case: Prevent duplicate metric names for the same role
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as Performance Manager
- User has permissions to create performance metrics
- At least one metric already exists (e.g., 'Quality Score' for 'Engineering Team')
- Metrics Management page is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to Metrics Management page | Metrics Management page loads with existing metrics displayed including 'Quality Score' for 'Engineering Team' |
| 2 | Click 'Add Metric' button | Add Metric form is displayed |
| 3 | Enter metric name 'Quality Score' | Metric name field accepts the input |
| 4 | Fill in all other required fields with valid data (description, type, target, weight) | All fields accept valid input without validation errors |
| 5 | Select 'Engineering Team' from the role/department dropdown | Engineering Team is selected |
| 6 | Click 'Submit' button | System validates the submission and displays error message 'A metric with this name already exists for the selected role/department' and prevents creation |
| 7 | Verify that the duplicate metric was not created in the metrics list | Only one 'Quality Score' metric exists for 'Engineering Team' in the metrics list |
| 8 | Modify the metric name to a unique value (e.g., 'Code Quality Score') | Metric name field is updated with the new unique name |
| 9 | Click 'Submit' button again | Metric is created successfully, confirmation message 'Metric created successfully' is displayed |
| 10 | Verify the newly created metric appears in the metrics list | The metric 'Code Quality Score' for 'Engineering Team' is visible in the metrics overview |

**Postconditions:**
- Original metric 'Quality Score' remains unchanged
- New metric 'Code Quality Score' is created and saved
- Both metrics are visible in the metrics list for Engineering Team
- Database maintains data integrity with no duplicates

---

## Story: As Performance Manager, I want to edit existing performance metrics to keep evaluation criteria up to date
**Story ID:** story-14

### Test Case: Validate successful metric editing with valid input
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in as Performance Manager
- User has permissions to edit performance metrics
- At least one editable metric exists in the system (not linked to active review cycles)
- Metrics Management page is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to Metrics Management page from the main dashboard | Metrics Management page loads successfully and displays the list of existing metrics with edit options available |
| 2 | Locate an existing metric (e.g., 'Sales Target Achievement') and click the 'Edit' button or icon | Edit Metric form is displayed with all fields pre-populated with the current metric data including Name, Description, Type, Target, Weight, and Role/Department |
| 3 | Modify the metric description to a new valid value (e.g., 'Updated: Measures monthly sales target completion percentage') | Description field accepts the modified input without validation errors |
| 4 | Modify the target value to a new valid number (e.g., change from '100' to '110') | Target field accepts the new numeric value without validation errors |
| 5 | Modify the weight value to a new valid number (e.g., change from '0.3' to '0.35') | Weight field accepts the new numeric value without validation errors |
| 6 | Click the 'Submit' or 'Update' button | Form is submitted successfully, system validates the inputs, and confirmation message 'Metric updated successfully' is displayed |
| 7 | Verify the updated metric appears in the metrics list with modified values | The metric 'Sales Target Achievement' is displayed in the metrics list with the updated description, target value '110', and weight '0.35' |
| 8 | Check the audit log for the metric update | Audit log contains an entry with timestamp, user information, and details of the changes made to the metric |

**Postconditions:**
- Metric is updated in PerformanceMetrics table with new values
- Audit log entry is created with timestamp and user details
- Updated metric is immediately visible in the metrics list
- Previous metric values are preserved in audit history

---

### Test Case: Reject editing of metrics linked to active review cycles
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- User is logged in as Performance Manager
- User has permissions to edit performance metrics
- At least one metric exists that is linked to an active review cycle
- Active review cycle is in progress
- Metrics Management page is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to Metrics Management page | Metrics Management page loads successfully displaying all metrics including those linked to active review cycles |
| 2 | Locate a metric that is linked to an active review cycle (e.g., 'Q4 Performance Rating') | Metric is visible in the list with edit option available |
| 3 | Click the 'Edit' button for the metric linked to active review cycle | Edit form is displayed with current metric data pre-populated in all fields |
| 4 | Modify any field (e.g., change target value from '90' to '95') | Field accepts the input change |
| 5 | Click the 'Submit' or 'Update' button | System validates the metric status and displays error message 'Cannot edit metric: This metric is linked to an active review cycle' and prevents the update from being saved |
| 6 | Verify that the metric values remain unchanged in the metrics list | The metric 'Q4 Performance Rating' displays the original target value '90' with no changes applied |
| 7 | Check the audit log | No audit log entry is created for the attempted update as the change was rejected |

**Postconditions:**
- Metric remains unchanged in the database
- Active review cycle integrity is maintained
- No audit log entry is created for the rejected update
- User is informed of the restriction with clear error message

---

### Test Case: Reject invalid input during metric editing
- **ID:** tc-006
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as Performance Manager
- User has permissions to edit performance metrics
- At least one editable metric exists in the system
- Metrics Management page is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to Metrics Management page | Metrics Management page loads successfully with existing metrics displayed |
| 2 | Select an editable metric and click the 'Edit' button | Edit Metric form is displayed with all fields pre-populated with current metric data |
| 3 | Clear the target field and enter an invalid non-numeric value (e.g., 'abc') | Inline validation error message is displayed below the target field indicating 'Target must be a valid number' |
| 4 | Clear the weight field and enter an invalid value outside the acceptable range (e.g., '1.5') | Inline validation error message is displayed below the weight field indicating 'Weight must be between 0 and 1' |
| 5 | Enter a negative number in the target field (e.g., '-20') | Inline validation error message is displayed indicating 'Target value must be a positive number' |
| 6 | Attempt to click the 'Submit' or 'Update' button | Submit button is disabled or submission is blocked, and all validation error messages remain visible highlighting the invalid fields |
| 7 | Correct the target field to a valid positive number (e.g., '85') | Validation error for target field disappears |
| 8 | Correct the weight field to a valid value within range (e.g., '0.4') | Validation error for weight field disappears and Submit button becomes enabled |
| 9 | Click the 'Submit' button with corrected values | Form is submitted successfully and confirmation message 'Metric updated successfully' is displayed |

**Postconditions:**
- Metric is updated only after all validation errors are corrected
- Invalid data is not saved to the database
- Audit log records only the successful update with valid data
- User receives clear feedback on validation errors

---

## Story: As Performance Manager, I want to delete obsolete performance metrics to maintain a relevant metrics catalog
**Story ID:** story-15

### Test Case: Validate successful metric deletion with confirmation
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as Performance Manager with delete permissions
- At least one performance metric exists that is not linked to any active review cycles
- Metrics Management page is accessible
- Audit logging system is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to Metrics Management page | Metrics Management page loads successfully and displays a list of all available performance metrics with their details (name, description, status) |
| 2 | Locate a metric that is not linked to any active review cycles and click the delete button/icon for that metric | A confirmation prompt dialog appears asking 'Are you sure you want to delete this metric?' with options to Confirm or Cancel |
| 3 | Click the Confirm button in the deletion confirmation prompt | The metric is successfully deleted from the system, a success confirmation message is displayed (e.g., 'Metric deleted successfully'), and the metrics list automatically refreshes showing the updated list without the deleted metric |
| 4 | Verify the deletion was logged by checking the audit logs | Audit log contains an entry for the deletion action with the user ID, timestamp, and deleted metric details |
| 5 | Verify the deletion response time | The entire deletion process completes in under 2 seconds from confirmation to list refresh |

**Postconditions:**
- The selected metric is permanently removed from the PerformanceMetrics table
- The metrics list no longer displays the deleted metric
- Deletion action is recorded in audit logs with user and timestamp
- No data integrity issues exist in the database

---

### Test Case: Prevent deletion of metrics linked to active review cycles
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as Performance Manager with delete permissions
- At least one performance metric exists that is linked to one or more active review cycles
- Metrics Management page is accessible
- Active review cycles exist in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to Metrics Management page | Metrics Management page loads successfully and displays a list of all available performance metrics |
| 2 | Identify and select a metric that is linked to an active review cycle | The metric is selected and the delete option/button is visible and available |
| 3 | Click the delete button for the selected metric | A confirmation prompt dialog appears asking for deletion confirmation |
| 4 | Click the Confirm button to attempt deletion | System rejects the deletion request and displays a clear error message such as 'Cannot delete metric: This metric is linked to one or more active review cycles' or 'Deletion failed: Metric is currently in use by active review cycles' |
| 5 | Verify the metric still exists in the metrics list | The metric remains in the PerformanceMetrics table and is still visible in the metrics list, unchanged |
| 6 | Check audit logs for the attempted deletion | Audit log records the failed deletion attempt with reason for rejection |

**Postconditions:**
- The metric remains in the system unchanged
- The link between the metric and active review cycles is preserved
- Error message is displayed to the user explaining why deletion failed
- No data integrity issues exist in the database

---

## Story: As Performance Manager, I want to validate performance metric data inputs to ensure data quality and accuracy
**Story ID:** story-23

### Test Case: Validate rejection of invalid metric data inputs
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in as Performance Manager with data entry permissions
- Metric data entry form is accessible
- Validation rules are configured for all metric data fields (data types, ranges, mandatory fields)
- Frontend validation is enabled and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the metric data entry form | Metric data entry form loads successfully displaying all required fields (numeric fields, text fields, mandatory fields marked with asterisks) |
| 2 | Enter invalid data in a mandatory numeric field (e.g., enter text 'abc' in a numeric field) | Inline validation error message appears immediately below or next to the field stating 'Please enter a valid number' or similar descriptive error |
| 3 | Leave a mandatory field empty and move to the next field | Inline validation error message appears stating 'This field is required' or similar message |
| 4 | Enter a numeric value outside the acceptable range (e.g., enter -5 when minimum is 0) | Inline validation error message appears stating 'Value must be between [min] and [max]' or similar range validation message |
| 5 | Verify validation response time for each error | Each validation error appears within 1 second of the invalid input or field blur event |
| 6 | Attempt to submit the form with validation errors present | Form submission is blocked, submit button is disabled or shows error, and a message appears stating 'Please correct all errors before submitting' or similar |
| 7 | Correct all validation errors by entering valid data in all fields | All inline error messages disappear as valid data is entered, and the submit button becomes enabled |
| 8 | Submit the form with all valid data | Form submits successfully, data is saved to PerformanceMetricData table, and a confirmation message is displayed stating 'Metric data saved successfully' or similar |

**Postconditions:**
- Valid metric data is saved in the PerformanceMetricData table
- No invalid data exists in the database
- User receives confirmation of successful data submission
- Form is cleared or redirected to appropriate page

---

### Test Case: Validate backend rejection of invalid data
- **ID:** tc-004
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- API endpoint POST /api/metricdata is accessible and operational
- Backend validation rules are configured and active
- User has valid authentication token for API access
- API testing tool (e.g., Postman, cURL) is available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Prepare an API request to POST /api/metricdata with invalid data payload (e.g., missing mandatory fields, invalid data types, out-of-range values) | API request is properly formatted with authentication headers and invalid payload |
| 2 | Submit the API request with invalid metric data | API returns HTTP 400 Bad Request status code |
| 3 | Review the API response body | Response contains descriptive validation error messages in JSON format, clearly identifying which fields failed validation and why (e.g., {'errors': [{'field': 'metricValue', 'message': 'Value must be a number'}, {'field': 'metricName', 'message': 'This field is required'}]}) |
| 4 | Verify the response time of the validation | API validation response is received within 1 second of request submission |
| 5 | Check the database to confirm no invalid data was saved | PerformanceMetricData table does not contain any records from the invalid submission attempt |
| 6 | Submit a corrected API request with valid data in all fields | API returns HTTP 200 OK or 201 Created status code with success message, and data is successfully saved to the database |

**Postconditions:**
- No invalid data is persisted in the PerformanceMetricData table
- Backend validation successfully prevents data corruption
- Descriptive error messages are provided for troubleshooting
- Valid data submitted subsequently is accepted and saved

---

