# Manual Test Cases

## Story: As Manager, I want to receive attendance alerts to achieve timely awareness of attendance anomalies
**Story ID:** story-4

### Test Case: Validate alert configuration and delivery
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- Manager is logged into the system with valid credentials
- Manager has appropriate role-based permissions to configure alerts
- Alert configuration interface is accessible
- Email notification service is operational
- Dashboard notification center is functional
- Real-time attendance monitoring system is active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to alert configuration settings page | Alert configuration page loads successfully displaying available alert types and notification channel options |
| 2 | Select 'Late Arrivals' as the alert type from the available options | Late Arrivals alert type is selected and threshold configuration fields are displayed |
| 3 | Set the threshold value for late arrivals (e.g., 15 minutes) | Threshold value is accepted and displayed in the configuration field |
| 4 | Select 'Email' as the notification channel | Email notification channel is selected and email address field is displayed with manager's email pre-populated |
| 5 | Click 'Save' button to save the alert configuration | Configuration is saved successfully with confirmation message displayed: 'Alert configuration saved successfully' |
| 6 | Simulate a late arrival event by creating a test attendance record where an employee arrives 20 minutes late (exceeding the 15-minute threshold) | System detects the late arrival anomaly and triggers alert generation process |
| 7 | Wait and monitor for alert delivery (maximum 5 minutes) | Alert email is received in manager's inbox within 5 minutes containing late arrival details (employee name, arrival time, threshold exceeded) |
| 8 | Navigate to the dashboard notification center | Dashboard loads successfully and notification center displays the late arrival alert with unacknowledged status |
| 9 | Click on the late arrival alert in the dashboard notification center | Alert details panel opens showing complete information: employee name, event type, timestamp, threshold value, and acknowledge/resolve options |
| 10 | Click 'Acknowledge' button on the alert | Alert status is updated to 'Acknowledged' with timestamp and manager's name recorded, confirmation message displayed |
| 11 | Refresh the dashboard notification center | Alert now displays 'Acknowledged' status with acknowledgment timestamp and manager details visible |

**Postconditions:**
- Alert configuration is saved in the system
- Alert is generated and logged in the system
- Email notification is sent and delivered
- Alert appears in dashboard with acknowledged status
- Alert acknowledgment is recorded with timestamp and manager information
- System is ready for subsequent alert monitoring

---

### Test Case: Verify alert logging and audit trail
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 20 mins

**Preconditions:**
- Manager is logged into the system with valid credentials
- Manager has permissions to view audit logs
- Alert system is configured and operational
- Audit logging functionality is enabled
- Multiple alert types are configured (absences, late arrivals, threshold breaches)
- Database has sufficient storage for audit logs

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Simulate an absence event by creating an attendance record with an employee marked as absent | System detects absence anomaly and generates an absence alert |
| 2 | Simulate a late arrival event by creating an attendance record with employee arriving late beyond threshold | System detects late arrival anomaly and generates a late arrival alert |
| 3 | Simulate a threshold breach event by creating multiple consecutive late arrivals for the same employee | System detects threshold breach and generates a threshold breach alert |
| 4 | Navigate to the audit logs section in the system | Audit logs page loads successfully with search and filter options available |
| 5 | Filter audit logs to display alert generation events for the current date | All three generated alerts (absence, late arrival, threshold breach) are displayed in the audit log with complete details: alert ID, type, timestamp, employee details, and generation status |
| 6 | Verify each alert log entry contains required information: alert ID, alert type, timestamp, employee name, threshold value, and generation timestamp | All alert entries contain complete and accurate information with precise timestamps in chronological order |
| 7 | Navigate to the dashboard notification center and view the generated alerts | All three alerts are displayed in the notification center with 'Unresolved' status |
| 8 | Select the absence alert and click 'Resolve' button, adding resolution notes: 'Employee on approved leave' | Alert status changes to 'Resolved' with resolution notes saved and timestamp recorded |
| 9 | Select the late arrival alert and click 'Resolve' button, adding resolution notes: 'Discussed with employee' | Alert status changes to 'Resolved' with resolution notes saved and timestamp recorded |
| 10 | Select the threshold breach alert and click 'Resolve' button, adding resolution notes: 'Performance improvement plan initiated' | Alert status changes to 'Resolved' with resolution notes saved and timestamp recorded |
| 11 | Return to the audit logs section and filter for alert resolution actions | Audit trail displays all three resolution actions with complete details: alert ID, resolution timestamp, manager name, resolution notes, and previous status |
| 12 | Review the complete audit log history for one specific alert from generation to resolution | Complete and accurate alert history is available showing: initial generation event, acknowledgment (if any), resolution action, all timestamps, manager actions, and status transitions in chronological order |
| 13 | Export audit logs to verify data completeness | Audit log export contains all alert events with complete information in structured format |

**Postconditions:**
- All generated alerts are logged in the audit trail
- All resolution actions are recorded with complete details
- Audit logs contain complete history from alert generation to resolution
- Alert statuses are updated to 'Resolved'
- Resolution notes are saved and associated with respective alerts
- Audit trail is available for compliance and reporting purposes

---

## Story: As Manager, I want to customize alert thresholds to achieve personalized attendance monitoring
**Story ID:** story-10

### Test Case: Validate alert threshold customization and application
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 18 mins

**Preconditions:**
- Manager is logged into the system with valid credentials
- Manager has role-based permissions to customize alert thresholds
- Alert threshold settings interface is accessible
- Default threshold values are configured in the system
- Alert generation system is operational
- Preview functionality is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the alert settings page from the main dashboard menu | Alert settings page loads successfully displaying navigation options for threshold configuration |
| 2 | Click on 'Alert Threshold Settings' option | Alert threshold configuration interface is displayed showing all available alert types (absences, late arrivals, early departures, threshold breaches) |
| 3 | Review the current threshold values displayed for each alert type | Current thresholds are displayed correctly: Late Arrivals (default: 15 minutes), Absences (default: 1 occurrence), Early Departures (default: 10 minutes), Consecutive Late Arrivals (default: 3 occurrences) |
| 4 | Click on the 'Late Arrivals' threshold field to edit | Late Arrivals threshold field becomes editable with current value highlighted and input cursor active |
| 5 | Enter a new valid threshold value of '20' minutes for Late Arrivals | New value '20' is accepted and displayed in the threshold field without validation errors |
| 6 | Click on the 'Consecutive Late Arrivals' threshold field to edit | Consecutive Late Arrivals threshold field becomes editable with current value highlighted |
| 7 | Enter a new valid threshold value of '5' occurrences for Consecutive Late Arrivals | New value '5' is accepted and displayed in the threshold field without validation errors |
| 8 | Click on the 'Early Departures' threshold field to edit | Early Departures threshold field becomes editable with current value highlighted |
| 9 | Enter a new valid threshold value of '15' minutes for Early Departures | New value '15' is accepted and displayed in the threshold field without validation errors |
| 10 | Click 'Save' button to save the modified threshold settings | System validates all inputs, saves the new threshold values, and displays confirmation message: 'Alert thresholds saved and applied successfully' |
| 11 | Verify the saved values by refreshing the alert threshold settings page | Page reloads and displays the updated threshold values: Late Arrivals (20 minutes), Consecutive Late Arrivals (5 occurrences), Early Departures (15 minutes) |
| 12 | Click on 'Preview Alert Impact' button | Preview interface opens displaying a simulation panel with options to view expected alerts based on new thresholds |
| 13 | Select a date range for preview (e.g., last 7 days) and click 'Generate Preview' | System processes historical attendance data and displays preview results showing: number of alerts that would have been generated with new thresholds vs. old thresholds, breakdown by alert type, and comparison metrics |
| 14 | Review the preview results to verify new threshold settings impact | Preview accurately reflects new threshold settings: Late Arrivals alerts reduced (threshold increased from 15 to 20 minutes), Consecutive Late Arrivals alerts reduced (threshold increased from 3 to 5), Early Departures alerts increased (threshold increased from 10 to 15 minutes) |
| 15 | Simulate a new late arrival event with employee arriving 18 minutes late | No alert is generated because 18 minutes is below the new threshold of 20 minutes |
| 16 | Simulate a new late arrival event with employee arriving 25 minutes late | Alert is generated immediately because 25 minutes exceeds the new threshold of 20 minutes, confirming new thresholds are applied in real-time |

**Postconditions:**
- Custom threshold values are saved in the system database
- New thresholds are immediately applied to alert generation logic
- Preview results are available for manager review
- Alert generation uses updated threshold values for all subsequent monitoring
- System logs threshold changes for audit purposes
- Manager can verify threshold changes are effective

---

### Test Case: Verify validation prevents invalid threshold inputs
- **ID:** tc-004
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Manager is logged into the system with valid credentials
- Manager has permissions to access alert threshold settings
- Alert threshold settings interface is accessible
- Input validation rules are configured in the system
- Current valid threshold values are set

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the alert threshold settings page | Alert threshold settings page loads successfully displaying current threshold values and editable fields |
| 2 | Click on the 'Late Arrivals' threshold field and enter a negative value '-10' | System detects invalid input and displays validation error message: 'Threshold value must be a positive number' in red text near the field |
| 3 | Attempt to click 'Save' button with the negative value still in the field | Save button is disabled or clicking it triggers validation error preventing save action, error message remains visible |
| 4 | Clear the negative value and enter zero '0' in the 'Late Arrivals' threshold field | System detects invalid input and displays validation error message: 'Threshold value must be greater than zero' |
| 5 | Clear the zero value and enter a non-numeric value 'abc' in the 'Late Arrivals' threshold field | System detects invalid input type and displays validation error message: 'Please enter a valid numeric value' |
| 6 | Clear the non-numeric value and enter a decimal value '15.5' in the 'Late Arrivals' threshold field | System detects invalid format and displays validation error message: 'Threshold value must be a whole number' (if decimals are not allowed) or accepts the value (if decimals are allowed per business rules) |
| 7 | Clear the field and enter an extremely large value '999999' in the 'Late Arrivals' threshold field | System detects value exceeding maximum allowed threshold and displays validation error message: 'Threshold value cannot exceed [maximum value, e.g., 480 minutes]' |
| 8 | Click on the 'Consecutive Late Arrivals' threshold field and enter a negative value '-5' | System displays validation error message: 'Threshold value must be a positive number' |
| 9 | Clear the field and leave the 'Consecutive Late Arrivals' threshold field empty (blank) | System detects missing required value and displays validation error message: 'This field is required' or 'Please enter a threshold value' |
| 10 | Enter special characters '!@#$' in the 'Early Departures' threshold field | System detects invalid characters and displays validation error message: 'Only numeric values are allowed' |
| 11 | Attempt to save the form with multiple validation errors present | System prevents saving and displays summary of all validation errors: 'Please correct the following errors before saving' with list of all invalid fields |
| 12 | Correct all invalid inputs by entering valid threshold values: Late Arrivals (20), Consecutive Late Arrivals (5), Early Departures (15) | All validation error messages disappear as valid values are entered, fields display green checkmarks or success indicators |
| 13 | Click 'Save' button with all valid inputs | System accepts all valid inputs, saves the threshold settings successfully, and displays confirmation message: 'Alert thresholds saved successfully' |

**Postconditions:**
- Invalid threshold values are rejected and not saved to the database
- Validation error messages are displayed appropriately for each error type
- System prevents saving of invalid configurations
- Only valid threshold values are accepted and saved
- User is guided to correct invalid inputs through clear error messages
- Data integrity is maintained by preventing invalid threshold configurations

---

