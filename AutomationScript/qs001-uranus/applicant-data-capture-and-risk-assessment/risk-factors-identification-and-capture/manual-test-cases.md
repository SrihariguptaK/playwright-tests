# Manual Test Cases

## Story: As Risk Analyst, I want to capture applicant risk factors to achieve precise risk profiling
**Story ID:** story-2

### Test Case: Validate risk factor data submission with complete inputs
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with Risk Analyst role
- Applicant profile exists in the system
- ApplicantRiskFactors table is accessible
- Quoting engine integration is active
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the risk factors input section from the applicant profile page | Risk factors input page loads successfully within 2 seconds. All relevant risk categories are displayed based on applicant profile. Mandatory fields are clearly marked with asterisks. Input fields are enabled and ready for data entry |
| 2 | Enter valid risk factor data in all mandatory fields including risk category selection, risk severity level, risk description, and any profile-specific required fields | All inputs are accepted without validation errors. Real-time validation shows green checkmarks or success indicators next to completed fields. No error messages are displayed. Character limits and format requirements are respected |
| 3 | Click the Submit button to save the risk factor data | System displays a success message confirming data has been saved. Risk factor data is successfully integrated with the quoting engine. Response time is under 2 seconds. User is redirected to confirmation page or applicant summary showing updated risk profile |

**Postconditions:**
- Risk factor data is persisted in ApplicantRiskFactors table
- Quoting engine has received and processed the risk data
- Applicant risk profile is updated
- Audit log entry is created for the submission
- Risk data status is set to 'Submitted'

---

### Test Case: Verify rejection of incomplete risk factor data submission
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in with Risk Analyst role
- Applicant profile exists in the system
- ApplicantRiskFactors table is accessible
- Validation rules are configured and active
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the risk factors input section from the applicant profile page | Risk factors input page loads successfully. All relevant risk categories and input fields are displayed. Mandatory fields are clearly marked with asterisks or required indicators |
| 2 | Leave one or more mandatory risk factor fields empty (such as risk category, severity level, or description) and optionally fill some non-mandatory fields | Real-time validation highlights the missing mandatory fields with red borders or warning icons. Inline error messages appear below empty required fields indicating 'This field is required'. Submit button may be disabled or show warning state |
| 3 | Attempt to submit the incomplete risk factor data by clicking the Submit button | Submission is blocked and prevented. Clear error message is displayed at the top of the form stating 'Please complete all required fields before submitting'. All incomplete mandatory fields are highlighted in red. Focus is moved to the first incomplete field. No data is saved to the database. User remains on the input page |

**Postconditions:**
- No data is saved to ApplicantRiskFactors table
- No integration call is made to quoting engine
- User remains on the risk factors input page
- Form retains any valid data entered
- Error state is clearly visible to the user

---

### Test Case: Test addition of custom risk factor details
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in with Risk Analyst role
- Applicant profile exists in the system
- ApplicantRiskFactors table supports custom fields
- Custom risk factor feature is enabled
- Quoting engine can process custom risk factors

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the risk factors input section from the applicant profile page | Risk factors input page loads successfully. Standard risk categories and input fields are displayed. An 'Add Custom Risk Factor' button or link is visible and enabled |
| 2 | Click on 'Add Custom Risk Factor' button and enter custom risk factor details including custom category name, description, severity level, and any additional notes | Custom risk factor input fields appear dynamically. All custom inputs are accepted with appropriate validation (character limits, required fields). Real-time validation confirms valid entries. Custom risk factor is added to the form display. Option to add multiple custom factors is available |
| 3 | Complete all mandatory standard risk factor fields and click Submit button to save all data including custom risk factors | System displays success message confirming all data including custom risk factors has been saved. Custom risk factors are successfully integrated with the quoting engine. Response time is under 2 seconds. Confirmation page shows both standard and custom risk factors. Risk profile reflects all captured data |

**Postconditions:**
- All risk factor data including custom entries is persisted in ApplicantRiskFactors table
- Custom risk factors are properly tagged and identifiable
- Quoting engine has processed both standard and custom risk data
- Applicant risk profile includes custom risk factors
- Audit log captures custom risk factor additions

---

## Story: As Risk Analyst, I want to review and validate captured risk factors to achieve data quality assurance
**Story ID:** story-5

### Test Case: Validate risk factor review dashboard displays data correctly
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in with Risk Analyst role and review permissions
- Risk factor data has been submitted and is pending review
- ApplicantRiskFactors table contains reviewable records
- Review dashboard API endpoints are accessible
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Login to the system using Risk Analyst credentials and navigate to the risk factor review dashboard from the main menu | Review dashboard loads within 3 seconds. Dashboard displays all captured risk factors pending review in a structured table or card format. Each entry shows applicant name, submission date, risk categories, and review status. Data is accurate and matches submitted information. Filtering and sorting options are available |
| 2 | Review the displayed risk factor data and identify any missing or inconsistent data entries by examining completeness and logical consistency | System automatically highlights issues with visual indicators (red flags, warning icons, or colored backgrounds). Missing mandatory fields are clearly marked. Inconsistent data (logical conflicts, out-of-range values) is flagged with specific issue descriptions. Tooltip or detail panel explains each validation issue. Issue summary count is displayed |
| 3 | Select a risk factor entry with issues, enter correction request comments in the provided text field, and click 'Request Corrections' button | Correction request is submitted successfully. Confirmation message appears stating 'Correction request sent successfully'. Risk data status is updated to 'Correction Requested'. Comments are saved and associated with the record. Notification is triggered to the data submitter. Dashboard refreshes to show updated status. Timestamp of correction request is recorded |

**Postconditions:**
- Risk factor status is updated to 'Correction Requested' in database
- Correction comments are stored and linked to the record
- Notification is sent to appropriate stakeholders
- Audit trail captures the review action
- Dashboard reflects the updated status

---

### Test Case: Verify access control restricts non-analyst users
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Test user account exists without Risk Analyst role (e.g., Sales Agent, Administrator, or other role)
- Role-based access control is configured and active
- Review dashboard and APIs have proper security settings
- Authentication system is functioning
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Login to the system using credentials of a non-Risk Analyst user and attempt to navigate to the risk factor review dashboard via direct URL or menu access | Access to the review dashboard is denied. User is redirected to an access denied page or unauthorized error page (HTTP 403). Clear error message is displayed stating 'You do not have permission to access this resource' or similar. Review dashboard content is not visible. Navigation menu does not show review dashboard option for unauthorized roles |
| 2 | Attempt to directly access review API endpoints (GET /api/applicants/riskfactors/review) using API testing tool or browser with non-analyst user session token | API request is rejected with HTTP 403 Forbidden status code. Response body contains appropriate error message indicating insufficient permissions. No risk factor data is returned in the response. Security headers are properly set. Attempt is logged in security audit log |

**Postconditions:**
- No unauthorized access to risk factor review data occurred
- Security audit log contains entry of unauthorized access attempt
- User session remains valid but restricted to authorized functions
- No data breach or exposure occurred
- System security integrity is maintained

---

### Test Case: Test approval of risk factor data
- **ID:** tc-006
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with Risk Analyst role and approval permissions
- Risk factor data has been submitted and is pending review
- Risk data is complete and passes all validation checks
- ApplicantRiskFactors table contains reviewable records
- Approval API endpoint is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Login to the system as Risk Analyst and navigate to the review dashboard, then select a risk factor record that is complete and valid for review | Review dashboard displays successfully within 3 seconds. Risk factor data is displayed accurately with all captured details visible. Data shows no validation issues or missing fields. Review options including 'Approve' and 'Request Corrections' buttons are enabled and visible. Record details are complete and consistent |
| 2 | Review all risk factor details for accuracy and completeness, then click the 'Approve' button to approve the risk data | Approval confirmation dialog appears asking 'Are you sure you want to approve this risk data?'. Upon confirmation, system processes the approval request. Success message is displayed stating 'Risk data approved successfully'. Risk data status is updated to 'Approved' in real-time. Approval timestamp and analyst name are recorded. Confirmation notification is shown on screen. Dashboard refreshes to reflect the approved status |

**Postconditions:**
- Risk factor status is updated to 'Approved' in ApplicantRiskFactors table
- Approval timestamp and approver details are recorded
- Approved data is available for underwriting and quoting processes
- Notification is sent to relevant stakeholders
- Audit log entry is created documenting the approval
- Record moves out of pending review queue

---

## Story: As Risk Analyst, I want to generate risk factor summary reports to achieve informed decision making
**Story ID:** story-8

### Test Case: Validate generation of risk factor summary report with filters
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as a Risk Analyst with valid credentials
- Risk report module is accessible and functional
- ApplicantRiskFactors table contains test data with various risk levels, dates, and statuses
- System is under normal load conditions
- PDF and Excel export functionality is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the risk report module from the main dashboard | Risk report module page loads successfully and displays filter options |
| 2 | Select date range filter (e.g., last 30 days) from the date picker | Date range is selected and displayed in the filter section |
| 3 | Select risk level filter (e.g., High, Medium) | Risk level filter is applied and displayed in the active filters section |
| 4 | Select status filter (e.g., Active, Pending) | Status filter is applied and displayed in the active filters section |
| 5 | Click on 'Generate Report' button | System processes the request and generates the report within 5 seconds, displaying a loading indicator during generation |
| 6 | Review the generated report data including applicant names, risk categories, risk levels, and dates | Report displays only data matching the selected filters (date range: last 30 days, risk levels: High and Medium, status: Active and Pending) |
| 7 | Verify that risk factors are properly aggregated by applicant and category | Report shows correct aggregation with no duplicate entries and proper categorization |
| 8 | Click on 'Export to PDF' button | PDF file downloads successfully with filename containing report name and timestamp |
| 9 | Open the downloaded PDF file | PDF opens successfully, is readable, contains all report data with proper formatting, headers, and footers |
| 10 | Return to the report page and click on 'Export to Excel' button | Excel file downloads successfully with filename containing report name and timestamp |
| 11 | Open the downloaded Excel file | Excel file opens successfully, is readable, contains all report data in structured columns with proper headers and formatting |

**Postconditions:**
- Risk factor summary report is generated and displayed on screen
- PDF and Excel files are downloaded to the user's default download location
- Report generation is logged in the system audit trail
- User remains on the risk report module page
- Filters remain applied for subsequent report generations

---

### Test Case: Verify scheduling of automated report generation
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in as a Risk Analyst with scheduling permissions
- Risk report module is accessible and functional
- System scheduler service is running and operational
- Email delivery service is configured and functional
- Test data exists in ApplicantRiskFactors table

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the risk report module | Risk report module page loads successfully |
| 2 | Click on 'Schedule Report' or 'Automated Reports' button | Schedule configuration dialog or page opens displaying scheduling options |
| 3 | Enter report name as 'Weekly Risk Summary' | Report name is entered and displayed in the name field |
| 4 | Select report filters: date range (Last 7 days), risk level (All), status (Active) | Selected filters are displayed in the schedule configuration |
| 5 | Set recurrence pattern to 'Weekly' and select day as 'Monday' | Recurrence pattern is set and displayed as 'Every Monday' |
| 6 | Set time for report generation as '08:00 AM' | Time is set and displayed as '08:00 AM' |
| 7 | Select export format as 'PDF and Excel' | Both PDF and Excel formats are selected and indicated |
| 8 | Enter delivery email address in the recipient field | Email address is entered and validated as correct format |
| 9 | Click 'Save Schedule' or 'Create Schedule' button | System saves the schedule and displays success confirmation message with schedule ID |
| 10 | Verify the scheduled report appears in the list of automated reports | Scheduled report 'Weekly Risk Summary' is listed with correct recurrence pattern, time, and status as 'Active' |
| 11 | Wait for or simulate the scheduled time (Monday 08:00 AM) to trigger report generation | System automatically generates the report at the scheduled time |
| 12 | Check the scheduled reports execution log or history | Log shows successful execution with timestamp matching the scheduled time |
| 13 | Verify email delivery by checking the recipient inbox | Email is received with subject containing report name, and attachments include both PDF and Excel files with correct data |

**Postconditions:**
- Automated report schedule is saved and active in the system
- Schedule appears in the list of automated reports
- Report is generated and delivered at the scheduled time
- Execution is logged in the system audit trail
- Email with report attachments is delivered to specified recipients

---

### Test Case: Test access control for risk reports
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- System has role-based access control configured
- Test user accounts exist: one with Risk Analyst role and one without (e.g., General User or Applicant role)
- Risk report module is functional and accessible via direct URL
- ApplicantRiskFactors table contains test data
- Authentication and authorization services are operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Logout from any existing session to ensure clean test state | User is logged out and redirected to login page |
| 2 | Login with unauthorized user credentials (username: 'testuser', role: General User) | Login successful and user is redirected to their authorized dashboard |
| 3 | Attempt to navigate to risk report module via menu or navigation | Risk report module option is not visible in the navigation menu |
| 4 | Attempt to access risk report module directly by entering the URL '/api/reports/riskfactors' or report page URL | Access is denied with HTTP 403 Forbidden status or appropriate error page displaying message 'Access Denied: You do not have permission to view risk reports' |
| 5 | Verify that no report data is displayed or accessible | No sensitive risk report data is exposed; user sees only the access denied message |
| 6 | Verify error is logged in the system security audit log | Unauthorized access attempt is logged with user ID, timestamp, and attempted resource |
| 7 | Logout from the unauthorized user account | User is logged out successfully and redirected to login page |
| 8 | Login with Risk Analyst credentials (username: 'riskanalyst01', role: Risk Analyst) | Login successful and user is redirected to Risk Analyst dashboard |
| 9 | Navigate to risk report module via menu or navigation | Risk report module option is visible and accessible in the navigation menu |
| 10 | Click on risk report module link | Risk report module page loads successfully displaying filter options and report generation interface |
| 11 | Generate a sample risk report without applying any filters | Report is generated successfully within 5 seconds and displays risk factor data |
| 12 | Verify all report features are accessible (filters, export, scheduling) | All features are visible and functional for the Risk Analyst user |

**Postconditions:**
- Unauthorized user access attempt is denied and logged
- No sensitive data is exposed to unauthorized users
- Risk Analyst user successfully accesses and uses risk report module
- Security audit log contains records of both access attempts
- System maintains proper role-based access control integrity

---

