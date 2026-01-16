# Manual Test Cases

## Story: As Quoting Specialist, I want to receive real-time quote updates based on rating engine responses to achieve faster and accurate quoting
**Story ID:** story-15

### Test Case: Validate real-time quote update on rating response
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as Quoting Specialist with valid credentials
- Quoting module UI is accessible and loaded
- Rating engine API is available and responding
- User has necessary role-based permissions to create quotes
- Test quote data is prepared with valid inputs

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the quote creation page in the Quoting module UI | Quote creation page loads successfully with all input fields visible |
| 2 | Enter valid quote data including customer information, product details, coverage amounts, and risk factors | All quote data fields accept input without validation errors |
| 3 | Click the Submit or Calculate Quote button to send data to rating engine | Quote data is successfully sent to rating engine via POST /api/rate endpoint and loading indicator appears |
| 4 | Observe the UI while rating engine processes the request | Status indicator shows 'Calculating' or 'Processing' state during rating calculation |
| 5 | Wait for rating engine response to be received by the system | Rating response is received from the rating engine within 2 seconds |
| 6 | Measure the time between receiving rating response and UI update | Quote price updates on the UI within 1 second of receiving rating engine response |
| 7 | Verify the updated quote display shows the calculated premium amount | Correct price is displayed with proper formatting and currency symbol |
| 8 | Check the status indicator after quote update completes | Status shows 'Complete' or 'Ready' with green indicator or checkmark |
| 9 | Review all quote details including breakdown of premium components if available | All quote information is accurately displayed with correct calculations and status shown |

**Postconditions:**
- Quote is successfully rated and displayed in the UI
- Quote status is set to 'Rated' or 'Complete'
- Quote data is saved in the system for future reference
- User can proceed to submit or adjust the quote

---

### Test Case: Verify error message display on rating failure
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as Quoting Specialist with valid credentials
- Quoting module UI is accessible and loaded
- Test environment allows simulation of rating engine failures
- User has necessary permissions to create and refresh quotes
- Mock or test rating engine is configured to simulate failure scenarios

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the quote creation page in the Quoting module UI | Quote creation page loads successfully |
| 2 | Enter valid quote data in all required fields | Quote data is entered without validation errors |
| 3 | Configure test environment or mock service to simulate rating engine failure response (e.g., 500 error, service unavailable) | Rating engine is set to return failure response |
| 4 | Click Submit or Calculate Quote button to trigger rating request | Quote data is sent to rating engine and system awaits response |
| 5 | Observe the UI when rating engine returns failure response | Descriptive error message is displayed on UI indicating rating failure with clear explanation (e.g., 'Rating service temporarily unavailable. Please try again.') |
| 6 | Verify the error message contains actionable information for the user | Error message is user-friendly, non-technical, and suggests next steps |
| 7 | Locate and click the manual refresh or retry button on the quote page | Manual refresh button is visible and clickable |
| 8 | Click the manual refresh button to retry the rating request | System retries rating request by sending data to rating engine again |
| 9 | Configure rating engine to return successful response for the retry attempt | Rating engine is set to return valid rating response |
| 10 | Observe the UI after successful rating response is received | Error message is removed from the UI and quote price is displayed |
| 11 | Verify the quote display shows correct price and status after successful update | Quote displays accurate premium amount with 'Complete' status and no error messages visible |

**Postconditions:**
- Error handling mechanism is validated
- Manual refresh functionality is confirmed working
- Error messages are cleared after successful retry
- Quote is successfully rated after retry
- System logs contain error and retry events for troubleshooting

---

## Story: As QA Engineer, I want to test the integration with the policy rating engine to achieve reliable and accurate rating results
**Story ID:** story-16

### Test Case: Validate rating accuracy for multiple products
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- QA Engineer has access to test environment
- Rating engine integration is deployed in test environment
- Predefined test data sets are prepared for multiple product types
- Expected rating outputs are documented based on actuarial benchmarks
- API testing tool or automated test framework is configured
- Test data includes various product types (e.g., auto, home, life insurance)

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Prepare test data sets with predefined inputs for Product Type 1 (e.g., Auto Insurance) including all required rating factors | Test data set for Product Type 1 is complete with all necessary input parameters |
| 2 | Send rating request to the rating engine API with Product Type 1 test data using POST /api/rate endpoint | API request is sent successfully and returns HTTP 200 status code |
| 3 | Capture and review the rating response received for Product Type 1 | Rating response contains premium amount, rating factors breakdown, and all expected fields |
| 4 | Compare the received rating result against the expected output documented in actuarial benchmarks for Product Type 1 | Received rating matches expected output with zero discrepancies (within acceptable tolerance if defined) |
| 5 | Prepare test data sets with predefined inputs for Product Type 2 (e.g., Home Insurance) | Test data set for Product Type 2 is complete with all necessary input parameters |
| 6 | Send rating request to the rating engine API with Product Type 2 test data | API request is sent successfully and returns HTTP 200 status code |
| 7 | Capture and review the rating response received for Product Type 2 | Rating response contains accurate premium calculation and all expected data fields |
| 8 | Compare the received rating result against the expected output for Product Type 2 | Received rating matches expected output with no discrepancies found |
| 9 | Repeat steps 5-8 for Product Type 3 and any additional product types in scope | All product types return accurate ratings matching actuarial benchmarks |
| 10 | Compile all test results including input data, received outputs, expected outputs, and comparison results | Comprehensive test results are compiled in structured format |
| 11 | Document test results in the test management system or test report with pass/fail status for each product type | Results are documented for review with all test cases marked as PASS and available for stakeholder review |

**Postconditions:**
- Rating accuracy is validated for all tested product types
- Test results are documented and stored in test repository
- No discrepancies found between actual and expected ratings
- Test evidence is available for audit and compliance purposes
- QA sign-off can be provided for rating accuracy

---

### Test Case: Test system behavior under API timeout
- **ID:** tc-004
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- QA Engineer has access to test environment with admin privileges
- Rating engine API integration is deployed and accessible
- Test environment allows simulation of timeout scenarios
- Mock service or network delay tool is configured to simulate timeouts
- System logs are accessible for verification
- Retry mechanism is implemented in the system
- User interface is available to observe error notifications

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Configure the test environment or mock rating engine to simulate API timeout scenario (e.g., delay response beyond timeout threshold of 30 seconds) | Test environment is configured to cause timeout when rating request is made |
| 2 | Prepare valid test quote data with all required rating parameters | Test data is ready with valid inputs for rating request |
| 3 | Send rating request to the API endpoint POST /api/rate with the test data | Rating request is sent to the API and system waits for response |
| 4 | Monitor the system behavior when API timeout occurs after the configured timeout period | System detects the timeout condition and triggers retry mechanism automatically |
| 5 | Verify that the retry mechanism attempts to resend the rating request | System initiates retry attempt as per configured retry policy (e.g., 3 retry attempts with exponential backoff) |
| 6 | Navigate to the user interface where the quote is being processed | UI is accessible and shows quote in processing state |
| 7 | Observe the error notification displayed to the user after timeout and retry attempts | Appropriate error message is displayed such as 'Rating service is taking longer than expected. Please try again later.' or similar user-friendly notification |
| 8 | Verify the error message provides clear guidance and does not expose technical details | Error notification is user-friendly, non-technical, and provides actionable guidance |
| 9 | Access system logs or application logs to check for timeout event entries | System logs are accessible and contain relevant timeout entries |
| 10 | Search logs for timeout event with timestamp, request details, and error information | Timeout event is logged with complete details including timestamp, request ID, endpoint, timeout duration, and error code |
| 11 | Verify log entry contains sufficient information for troubleshooting including retry attempts | Log entry includes all necessary details such as original request, retry attempts count, and final failure status |
| 12 | Review that no sensitive data is exposed in error messages or logs | Error messages and logs do not contain sensitive customer or system information |

**Postconditions:**
- Timeout handling mechanism is validated and working correctly
- Retry mechanism is confirmed to trigger on timeout
- Error notifications are user-friendly and informative
- System logs contain complete timeout event details for troubleshooting
- Test results are documented with evidence of timeout handling
- System gracefully handles timeout scenarios without crashes or data corruption

---

## Story: As Business Analyst, I want to analyze rating engine integration requirements to achieve comprehensive documentation and stakeholder alignment
**Story ID:** story-19

### Test Case: Verify completeness of requirements documentation
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 30 mins

**Preconditions:**
- Business Requirements Document (BRD) has been created and is accessible
- User has appropriate access rights to view BRD documentation
- Integration requirements gathering phase has been completed
- Stakeholder interviews have been conducted

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the Business Requirements Document repository and open the latest version of the rating engine integration BRD | BRD document opens successfully and displays the table of contents with all sections visible |
| 2 | Review the functional requirements section of the BRD for integration requirements | All functional requirements are documented with clear descriptions, requirement IDs, and acceptance criteria. Each requirement includes purpose, scope, and business value |
| 3 | Review the non-functional requirements section including performance, security, scalability, and availability requirements | All non-functional requirements are present with measurable criteria and specific thresholds defined (e.g., response time < 2 seconds, 99.9% uptime) |
| 4 | Navigate to the dependencies section and check documentation for system dependencies, data dependencies, and external service dependencies | All dependencies are clearly identified with dependency type, description, impact analysis, and mitigation strategies documented |
| 5 | Review the constraints section for technical, business, regulatory, and resource constraints | All constraints are documented with constraint type, description, and impact on implementation clearly stated |
| 6 | Navigate to the stakeholder sign-off section and verify approval documentation | Sign-off documents are available showing approval from all key stakeholders including Business Owner, Technical Lead, Security Team, and Compliance Officer with dates and signatures |
| 7 | Check the document version history and change log | Version history is complete with all revisions tracked, including date, author, and summary of changes |

**Postconditions:**
- Requirements documentation completeness has been verified
- Any gaps or missing information have been identified and documented
- Verification results are recorded for audit purposes

---

### Test Case: Validate requirement change management process
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 25 mins

**Preconditions:**
- Requirements change management system is accessible and operational
- User has permissions to submit and review change requests
- At least one approved requirement exists in the BRD
- Change request template and workflow are defined

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Access the requirements change management system and navigate to the 'Submit Change Request' section | Change request submission form is displayed with all required fields visible (Requirement ID, Change Description, Justification, Impact Analysis, Priority) |
| 2 | Select an existing requirement from the BRD (e.g., REQ-INT-001) and fill in the change request form with: Change Description: 'Update API response time from 2 seconds to 1 second', Justification: 'Business requirement for improved user experience', Impact: 'Medium', Priority: 'High' | All fields accept input correctly and validation messages appear for any required fields if left empty |
| 3 | Attach supporting documentation (business justification document) and submit the change request | System displays confirmation message 'Change Request CR-2024-001 has been successfully submitted' and assigns a unique change request ID |
| 4 | Navigate to the change request tracking dashboard and search for the newly submitted change request using the CR ID | Change request is displayed in the tracking system with status 'Pending Review', submission date, submitter name, and all entered details are accurately reflected |
| 5 | Verify that automated notifications were sent to designated reviewers (Technical Lead, Business Owner) | Email notifications are logged in the system showing notification sent to all required reviewers with timestamp |
| 6 | As a reviewer, access the change request and add review comments: 'Technical feasibility confirmed. Requires infrastructure upgrade.' | Comments are saved successfully and timestamp with reviewer name is recorded |
| 7 | Update the change request status to 'Approved' and provide approval justification | Change request status updates to 'Approved', approval date and approver details are recorded, and status change is reflected in the tracking dashboard |
| 8 | Submit another change request and update its status to 'Rejected' with rejection reason: 'Does not align with current business priorities' | Change request status updates to 'Rejected', rejection reason is saved, and submitter receives notification of rejection with reason |
| 9 | Generate a change request summary report for all submitted change requests | Report displays all change requests with their current status, submission date, review date, and decision outcome in a clear tabular format |

**Postconditions:**
- Change requests are logged and tracked in the system
- Change request statuses reflect the review decisions
- Audit trail of all change management activities is maintained
- Approved changes are ready for implementation planning

---

## Story: As System Administrator, I want to manage access controls for rating engine integration components to achieve secure and compliant operations
**Story ID:** story-20

### Test Case: Verify role-based access enforcement
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 20 mins

**Preconditions:**
- Role-Based Access Control (RBAC) system is configured and operational
- At least two user accounts exist: one with 'Integration_Admin' role (authorized) and one with 'Read_Only' role (unauthorized)
- Rating engine API endpoints are deployed and accessible
- Test API endpoint '/api/rating-engine/config' requires 'Integration_Admin' role
- Access logging is enabled and functioning
- Valid authentication tokens are available for both test users

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Authenticate as user 'admin_user01' with 'Integration_Admin' role and obtain authentication token | Authentication successful, valid JWT token is returned with role 'Integration_Admin' embedded in claims |
| 2 | Send GET request to protected API endpoint '/api/rating-engine/config' using the authorized user's authentication token in the Authorization header | HTTP 200 OK response is returned with configuration data in JSON format. Response includes rating engine configuration parameters |
| 3 | Verify the response payload contains expected configuration data fields (engine_version, rate_tables, calculation_rules) | All expected configuration fields are present and populated with valid data |
| 4 | Authenticate as user 'readonly_user01' with 'Read_Only' role and obtain authentication token | Authentication successful, valid JWT token is returned with role 'Read_Only' embedded in claims |
| 5 | Send GET request to the same protected API endpoint '/api/rating-engine/config' using the unauthorized user's authentication token | HTTP 403 Forbidden response is returned with error message: 'Access Denied: Insufficient permissions to access this resource. Required role: Integration_Admin' |
| 6 | Verify that no configuration data is returned in the error response payload | Response body contains only error details without exposing any sensitive configuration information |
| 7 | Access the system access logs dashboard and filter logs for the API endpoint '/api/rating-engine/config' for the last 10 minutes | Access logs dashboard displays filtered results showing recent access attempts to the specified endpoint |
| 8 | Verify the log entry for the authorized user's successful access attempt | Log entry shows: Timestamp (within last 10 minutes), User ID 'admin_user01', Role 'Integration_Admin', Endpoint '/api/rating-engine/config', HTTP Method 'GET', Status Code '200', IP Address, and Session ID |
| 9 | Verify the log entry for the unauthorized user's denied access attempt | Log entry shows: Timestamp (within last 10 minutes), User ID 'readonly_user01', Role 'Read_Only', Endpoint '/api/rating-engine/config', HTTP Method 'GET', Status Code '403', IP Address, Session ID, and Denial Reason 'Insufficient permissions' |
| 10 | Export the access log entries for both attempts in CSV format | CSV file is generated successfully containing both log entries with all required fields in structured format |

**Postconditions:**
- Access control enforcement has been verified for both authorized and unauthorized scenarios
- All access attempts are logged with complete details
- No unauthorized access to sensitive endpoints occurred
- Audit trail is maintained for compliance review

---

### Test Case: Validate access review reporting
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 35 mins

**Preconditions:**
- Access logging system has been operational for at least one month
- Historical access data exists for the last 30 days
- User has 'System_Administrator' role with permissions to generate access reports
- Access review reporting module is configured and accessible
- At least 50 access events have been logged in the past month across different users and endpoints

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in to the system administration portal with System Administrator credentials | Successfully logged in and administration dashboard is displayed with 'Access Review Reports' menu option visible |
| 2 | Navigate to 'Access Review Reports' section and select 'Generate Monthly Access Report' option | Report generation form is displayed with date range selector, filter options, and report format selection |
| 3 | Set the report parameters: Date Range: 'Last Month' (auto-populates to previous calendar month), Include: 'All Users', 'All Endpoints', 'All Access Types', Report Format: 'PDF with Summary' | All parameters are set correctly and validation shows no errors. Date range displays specific start and end dates |
| 4 | Click 'Generate Report' button and wait for report processing | Progress indicator shows report generation in progress. After processing (30-60 seconds), success message appears: 'Access Report Generated Successfully' with download link |
| 5 | Download and open the generated access report PDF | PDF report opens successfully and displays report header with: Report Title 'Monthly Access Review Report', Date Range, Generation Date, Generated By (admin username) |
| 6 | Review the Executive Summary section of the report | Summary section includes: Total Access Events count, Unique Users count, Successful Access count, Failed Access count, Top 5 Most Accessed Endpoints, Access by Role breakdown (pie chart), and Access Trend graph (daily access over the month) |
| 7 | Review the Detailed Access Events section showing all access events in tabular format | Table includes columns: Timestamp, User ID, User Name, Role, Endpoint, HTTP Method, Status Code, IP Address, Session ID, and Duration. All entries are sorted by timestamp (most recent first) |
| 8 | Navigate to the 'Anomalies and Security Alerts' section of the report | Section displays identified anomalies including: Multiple failed login attempts (threshold: >5 failures in 1 hour), After-hours access (access between 10 PM - 6 AM), Access from unusual IP addresses, Privilege escalation attempts, and Unusual access patterns |
| 9 | Review flagged anomaly: 'User readonly_user02 attempted to access admin endpoint 15 times with 403 errors on 2024-01-15' | Anomaly entry shows: Severity Level 'High', User Details, Timestamp Range, Endpoint Attempted, Number of Attempts, Status Codes, and Recommended Action 'Investigate potential unauthorized access attempt and review user permissions' |
| 10 | Check the 'Compliance Summary' section at the end of the report | Compliance section shows: RBAC Enforcement Rate (100% expected), Access Logging Coverage (100% expected), Policy Violations count, and Compliance Status 'Compliant' or 'Non-Compliant' with details |
| 11 | Export the detailed access events data in CSV format using the 'Export to CSV' option | CSV file downloads successfully containing all access events with same columns as PDF report, suitable for further analysis in spreadsheet applications |
| 12 | Verify report archival by checking the 'Report History' section | Generated report appears in Report History with generation date, report type, date range covered, generated by user, and download link for future reference |

**Postconditions:**
- Monthly access report has been successfully generated and reviewed
- Anomalies have been identified and flagged for investigation
- Report is archived in the system for compliance and audit purposes
- CSV export is available for detailed analysis
- Follow-up actions for identified anomalies are documented

---

