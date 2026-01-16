# Manual Test Cases

## Story: As Integration Engineer, I want to establish secure API connections to the policy rating engine to achieve reliable real-time data exchange
**Story ID:** story-11

### Test Case: Validate successful API connection with valid credentials
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Policy rating engine API is accessible and running
- Valid OAuth 2.0 credentials are available (client ID and client secret)
- System has network connectivity to rating engine endpoint
- HTTPS endpoint is properly configured with valid SSL/TLS certificates
- Integration Engineer has administrative access to configure API credentials

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to API configuration settings in the system administration panel | API configuration page loads successfully with credential input fields visible |
| 2 | Enter valid OAuth 2.0 client ID in the designated field | Client ID is accepted and displayed in the input field without validation errors |
| 3 | Enter valid OAuth 2.0 client secret in the designated field | Client secret is accepted and masked for security, no validation errors displayed |
| 4 | Click 'Save' or 'Apply' button to store the credentials | Credentials are saved successfully with confirmation message displayed, no errors occur |
| 5 | Initiate API connection to rating engine by clicking 'Test Connection' or triggering automatic connection | System initiates OAuth 2.0 authentication flow and requests access token from authorization server |
| 6 | Monitor the connection establishment process | Connection is established securely over HTTPS (TLS 1.2 or higher) within 1 second, success message displayed |
| 7 | Verify SSL/TLS certificate validation during connection | Certificate is validated successfully with no warnings or errors, secure connection indicator shown |
| 8 | Navigate to connection logs or system logs section | Connection logs are accessible and display recent connection attempts |
| 9 | Locate the most recent connection attempt entry in the logs | Connection attempt is logged with timestamp, status 'SUCCESS', endpoint URL, and authentication method (OAuth 2.0) |
| 10 | Verify connection health monitoring is active | Connection health status shows 'Active' or 'Connected' with uptime metrics displayed |

**Postconditions:**
- API connection to rating engine is established and active
- OAuth 2.0 credentials are securely stored in system configuration
- Connection attempt is logged with success status and timestamp
- System is ready to send rating requests to the policy rating engine
- Connection health monitoring is active and tracking uptime

---

### Test Case: Verify connection retry on failure
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- API connection configuration is completed with valid credentials
- System has retry mechanism configured (maximum 3 retries)
- Network simulation tools or ability to disable network connectivity is available
- Connection logging is enabled and accessible
- Rating engine endpoint is known and configured

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Ensure API connection is initially disconnected or idle | System shows no active connection to rating engine API |
| 2 | Simulate network failure by disabling network connectivity or blocking the rating engine endpoint using firewall rules | Network path to rating engine API is blocked, endpoint is unreachable |
| 3 | Initiate API connection attempt from the system | System attempts to connect to rating engine API endpoint |
| 4 | Observe the initial connection attempt | Connection attempt fails due to network unavailability, timeout error or connection refused error is generated |
| 5 | Monitor system behavior immediately after first failure | System automatically initiates first retry attempt after configured delay (e.g., 2-5 seconds) |
| 6 | Observe the first retry attempt | First retry fails, system waits for configured delay before second retry |
| 7 | Observe the second retry attempt | Second retry fails, system waits for configured delay before third retry |
| 8 | Observe the third and final retry attempt | Third retry fails, system stops retry attempts after reaching maximum retry count of 3 |
| 9 | Verify delay between retry attempts is consistent | Each retry is separated by appropriate delay interval (exponential backoff or fixed delay as configured) |
| 10 | Navigate to error logs or connection logs | Error logs are accessible and contain recent connection failure entries |
| 11 | Check error log entries for the failed connection attempts | Failure is logged with timestamp, error message, retry count (3 retries), and final failure status |
| 12 | Verify error notification or alert is generated | System generates error notification indicating connection failure after maximum retries exhausted |

**Postconditions:**
- Connection to rating engine remains disconnected
- All retry attempts (3 total) are logged with timestamps and failure reasons
- Error notification is generated for monitoring and alerting
- System is in error state awaiting manual intervention or network restoration
- No further automatic retry attempts are made after maximum retries reached

---

### Test Case: Ensure unauthorized access is rejected
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Policy rating engine API is accessible and running
- Invalid or expired OAuth 2.0 credentials are available for testing
- Security monitoring and alerting system is configured and active
- Connection logging is enabled
- System has network connectivity to rating engine endpoint

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to API configuration settings in the system administration panel | API configuration page loads successfully |
| 2 | Enter invalid OAuth 2.0 client ID (e.g., incorrect or non-existent client ID) | Invalid client ID is entered in the configuration field |
| 3 | Enter invalid OAuth 2.0 client secret (e.g., incorrect secret or random string) | Invalid client secret is entered and masked in the configuration field |
| 4 | Save the invalid credentials configuration | Credentials are saved to configuration (validation occurs during connection attempt) |
| 5 | Attempt to initiate API connection to rating engine using the invalid credentials | System initiates OAuth 2.0 authentication flow with invalid credentials |
| 6 | Observe the authentication response from the authorization server | Authentication fails with HTTP 401 Unauthorized or 403 Forbidden error response, error message indicates invalid credentials |
| 7 | Verify error message displayed to the user | Clear error message is displayed indicating authentication failure (e.g., 'Authentication failed: Invalid credentials') |
| 8 | Attempt to send a test request to the rating engine API | No connection is established, request is blocked at authentication layer |
| 9 | Verify that no API access is granted | Connection is denied, no access token is issued, system remains disconnected from rating engine |
| 10 | Navigate to connection logs or security logs | Logs are accessible and contain recent authentication attempt entries |
| 11 | Locate the failed authentication attempt in the logs | Failed authentication attempt is logged with timestamp, status 'FAILED', error code (401/403), and reason 'Invalid credentials' |
| 12 | Check system security alerts or monitoring dashboard | Security alert is generated for unauthorized access attempt with details including timestamp, source, and failure reason |
| 13 | Verify alert is routed to security monitoring system | Alert is visible in security monitoring dashboard for investigation and tracking of unauthorized access attempts |
| 14 | Confirm no sensitive data or API access was granted during failed attempt | Zero unauthorized access incidents recorded, no data breach or unauthorized API calls logged |

**Postconditions:**
- API connection remains disconnected and unauthorized
- Failed authentication attempt is logged with complete details
- Security alert is generated and visible in monitoring system
- No access token is issued or stored
- System maintains security posture with zero unauthorized access incidents
- Invalid credentials remain in configuration for correction by Integration Engineer

---

## Story: As Backend Developer, I want to implement request and response handling for rating engine API to achieve reliable data exchange
**Story ID:** story-12

### Test Case: Validate correct serialization of rating request
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Quoting module database is accessible and contains valid quote data
- API connection to rating engine is established and active
- Rating engine API schema documentation is available for validation
- JSON serialization library is configured in the system
- Sample rating request data is prepared in the quoting module
- API endpoint POST /api/rate is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to quoting module and create or select an existing quote requiring rating | Quote data is loaded successfully with all required fields populated (e.g., coverage type, limits, applicant details) |
| 2 | Verify all required rating request fields are present in the quote data | All mandatory fields for rating request are present and contain valid data matching expected input format |
| 3 | Review the data structure against rating engine API schema requirements | Data structure matches expected input format with correct field names, data types, and required attributes |
| 4 | Trigger the rating request process from the quoting module | System initiates request preparation and serialization process |
| 5 | Monitor the data serialization process | System serializes quote data into JSON format according to rating engine API schema |
| 6 | Capture or log the serialized JSON payload before transmission | JSON payload is generated and logged, contains all required fields in correct format |
| 7 | Validate the JSON payload against the API schema specification | JSON payload matches API schema exactly with correct structure, field names, data types, and no missing required fields |
| 8 | Verify JSON syntax is valid and properly formatted | JSON is syntactically correct with proper brackets, quotes, commas, and no formatting errors |
| 9 | Send the serialized JSON payload to the rating engine API via POST request to /api/rate endpoint | POST request is transmitted successfully over HTTPS with JSON payload in request body |
| 10 | Monitor the API response to the request | Rating engine API receives the request and processes it without errors |
| 11 | Verify API accepts the request without validation errors | API returns HTTP 200 OK or 201 Created status, no schema validation errors or bad request errors (400) are returned |
| 12 | Check transaction logs for request details | Request is logged with timestamp, payload summary, endpoint, and success status |

**Postconditions:**
- Rating request is successfully serialized to valid JSON format
- JSON payload matches rating engine API schema specification
- Request is accepted by rating engine API without errors
- Transaction is logged with complete request details and timestamp
- System is ready to receive and process API response

---

### Test Case: Verify response validation and error handling
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- API connection to rating engine is established and active
- Rating request has been sent to the API
- Response schema validation rules are configured in the system
- Error handling and retry policies are configured
- Transaction logging is enabled
- Test scenarios for both valid and error responses are prepared

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Send a rating request to the API that will return a valid successful response | Request is transmitted successfully to rating engine API |
| 2 | Receive response JSON from the rating engine API with valid data | System receives HTTP 200 OK response with JSON payload containing rating results |
| 3 | Capture the response JSON payload | Response payload is captured and available for validation |
| 4 | Trigger automatic schema validation against expected response schema | System validates response JSON structure, field names, data types, and required fields against schema |
| 5 | Verify validation results for valid response | Response passes schema validation successfully with no errors, all required fields present with correct data types |
| 6 | Verify response data is parsed and extracted correctly | Rating results are extracted from JSON and available for processing (e.g., premium amount, rating factors) |
| 7 | Check transaction logs for successful response processing | Response is logged with timestamp, status 'SUCCESS', and payload summary |
| 8 | Send a rating request that will trigger an API error response (e.g., invalid input data or business rule violation) | Request is transmitted to rating engine API |
| 9 | Receive response JSON from API with error code (e.g., HTTP 400 Bad Request, 422 Unprocessable Entity, or 500 Internal Server Error) | System receives error response with appropriate HTTP status code and error details in JSON payload |
| 10 | Verify system detects the error code in the response | System identifies error status code and extracts error message and details from response payload |
| 11 | Monitor error handling mechanism activation | System triggers error handling workflow based on error type and configured policies |
| 12 | Verify error is logged with complete details | Error is logged with timestamp, error code, error message, request details, and response payload |
| 13 | Check if retry mechanism is activated for retryable errors | For transient errors (e.g., 500, 503), system initiates retry attempt according to retry policy; for non-retryable errors (e.g., 400), no retry is attempted |
| 14 | Verify error notification is generated | Error notification is created and routed to appropriate monitoring system or user notification queue |
| 15 | Confirm response processing time for both scenarios | Both valid and error responses are processed within 1 second under normal load conditions |

**Postconditions:**
- Valid API responses pass schema validation and are processed successfully
- Error responses are detected and trigger appropriate error handling
- All responses (success and error) are logged with timestamps and complete details
- Retry mechanism is activated appropriately based on error type
- Error notifications are generated for monitoring and alerting
- Response processing completes within performance requirements (under 1 second)

---

## Story: As Security Analyst, I want to ensure secure data transmission between quoting module and rating engine to achieve compliance and data protection
**Story ID:** story-17

### Test Case: Verify encrypted API communication
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- Quoting module and rating engine are deployed and operational
- TLS 1.2 or higher is configured on both systems
- Network traffic monitoring tool (e.g., Wireshark) is installed and configured
- Test user has access to system logs
- API endpoints are accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Initiate API request from quoting module to rating engine | Connection is established using TLS 1.2 or higher protocol |
| 2 | Use network monitoring tool to intercept and capture network traffic between quoting module and rating engine | Captured traffic shows encrypted data packets that are unreadable in plain text format |
| 3 | Verify the TLS version in the captured handshake packets | TLS version is 1.2 or higher (1.3) |
| 4 | Access system logs and search for encryption status entries related to the API communication | Logs contain entries confirming TLS encryption is active with protocol version and cipher suite details |
| 5 | Review the API response to confirm successful data transmission | API response is received successfully with expected data payload |

**Postconditions:**
- API communication completed successfully
- All transmitted data was encrypted
- Security logs contain encryption confirmation entries
- No security warnings or alerts generated

---

### Test Case: Test input sanitization against injection attacks
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 20 mins

**Preconditions:**
- Quoting module and rating engine are deployed and operational
- Input validation and sanitization mechanisms are configured
- Security event logging is enabled
- Test user has access to security logs
- OAuth 2.0 authentication is active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Prepare API request with malicious SQL injection payload in input parameters (e.g., ' OR '1'='1) | Malicious payload is prepared for testing |
| 2 | Send the API request containing the malicious SQL injection payload to the rating engine | System rejects the request with appropriate error response (e.g., 400 Bad Request) |
| 3 | Access security event logs and search for entries related to the rejected request | Security log contains entry documenting the injection attempt with timestamp, source, and payload details |
| 4 | Prepare and send API request with XSS (Cross-Site Scripting) payload (e.g., <script>alert('XSS')</script>) | System rejects the request and logs the security event |
| 5 | Verify database and system integrity by checking for any unauthorized data access or modifications | No unauthorized data access occurred, database remains unchanged, system security is intact |
| 6 | Confirm that no data breach indicators are present in system monitoring tools | No breach indicators detected, all security metrics remain normal |

**Postconditions:**
- All malicious inputs were successfully blocked
- Security events are logged with complete details
- System remains secure with no data breaches
- No unauthorized access to sensitive data occurred
- System continues to operate normally

---

## Story: As DevOps Engineer, I want to deploy and monitor the rating engine integration components to achieve high availability and performance
**Story ID:** story-18

### Test Case: Validate automated deployment pipeline
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 25 mins

**Preconditions:**
- CI/CD pipeline is configured and accessible
- Rating engine integration components source code is committed to repository
- Deployment environment (staging/production) is available and ready
- DevOps engineer has necessary permissions to trigger deployment
- All deployment dependencies and configurations are in place

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Access the CI/CD pipeline interface and trigger the deployment pipeline for rating integration components | Pipeline execution starts successfully and shows 'In Progress' status |
| 2 | Monitor the pipeline execution stages (build, test, deploy) in real-time | All pipeline stages complete successfully without errors, showing green/success status |
| 3 | Verify that integration components are deployed to the target environment | Components are deployed successfully with correct version numbers and configurations |
| 4 | Test system functionality by sending a test API request from quoting module to rating engine | API request is processed successfully and returns expected response |
| 5 | Verify all integration services are operational by checking service status endpoints | All services report 'healthy' or 'running' status |
| 6 | Access deployment logs from the CI/CD pipeline | Deployment logs show all steps executed successfully with timestamps, no error messages present |
| 7 | Verify deployment artifacts and configurations are correctly placed in target directories | All files and configurations are in correct locations with proper permissions |

**Postconditions:**
- Rating integration components are successfully deployed
- All services are operational and responding to requests
- Deployment logs are complete and accessible
- System uptime is maintained
- No errors or warnings in deployment process

---

### Test Case: Test monitoring alert on API failure
- **ID:** tc-004
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 20 mins

**Preconditions:**
- Monitoring system is configured and operational
- Health checks are configured for API endpoints
- Alert notifications are configured to DevOps team
- API endpoints are currently healthy and operational
- DevOps engineer has access to monitoring dashboard and alert channels

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Document the current healthy status of the API endpoint in monitoring dashboard | API endpoint shows 'healthy' status with normal response times |
| 2 | Simulate API endpoint failure by stopping the rating engine service or blocking the endpoint | API endpoint becomes unavailable and stops responding to requests |
| 3 | Wait for the health check monitoring cycle to execute (typically 1-2 minutes) | Health check detects the API endpoint failure and marks it as 'unhealthy' or 'down' |
| 4 | Monitor the monitoring dashboard for status change | Dashboard displays API endpoint status as 'failed' or 'critical' with red indicator |
| 5 | Check alert notification channels (email, Slack, PagerDuty, etc.) for alert delivery | Alert notification is received by DevOps team within 5 minutes of failure detection |
| 6 | Verify alert contains necessary details (endpoint name, failure time, error description) | Alert includes complete information needed for troubleshooting |
| 7 | Restore the API endpoint by restarting the service or unblocking the endpoint | API endpoint becomes available and starts responding to requests |
| 8 | Wait for the next health check cycle to execute | Health check detects the restored API endpoint |
| 9 | Verify monitoring dashboard shows healthy status | Dashboard displays API endpoint status as 'healthy' with green indicator, response times return to normal |
| 10 | Check for recovery notification or alert resolution message | Recovery notification is sent confirming the endpoint is back to healthy status |

**Postconditions:**
- API endpoint is restored to healthy status
- Alert was successfully triggered and received within SLA
- Monitoring system correctly detected both failure and recovery
- All events are logged in monitoring system
- System returns to normal operational state

---

