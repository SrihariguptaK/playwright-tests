# Manual Test Cases

## Story: As Integration Engineer, I want to implement OAuth 2.0 authentication to achieve secure API access
**Story ID:** story-13

### Test Case: Validate successful OAuth token issuance with valid client credentials
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- OAuth 2.0 authentication system is deployed and running
- Valid client credentials (client_id and client_secret) are registered in the OAuth client database
- API endpoints are configured to require OAuth authentication
- Test environment has network connectivity to the OAuth server
- Logging system is enabled and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Submit valid client credentials to /oauth/token endpoint using POST request with grant_type=client_credentials, client_id, and client_secret in the request body | System responds with HTTP 200 OK status code and returns a JSON response containing a valid access_token, token_type (Bearer), expires_in value, and timestamp |
| 2 | Extract the access token from the response and use it in the Authorization header (Bearer <access_token>) to call a secured API endpoint (e.g., GET /api/employees) | API request is successfully authorized, system responds with HTTP 200 OK, and returns the requested data without authentication errors |
| 3 | Query the authentication logs for the recent token issuance event using the client_id as search criteria | Authentication event is logged with timestamp, client identifier, successful authentication status, token issuance confirmation, and IP address of the requesting client |

**Postconditions:**
- Valid access token is issued and stored in system
- Authentication event is permanently logged in the system
- Token expiration timer is initiated
- Client session is established and tracked

---

### Test Case: Reject API request without access token
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- OAuth 2.0 authentication system is deployed and running
- API endpoints are configured to require OAuth authentication
- Logging system is enabled and operational
- Test environment has network connectivity to the API server

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Send a GET request to a secured API endpoint (e.g., GET /api/employees) without including the Authorization header or access token | System responds with HTTP 401 Unauthorized status code and returns an error message indicating authentication is required (e.g., 'Missing or invalid authorization token') |
| 2 | Query the authentication logs for the recent unauthorized access attempt using the timestamp and endpoint path as search criteria | Unauthorized access attempt is logged with timestamp, requested endpoint, HTTP 401 response code, reason for rejection (missing token), and source IP address |

**Postconditions:**
- API request is denied and no data is returned
- Unauthorized access attempt is logged in security logs
- No system state changes occur
- Security monitoring system is alerted if configured

---

### Test Case: Reject API request with expired token
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- OAuth 2.0 authentication system is deployed and running
- A valid access token was previously issued and has now expired (past its expires_in duration)
- Expired token is available for testing purposes
- API endpoints are configured to validate token expiration
- Logging system is enabled and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Send a GET request to a secured API endpoint (e.g., GET /api/employees) using the expired access token in the Authorization header (Bearer <expired_token>) | System validates the token, detects expiration, responds with HTTP 401 Unauthorized status code, and returns an error message indicating the token has expired (e.g., 'Access token has expired') |
| 2 | Query the authentication logs for the recent expired token rejection event | Failed authentication attempt is logged with timestamp, client identifier, HTTP 401 response code, reason for rejection (expired token), token expiration time, and source IP address |

**Postconditions:**
- API request is denied and no data is returned
- Expired token rejection is logged in authentication logs
- Client must request a new token to continue API access
- No system state changes occur

---

## Story: As Security Analyst, I want to ensure all API data transmissions are encrypted to achieve data privacy
**Story ID:** story-14

### Test Case: Verify API endpoints accept HTTPS connections only
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- API server is deployed and running with TLS/SSL configuration
- Valid SSL/TLS certificate is installed and configured on the server
- API endpoints are configured to enforce HTTPS-only connections
- Test environment has network connectivity to the API server
- Both HTTPS (port 443) and HTTP (port 80) endpoints are accessible for testing

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Send an API request to a secured endpoint using HTTPS protocol (e.g., https://api.example.com/api/employees) with valid authentication credentials | TLS handshake completes successfully, request is accepted and processed by the server, system responds with HTTP 200 OK status code, and returns the requested data over encrypted connection |
| 2 | Send an API request to the same endpoint using HTTP protocol (e.g., http://api.example.com/api/employees) with valid authentication credentials | Request is rejected by the server, system responds with HTTP 400 Bad Request or HTTP 403 Forbidden status code, and returns an error message indicating HTTPS is required (e.g., 'Secure connection required. Please use HTTPS') |
| 3 | Query the connection logs to verify both connection attempts were recorded with their respective protocols | Logs show the successful HTTPS connection with encryption status and the rejected HTTP connection attempt with rejection reason |

**Postconditions:**
- HTTPS connection is established and data is transmitted securely
- HTTP connection is blocked and no data is transmitted
- Connection attempts are logged with encryption status
- Security policy enforcement is confirmed

---

### Test Case: Verify TLS version enforcement
- **ID:** tc-005
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- API server is deployed with TLS version enforcement configured
- Server is configured to accept only TLS 1.2 or higher
- Test tools capable of specifying TLS versions are available (e.g., OpenSSL, curl with --tlsv options)
- Valid SSL/TLS certificate is installed on the server
- Test environment has network connectivity to the API server

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Attempt to establish a connection to the API endpoint (e.g., https://api.example.com/api/employees) using TLS 1.1 protocol by specifying the TLS version in the connection request (e.g., curl --tlsv1.1 https://api.example.com/api/employees) | TLS handshake fails, connection is rejected by the server, system returns a connection error or SSL/TLS protocol error indicating the TLS version is not supported (e.g., 'SSL alert handshake failure' or 'Protocol version not supported') |
| 2 | Attempt to establish a connection to the same API endpoint using TLS 1.0 protocol by specifying the TLS version in the connection request (e.g., curl --tlsv1.0 https://api.example.com/api/employees) | TLS handshake fails, connection is rejected by the server, system returns a connection error or SSL/TLS protocol error indicating the TLS version is not supported |
| 3 | Attempt to establish a connection to the API endpoint using TLS 1.2 protocol by specifying the TLS version in the connection request (e.g., curl --tlsv1.2 https://api.example.com/api/employees) with valid authentication | TLS handshake completes successfully, connection is accepted, system establishes secure connection and responds with HTTP 200 OK status code |
| 4 | Attempt to establish a connection to the API endpoint using TLS 1.3 protocol by specifying the TLS version in the connection request (e.g., curl --tlsv1.3 https://api.example.com/api/employees) with valid authentication | TLS handshake completes successfully, connection is accepted, system establishes secure connection and responds with HTTP 200 OK status code |
| 5 | Query the connection logs to verify all connection attempts were recorded with their respective TLS versions and outcomes | Logs show rejected connections for TLS 1.0 and 1.1 with rejection reasons, and successful connections for TLS 1.2 and 1.3 with encryption details including cipher suite used |

**Postconditions:**
- TLS 1.2 and higher connections are successfully established
- TLS 1.1 and lower connections are blocked
- All connection attempts are logged with TLS version and status
- TLS version enforcement policy is confirmed operational

---

## Story: As Integration Engineer, I want to log all API access attempts to achieve auditability
**Story ID:** story-15

### Test Case: Verify logging of successful API access
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- API gateway is operational and configured for logging
- Centralized logging system is accessible
- Valid API client credentials are available
- User has authorization to query logs
- Test endpoint is available and responding

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Make authorized API request using valid client credentials to a test endpoint | API request is successfully processed and returns 200 OK status. Access attempt is logged with timestamp, client ID, endpoint path, and success result |
| 2 | Query the centralized logging system for the request using client ID and timestamp | Log entry is found and retrieved successfully within 1 hour of the request |
| 3 | Verify log entry contains all required fields: timestamp, client ID, endpoint, and result status | All fields are present and contain accurate data matching the API request made in step 1 |
| 4 | Verify the logging operation completed within performance requirements | Log timestamp shows logging occurred within 10ms of the API request |

**Postconditions:**
- Log entry is permanently stored in centralized logging system
- Log data is available for future audit queries
- No data integrity issues detected in log entry

---

### Test Case: Verify logging of failed API access
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- API gateway is operational and configured for logging
- Centralized logging system is accessible
- Alert system is configured and operational
- Invalid or expired API client credentials are available for testing
- Security team has access to alert notifications

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Make unauthorized API request using invalid or expired client credentials | API request is rejected with 401 Unauthorized or 403 Forbidden status. Access attempt is logged with timestamp, client ID (if available), endpoint path, and failure status |
| 2 | Query the centralized logging system for the failed request attempt | Log entry is found showing the failed access attempt with failure status and reason for rejection |
| 3 | Check alert system for suspicious activity notification related to the failed access attempt | Alert is generated and sent to security team for review, containing details of the failed access attempt including timestamp, client identifier, and endpoint targeted |
| 4 | Verify the failed attempt log contains complete information for security analysis | Log entry includes all relevant details: timestamp, attempted client ID, endpoint, failure reason, and IP address or source information |

**Postconditions:**
- Failed access attempt is logged and stored securely
- Security alert has been generated and delivered
- Log is available for security team review and investigation
- No unauthorized access was granted

---

## Story: As System Administrator, I want to manage API client credentials to achieve secure access control
**Story ID:** story-22

### Test Case: Verify creation and storage of API client credentials
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- System Administrator is logged into management console with valid credentials
- Administrator has appropriate role-based permissions for credential management
- Credential store is operational and accessible
- Test API endpoint is available for validation
- Secure storage encryption is configured and active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to API client management section in the management console | API client management interface loads successfully showing options to create, view, and manage credentials |
| 2 | Create new API client credentials via management console by providing required client information and submitting the creation request | Credentials are generated successfully within 2 seconds. Client ID and secret are displayed securely. Confirmation message indicates credentials are stored in encrypted format |
| 3 | Verify credentials are stored in the credential store by checking the client list | New API client appears in the client list with active status. Credential details are encrypted and stored securely |
| 4 | Use the newly created credentials to make an API request to a test endpoint | API access is granted successfully with 200 OK response. Authentication succeeds using the new credentials |
| 5 | Verify audit log entry for credential creation | Audit log contains entry showing credential creation with timestamp, administrator ID, and client ID |

**Postconditions:**
- New API client credentials are active and functional
- Credentials are stored securely in encrypted format
- Audit trail exists for credential creation
- Client can successfully authenticate to API

---

### Test Case: Verify credential rotation and revocation
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- System Administrator is logged into management console
- Active API client credentials exist in the system
- Administrator has permissions for credential rotation and revocation
- Test API endpoint is available
- Audit logging is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Select an existing API client from the management console and initiate credential rotation | Rotation process begins and completes within 2 seconds. New credentials are generated and displayed |
| 2 | Verify old credentials are revoked by checking credential status in the management console | Old credentials show as revoked or inactive status. New credentials show as active status |
| 3 | Attempt to make an API request using the revoked (old) credentials | API access is denied with 401 Unauthorized status. Error message indicates credentials are invalid or revoked |
| 4 | Make an API request using the new credentials generated during rotation | API access is granted successfully with 200 OK response. Authentication succeeds with new credentials |
| 5 | Review audit logs for credential rotation activity | Audit log shows credential rotation event with timestamp, administrator ID, client ID, and status change from old to new credentials |

**Postconditions:**
- Old credentials are permanently revoked and cannot be used
- New credentials are active and functional
- Audit trail documents the rotation event
- Client can only authenticate with new credentials

---

### Test Case: Verify access control to credential management
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Credential management console is operational
- Unauthorized user account exists without administrator privileges
- Role-based access control is configured and enforced
- Test user credentials are available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into the system using unauthorized user credentials (non-administrator account) | User successfully logs into the system but does not have administrator role |
| 2 | Attempt to navigate to the credential management section of the management console | Access is denied. User receives error message indicating insufficient permissions or the credential management option is not visible in the interface |
| 3 | Attempt to directly access credential management API endpoint /api/clients without proper authorization | API request is rejected with 403 Forbidden status. Error response indicates user lacks required administrator role |
| 4 | Verify audit log captures the unauthorized access attempt | Audit log contains entry showing unauthorized access attempt with user ID, timestamp, attempted resource, and denial reason |

**Postconditions:**
- Unauthorized user did not gain access to credential management
- Security controls prevented unauthorized access
- Audit trail documents the access denial
- No credentials were exposed or compromised

---

