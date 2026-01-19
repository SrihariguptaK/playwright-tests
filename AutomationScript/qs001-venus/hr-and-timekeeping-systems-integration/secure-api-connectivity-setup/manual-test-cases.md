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
- Valid OAuth client credentials (client_id and client_secret) are registered in the system
- /oauth/token endpoint is accessible
- At least one secured API endpoint is available for testing
- Test environment has network connectivity to the API server
- Logging system is enabled and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Submit valid client credentials (client_id and client_secret) to /oauth/token endpoint using POST request with grant_type=client_credentials | System responds with HTTP 200 OK status code and returns a JSON response containing a valid access_token, token_type (Bearer), expires_in value, and timestamp |
| 2 | Extract the access token from the response and include it in the Authorization header as 'Bearer {access_token}' when calling a secured API endpoint | API request is successfully authorized, system responds with HTTP 200 OK, and the requested data or operation is processed and returned correctly |
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
- At least one secured API endpoint is available for testing
- API endpoints are configured to require OAuth 2.0 authentication
- Logging system is enabled and operational
- Test environment has network connectivity to the API server

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Send a request to a secured API endpoint without including the Authorization header or access token | System responds with HTTP 401 Unauthorized status code and returns an error message indicating authentication is required (e.g., 'Authorization token required' or 'Unauthorized access') |
| 2 | Query the authentication logs for the recent unauthorized access attempt using the timestamp and endpoint path as search criteria | Unauthorized access attempt is logged with timestamp, requested endpoint, HTTP 401 response code, IP address of the requesting client, and indication of missing authentication token |

**Postconditions:**
- No API data is exposed or processed
- Unauthorized access attempt is logged in security logs
- System security state remains intact
- No session or token is created

---

### Test Case: Reject API request with expired token
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- OAuth 2.0 authentication system is deployed and running
- Valid OAuth client credentials are available
- An access token has been previously issued and has expired (either wait for natural expiration or use a token with modified expiry)
- At least one secured API endpoint is available for testing
- Logging system is enabled and operational
- System clock is synchronized and accurate

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Include the expired access token in the Authorization header as 'Bearer {expired_token}' and send a request to a secured API endpoint | System validates the token, detects expiration, responds with HTTP 401 Unauthorized status code, and returns an error message indicating token expiry (e.g., 'Token has expired' or 'Access token is no longer valid') |

**Postconditions:**
- Expired token is rejected and not honored
- Token expiration event is logged in authentication logs
- No API data is exposed or processed
- Client must request a new token to regain access

---

## Story: As Security Analyst, I want to ensure all API data transmissions are encrypted to achieve data privacy
**Story ID:** story-14

### Test Case: Verify API endpoints accept HTTPS connections only
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- API server is deployed and running with TLS/SSL configured
- Valid SSL/TLS certificate is installed on the server
- API endpoints are accessible via both HTTP and HTTPS protocols for testing
- Test client has network connectivity to the API server
- Logging system is enabled and operational
- DNS or host configuration allows access to the API server domain

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Send an API request to any /api/* endpoint using HTTPS protocol (https://server/api/endpoint) with valid request parameters | TLS handshake completes successfully, request is accepted by the server, system responds with appropriate HTTP status code (200, 201, etc.), and requested data or operation is processed and returned over encrypted connection |
| 2 | Send an API request to the same /api/* endpoint using HTTP protocol (http://server/api/endpoint) with valid request parameters | Request is rejected by the server, system responds with HTTP 400 Bad Request, HTTP 403 Forbidden, or connection refused error, and error message clearly indicates HTTPS is required (e.g., 'HTTPS connection required' or 'Insecure connection not allowed') |

**Postconditions:**
- HTTPS connection is established and logged
- HTTP connection attempt is rejected and logged
- No sensitive data is transmitted over unencrypted connection
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
- Test client or tool capable of specifying TLS version (e.g., OpenSSL, curl with --tlsv options) is available
- Valid SSL/TLS certificate is installed on the server
- API endpoints are accessible for testing
- Logging system is enabled and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Attempt to establish a connection to an API endpoint using TLS 1.1 or lower protocol version (e.g., using curl --tlsv1.1 or OpenSSL with -tls1_1 flag) | TLS handshake fails, connection is rejected by the server, client receives connection error or SSL/TLS protocol version mismatch error, and no data transmission occurs |
| 2 | Attempt to establish a connection to the same API endpoint using TLS 1.2 or higher protocol version (e.g., using curl --tlsv1.2 or OpenSSL with -tls1_2 flag) | TLS handshake completes successfully, connection is accepted by the server, secure encrypted channel is established, and API endpoint responds normally to requests |

**Postconditions:**
- TLS 1.2+ connection is established and logged with encryption details
- TLS 1.1 or lower connection attempt is rejected and logged
- Server maintains security compliance with TLS version requirements
- Connection security status is recorded in logs

---

