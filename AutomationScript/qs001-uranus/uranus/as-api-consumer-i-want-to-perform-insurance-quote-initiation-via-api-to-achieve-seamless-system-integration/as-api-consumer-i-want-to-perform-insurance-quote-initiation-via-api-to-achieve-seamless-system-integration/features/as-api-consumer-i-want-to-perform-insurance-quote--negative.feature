@negative @error-handling
Feature: As API Consumer, I want to perform insurance quote initiation via API to achieve seamless system integration - Negative Tests
  As a user
  I want to test negative tests
  So that I can ensure quality and reliability

  Background:
    Given the system is ready for testing
    And the test environment is properly configured

  @high @tc-nega-001
  Scenario: TC-NEGA-001 - Verify API rejects requests without OAuth2 authentication token with 401 Unauthorized
    Given aPI gateway is running and enforcing authentication
    And no OAuth2 token is included in the request
    And aPI endpoint /api/quotes is accessible
    And security middleware is properly configured
    When send POST request to /api/quotes without Authorization header and with valid quote payload: customerName='Test User', email='test@example.com', phoneNumber='555-0000', insuranceType='Auto', coverageAmount=50000, effectiveDate='2024-02-01'
    Then aPI returns 401 Unauthorized status code with JSON error response containing error code 'UNAUTHORIZED', message='Authentication required. Please provide a valid OAuth2 token.', and timestamp
    And verify the response headers include WWW-Authenticate header with value 'Bearer realm="API"'
    Then response contains WWW-Authenticate='Bearer realm="API"' header indicating OAuth2 Bearer token authentication is required
    And query database for any quote records with customerName='Test User' and email='test@example.com'
    Then no quote record is created in database, confirming request was rejected before processing
    And no quote is created in the system due to authentication failure
    And security audit log records the unauthorized access attempt with timestamp and source IP
    And aPI maintains security posture by rejecting unauthenticated requests
    And clear error message guides API consumer to provide authentication

  @high @tc-nega-002
  Scenario: TC-NEGA-002 - Confirm API rejects requests with expired OAuth2 token with 401 Unauthorized
    Given oAuth2 token was previously generated and has expired (past expires_in time)
    And expired token is available for testing: 'expired_token_xyz123'
    And aPI gateway validates token expiration timestamps
    And system clock is synchronized and accurate
    When send POST request to /api/quotes with Authorization header 'Bearer expired_token_xyz123' and valid quote payload: customerName='Expired Token Test', email='expired@example.com', phoneNumber='555-9999', insuranceType='Home', coverageAmount=200000, effectiveDate='2024-03-01'
    Then aPI returns 401 Unauthorized with JSON error response containing error code 'TOKEN_EXPIRED', message='The provided OAuth2 token has expired. Please obtain a new token.', and timestamp
    And verify the error response includes additional field 'tokenExpiredAt' with the expiration timestamp of the token
    Then response JSON contains tokenExpiredAt field showing when the token expired, helping API consumer understand the timing
    And query database to confirm no quote was created
    Then no quote record exists in database with email='expired@example.com', confirming request was properly rejected
    And expired token is rejected and no quote is created
    And security log records the expired token usage attempt
    And aPI consumer receives clear guidance to refresh their token
    And system maintains temporal security controls

  @high @tc-nega-003
  Scenario: TC-NEGA-003 - Validate API returns 400 Bad Request with descriptive errors when required fields are missing
    Given valid OAuth2 access token is obtained
    And aPI endpoint /api/quotes is accessible
    And input validation rules are configured for all required fields
    And required fields are: customerName, email, phoneNumber, insuranceType, coverageAmount, effectiveDate
    When send POST request to /api/quotes with valid OAuth2 token but payload missing customerName field: {email='missing.name@example.com', phoneNumber='555-1111', insuranceType='Auto', coverageAmount=50000, effectiveDate='2024-02-01'}
    Then aPI returns 400 Bad Request with JSON error response containing error code 'VALIDATION_ERROR', message='Request validation failed', and errors array with entry: {field='customerName', message='customerName is required and cannot be empty'}
    And send POST request to /api/quotes with valid OAuth2 token but payload missing multiple required fields: {customerName='John Doe', insuranceType='Auto'}
    Then aPI returns 400 Bad Request with errors array containing multiple validation errors: {field='email', message='email is required and cannot be empty'}, {field='phoneNumber', message='phoneNumber is required and cannot be empty'}, {field='coverageAmount', message='coverageAmount is required and cannot be empty'}, {field='effectiveDate', message='effectiveDate is required and cannot be empty'}
    And verify no quote records were created in database for either request
    Then database contains no quote records with email='missing.name@example.com' or customerName='John Doe' from these failed requests
    And invalid requests are rejected before database operations
    And aPI consumer receives specific field-level error messages for correction
    And data integrity is maintained by preventing incomplete records
    And validation errors are logged for monitoring and debugging

  @high @tc-nega-004
  Scenario: TC-NEGA-004 - Verify API rejects requests with invalid field formats and data types with 400 Bad Request
    Given valid OAuth2 access token is obtained
    And aPI has format validation rules for email, phoneNumber, coverageAmount, effectiveDate
    And type checking is enforced for numeric and date fields
    When send POST request to /api/quotes with invalid email format: customerName='Invalid Email Test', email='notanemail', phoneNumber='555-2222', insuranceType='Auto', coverageAmount=50000, effectiveDate='2024-02-01'
    Then aPI returns 400 Bad Request with error: {field='email', message='email must be a valid email address format'}
    And send POST request to /api/quotes with invalid coverageAmount (string instead of number): customerName='Invalid Amount Test', email='invalid.amount@example.com', phoneNumber='555-3333', insuranceType='Home', coverageAmount='fifty thousand', effectiveDate='2024-02-01'
    Then aPI returns 400 Bad Request with error: {field='coverageAmount', message='coverageAmount must be a valid number'}
    And send POST request to /api/quotes with invalid effectiveDate format: customerName='Invalid Date Test', email='invalid.date@example.com', phoneNumber='555-4444', insuranceType='Life', coverageAmount=100000, effectiveDate='02/01/2024'
    Then aPI returns 400 Bad Request with error: {field='effectiveDate', message='effectiveDate must be in ISO 8601 format (YYYY-MM-DD)'}
    And send POST request to /api/quotes with negative coverageAmount: customerName='Negative Amount Test', email='negative@example.com', phoneNumber='555-5555', insuranceType='Auto', coverageAmount=-50000, effectiveDate='2024-02-01'
    Then aPI returns 400 Bad Request with error: {field='coverageAmount', message='coverageAmount must be a positive number greater than 0'}
    And all invalid format requests are rejected with specific error messages
    And no quote records are created in database for any invalid requests
    And aPI maintains data quality by enforcing format and type validation
    And error messages provide clear guidance for API consumers to correct their requests

  @high @tc-nega-005
  Scenario: TC-NEGA-005 - Ensure API rejects requests with invalid or unsupported insuranceType values
    Given valid OAuth2 access token is obtained
    And aPI supports only specific insurance types: Auto, Home, Life, Health
    And business rules enforce insurance type validation
    And database schema has constraints on insuranceType values
    When send POST request to /api/quotes with unsupported insuranceType='Pet': customerName='Pet Insurance Test', email='pet@example.com', phoneNumber='555-6666', insuranceType='Pet', coverageAmount=10000, effectiveDate='2024-02-01'
    Then aPI returns 400 Bad Request with error: {field='insuranceType', message='insuranceType must be one of: Auto, Home, Life, Health'}
    And send POST request to /api/quotes with empty insuranceType='': customerName='Empty Type Test', email='empty.type@example.com', phoneNumber='555-7777', insuranceType='', coverageAmount=50000, effectiveDate='2024-02-01'
    Then aPI returns 400 Bad Request with error: {field='insuranceType', message='insuranceType is required and must be one of: Auto, Home, Life, Health'}
    And send POST request to /api/quotes with case-sensitive variation insuranceType='auto' (lowercase): customerName='Case Test', email='case@example.com', phoneNumber='555-8888', insuranceType='auto', coverageAmount=50000, effectiveDate='2024-02-01'
    Then aPI either accepts 'auto' and normalizes to 'Auto' returning 201 Created, OR returns 400 Bad Request with error indicating exact case matching is required
    And invalid insurance types are rejected preventing unsupported product quotes
    And no quote records are created for unsupported insurance types
    And aPI enforces business rules for supported insurance products
    And error messages clearly list valid insurance type options

  @medium @tc-nega-006
  Scenario: TC-NEGA-006 - Validate API handles malformed JSON payload with 400 Bad Request
    Given valid OAuth2 access token is obtained
    And aPI expects Content-Type='application/json' header
    And jSON parsing middleware is configured
    And error handling for parse errors is implemented
    When send POST request to /api/quotes with valid OAuth2 token and malformed JSON payload with missing closing brace: '{"customerName":"Malformed Test","email":"malformed@example.com"'
    Then aPI returns 400 Bad Request with error code 'INVALID_JSON', message='Request body contains malformed JSON. Please check syntax.', and no field-specific errors
    And send POST request to /api/quotes with valid OAuth2 token and JSON with trailing comma: '{"customerName":"Trailing Comma","email":"trailing@example.com",}'
    Then aPI returns 400 Bad Request with error code 'INVALID_JSON' and message indicating JSON parsing failure
    And send POST request to /api/quotes with valid OAuth2 token but Content-Type='text/plain' and valid JSON in body
    Then aPI returns 400 Bad Request or 415 Unsupported Media Type with error message='Content-Type must be application/json'
    And malformed requests are rejected before processing
    And no database operations are attempted for unparseable requests
    And aPI provides clear error messages for JSON syntax issues
    And system remains stable when receiving malformed input

  @high @tc-nega-007
  Scenario: TC-NEGA-007 - Verify API rejects requests with SQL injection attempts in input fields
    Given valid OAuth2 access token is obtained
    And aPI uses parameterized queries or ORM for database operations
    And input sanitization is implemented
    And security monitoring is active
    When send POST request to /api/quotes with SQL injection in customerName field: customerName='Robert"; DROP TABLE quotes; --', email='sql.injection@example.com', phoneNumber='555-9999', insuranceType='Auto', coverageAmount=50000, effectiveDate='2024-02-01'
    Then aPI either returns 400 Bad Request with validation error for invalid characters in customerName, OR returns 201 Created but safely escapes the input preventing SQL execution
    And if quote was created, query database to verify quotes table still exists and the customerName is stored as literal string 'Robert"; DROP TABLE quotes; --' without executing SQL
    Then database quotes table exists and is not dropped, and if record exists, customerName contains the literal string safely stored
    And verify security audit log contains entry flagging potential SQL injection attempt
    Then security log contains warning or alert entry with timestamp, source IP, and details of the suspicious input pattern
    And sQL injection attempts are neutralized through parameterization or sanitization
    And database integrity is maintained and no malicious SQL is executed
    And security monitoring captures and logs injection attempts
    And aPI remains secure against common injection attacks

