@edge-cases @boundary
Feature: As API Consumer, I want to perform insurance quote initiation via API to achieve seamless system integration - Edge Case Tests
  As a user
  I want to test edge case tests
  So that I can ensure quality and reliability

  Background:
    Given the system is ready for testing
    And the test environment is properly configured

  @medium @tc-edge-001
  Scenario: TC-EDGE-001 - Test API behavior with minimum valid coverageAmount boundary value
    Given valid OAuth2 access token is obtained
    And business rules define minimum coverageAmount (e.g., $1 or $1000)
    And aPI validation enforces minimum coverage limits
    And database can store minimum value amounts
    When send POST request to /api/quotes with coverageAmount=1 (minimum possible value): customerName='Min Coverage Test', email='min.coverage@example.com', phoneNumber='555-0001', insuranceType='Auto', coverageAmount=1, effectiveDate='2024-02-01'
    Then aPI either returns 201 Created accepting the minimum value, OR returns 400 Bad Request with error: {field='coverageAmount', message='coverageAmount must be at least $1000'} if business minimum is higher
    And if minimum is $1000, send POST request with coverageAmount=1000: customerName='Exact Min Test', email='exact.min@example.com', phoneNumber='555-0002', insuranceType='Home', coverageAmount=1000, effectiveDate='2024-02-01'
    Then aPI returns 201 Created with quoteReferenceId and coverageAmount=1000 in response
    And send POST request with coverageAmount=999 (one below minimum): customerName='Below Min Test', email='below.min@example.com', phoneNumber='555-0003', insuranceType='Life', coverageAmount=999, effectiveDate='2024-02-01'
    Then aPI returns 400 Bad Request with error: {field='coverageAmount', message='coverageAmount must be at least $1000'}
    And minimum boundary value is correctly validated and enforced
    And quotes at exact minimum threshold are accepted
    And quotes below minimum are rejected with clear error message
    And business rules for minimum coverage are properly implemented

  @medium @tc-edge-002
  Scenario: TC-EDGE-002 - Validate API handling of maximum valid coverageAmount boundary value
    Given valid OAuth2 access token is obtained
    And business rules define maximum coverageAmount (e.g., $10,000,000)
    And database numeric field can store maximum value without overflow
    And aPI validation enforces maximum coverage limits
    When send POST request to /api/quotes with coverageAmount=10000000 (maximum allowed): customerName='Max Coverage Test', email='max.coverage@example.com', phoneNumber='555-0004', insuranceType='Life', coverageAmount=10000000, effectiveDate='2024-02-01'
    Then aPI returns 201 Created with quoteReferenceId and coverageAmount=10000000 correctly stored and returned in response
    And send POST request with coverageAmount=10000001 (one above maximum): customerName='Above Max Test', email='above.max@example.com', phoneNumber='555-0005', insuranceType='Life', coverageAmount=10000001, effectiveDate='2024-02-01'
    Then aPI returns 400 Bad Request with error: {field='coverageAmount', message='coverageAmount cannot exceed $10,000,000'}
    And query database for the successfully created quote with coverageAmount=10000000
    Then database record shows coverageAmount stored as 10000000 with correct numeric precision and no data truncation
    And maximum boundary value is correctly validated and enforced
    And quotes at exact maximum threshold are accepted and stored properly
    And quotes above maximum are rejected with clear error message
    And database handles large numeric values without overflow or precision loss

  @medium @tc-edge-003
  Scenario: TC-EDGE-003 - Test API with effectiveDate set to current date (today) as boundary condition
    Given valid OAuth2 access token is obtained
    And system date and time are accurate and synchronized
    And business rules allow effectiveDate to be current date or future dates only
    And aPI validates effectiveDate against current date
    When get current date in ISO 8601 format (e.g., '2024-01-15' if today is January 15, 2024)
    Then current date is captured in YYYY-MM-DD format
    And send POST request to /api/quotes with effectiveDate set to current date: customerName='Today Date Test', email='today@example.com', phoneNumber='555-0006', insuranceType='Auto', coverageAmount=50000, effectiveDate='2024-01-15'
    Then aPI returns 201 Created accepting current date as valid effectiveDate, with quoteReferenceId and status='pending'
    And send POST request with effectiveDate set to yesterday (one day in past): customerName='Past Date Test', email='past@example.com', phoneNumber='555-0007', insuranceType='Home', coverageAmount=200000, effectiveDate='2024-01-14'
    Then aPI returns 400 Bad Request with error: {field='effectiveDate', message='effectiveDate cannot be in the past. Must be today or a future date.'}
    And current date is accepted as valid effectiveDate boundary
    And past dates are rejected preventing backdated policies
    And date validation correctly compares against system current date
    And business rules for policy effective dates are enforced

  @medium @tc-edge-004
  Scenario: TC-EDGE-004 - Verify API handles extremely long string values in text fields approaching character limits
    Given valid OAuth2 access token is obtained
    And database schema defines maximum character lengths for text fields (e.g., customerName VARCHAR(255))
    And aPI validation enforces maximum length constraints
    And test data with strings of various lengths is prepared
    When send POST request to /api/quotes with customerName containing exactly 255 characters (maximum allowed): customerName='A' repeated 255 times, email='long.name@example.com', phoneNumber='555-0008', insuranceType='Auto', coverageAmount=50000, effectiveDate='2024-02-01'
    Then aPI returns 201 Created with quoteReferenceId and the full 255-character customerName is stored and returned in response
    And send POST request with customerName containing 256 characters (one over limit): customerName='B' repeated 256 times, email='toolong@example.com', phoneNumber='555-0009', insuranceType='Home', coverageAmount=100000, effectiveDate='2024-02-01'
    Then aPI returns 400 Bad Request with error: {field='customerName', message='customerName cannot exceed 255 characters'}
    And query database for the successfully created quote and verify full customerName is stored without truncation
    Then database record contains complete 255-character customerName with no data loss or truncation
    And maximum character length boundaries are enforced for text fields
    And data at exact maximum length is accepted and stored completely
    And data exceeding maximum length is rejected with clear error
    And no silent truncation occurs that could cause data integrity issues

  @medium @tc-edge-005
  Scenario: TC-EDGE-005 - Test API behavior with special characters and Unicode in text fields
    Given valid OAuth2 access token is obtained
    And database supports UTF-8 encoding for international characters
    And aPI accepts and properly encodes special characters
    And test data includes various special character sets
    When send POST request to /api/quotes with customerName containing special characters and accents: customerName='José María O'Brien-Smith', email='special.chars@example.com', phoneNumber='555-0010', insuranceType='Auto', coverageAmount=50000, effectiveDate='2024-02-01'
    Then aPI returns 201 Created with quoteReferenceId and customerName='José María O'Brien-Smith' is correctly stored and returned with all special characters preserved
    And send POST request with customerName containing Unicode characters (emoji and non-Latin scripts): customerName='李明 🏠 Insurance', email='unicode@example.com', phoneNumber='555-0011', insuranceType='Home', coverageAmount=150000, effectiveDate='2024-02-01'
    Then aPI returns 201 Created and customerName='李明 🏠 Insurance' is correctly stored with Unicode characters preserved, or returns 400 Bad Request if Unicode is not supported with clear error message
    And query database for both created quotes and verify special characters and Unicode are stored correctly
    Then database records show customerName values with all special characters, accents, and Unicode properly stored without corruption or encoding issues
    And special characters and accents are properly handled and stored
    And unicode support is either functional or clearly rejected with error
    And character encoding is consistent throughout API and database
    And international customer names are supported for global operations

  @high @tc-edge-006
  Scenario: TC-EDGE-006 - Validate API performance and behavior under high concurrent request load
    Given valid OAuth2 access tokens are obtained for multiple concurrent clients
    And load testing tool is configured to send concurrent requests
    And aPI infrastructure is running with normal resource allocation
    And database connection pool is configured with sufficient connections
    When configure load testing tool to send 50 concurrent POST requests to /api/quotes with unique valid payloads (different customerName and email for each)
    Then load testing tool is ready to execute concurrent requests
    And execute 50 concurrent POST requests simultaneously and monitor response times and status codes
    Then all 50 requests return either 201 Created or 429 Too Many Requests (if rate limiting is active), with no 500 Internal Server Error responses
    And verify that at least 95% of successful requests (201 Created) have response times under 500ms
    Then 95% or more of successful requests complete within 500ms SLA, meeting performance requirements under load
    And query database to verify all quotes with 201 Created responses were successfully persisted
    Then database contains quote records for all requests that received 201 Created status, with no data loss or corruption
    And aPI maintains performance SLA under concurrent load conditions
    And no data corruption or race conditions occur with simultaneous requests
    And rate limiting (if implemented) properly throttles excessive requests
    And system remains stable and responsive under stress

  @low @tc-edge-007
  Scenario: TC-EDGE-007 - Test API with empty string values versus null values for optional fields
    Given valid OAuth2 access token is obtained
    And aPI has optional fields in addition to required fields
    And database schema allows null values for optional fields
    And aPI distinguishes between empty strings and null values
    When send POST request to /api/quotes with optional field 'middleName' set to empty string: customerName='Empty String Test', middleName='', email='empty.string@example.com', phoneNumber='555-0012', insuranceType='Auto', coverageAmount=50000, effectiveDate='2024-02-01'
    Then aPI returns 201 Created and middleName is stored as empty string '' in database, or returns 400 Bad Request if empty strings are not allowed
    And send POST request to /api/quotes with optional field 'middleName' omitted entirely (null): customerName='Null Test', email='null.test@example.com', phoneNumber='555-0013', insuranceType='Home', coverageAmount=100000, effectiveDate='2024-02-01'
    Then aPI returns 201 Created and middleName is stored as NULL in database
    And query database for both quotes and compare how middleName is stored (empty string vs NULL)
    Then database clearly distinguishes between empty string '' and NULL values for optional fields, maintaining semantic difference
    And aPI consistently handles empty strings and null values for optional fields
    And database storage correctly represents the difference between empty and null
    And aPI behavior is documented and predictable for optional field handling
    And data semantics are preserved for downstream processing

