@functional @smoke
Feature: As API Consumer, I want to perform insurance quote initiation via API to achieve seamless system integration - Functional Tests
  As a user
  I want to test functional tests
  So that I can ensure quality and reliability

  Background:
    Given the system is ready for testing
    And the test environment is properly configured

  @high @tc-func-001
  Scenario: TC-FUNC-001 - Verify successful quote creation via API with complete valid payload and OAuth2 authentication
    Given aPI gateway is running and accessible at the base URL
    And valid OAuth2 client credentials are configured and available
    And database is accessible and quote table schema is initialized
    And test environment has network connectivity to API endpoint
    When send POST request to /oauth/token with client_id, client_secret, and grant_type=client_credentials
    Then aPI returns 200 OK with access_token, token_type=Bearer, and expires_in fields in JSON response
    And send POST request to /api/quotes with Authorization header 'Bearer {access_token}' and valid JSON payload containing all required fields: customerName='John Doe', email='john.doe@example.com', phoneNumber='555-1234', insuranceType='Auto', coverageAmount=50000, effectiveDate='2024-02-01'
    Then aPI returns 201 Created status code with JSON response containing quoteReferenceId (format: QT-XXXXXXXX), status='pending', createdAt timestamp, and all submitted quote details
    And query the database quotes table using the returned quoteReferenceId
    Then quote record exists in database with matching customerName='John Doe', email='john.doe@example.com', phoneNumber='555-1234', insuranceType='Auto', coverageAmount=50000, effectiveDate='2024-02-01', and status='pending'
    And verify the response headers include Content-Type='application/json' and Location header with the quote resource URL
    Then response headers contain Content-Type='application/json' and Location='/api/quotes/{quoteReferenceId}'
    And new quote record is persisted in database with unique quoteReferenceId
    And quote status is set to 'pending' awaiting further processing
    And aPI access token remains valid for subsequent requests within expiration time
    And system audit log contains entry for quote creation with timestamp and client identifier

  @high @tc-func-002
  Scenario: TC-FUNC-002 - Validate API response time is under 500ms for quote creation under normal load
    Given aPI gateway and backend services are running with normal system load
    And valid OAuth2 access token is obtained and ready for use
    And performance monitoring tools are configured to measure response times
    And database connection pool has available connections
    When record the current timestamp before sending the request
    Then start timestamp is captured in milliseconds
    And send POST request to /api/quotes with valid OAuth2 token and complete quote payload: customerName='Jane Smith', email='jane.smith@example.com', phoneNumber='555-5678', insuranceType='Home', coverageAmount=250000, effectiveDate='2024-03-15'
    Then aPI processes the request and begins response generation
    And record the timestamp when 201 Created response is fully received
    Then end timestamp is captured in milliseconds
    And calculate the elapsed time (end timestamp - start timestamp)
    Then total API response time is less than 500ms and response contains valid quoteReferenceId and status='pending'
    And quote is successfully created in database within performance SLA
    And response time metric is logged for monitoring and alerting
    And system performance remains stable with no degradation
    And aPI consumer receives timely response enabling real-time integration

  @high @tc-func-003
  Scenario: TC-FUNC-003 - Verify API creates quotes for different insurance types with type-specific validation
    Given valid OAuth2 access token is obtained
    And aPI supports multiple insurance types: Auto, Home, Life, Health
    And database schema supports all insurance type variations
    And business rules for each insurance type are configured
    When send POST request to /api/quotes with insuranceType='Life' and payload: customerName='Robert Johnson', email='robert.j@example.com', phoneNumber='555-9012', coverageAmount=500000, effectiveDate='2024-04-01', beneficiaryName='Mary Johnson'
    Then aPI returns 201 Created with quoteReferenceId starting with 'QT-LIFE-' and status='pending', accepting Life insurance specific field beneficiaryName
    And send POST request to /api/quotes with insuranceType='Health' and payload: customerName='Sarah Williams', email='sarah.w@example.com', phoneNumber='555-3456', coverageAmount=100000, effectiveDate='2024-05-01', preExistingConditions=false
    Then aPI returns 201 Created with quoteReferenceId starting with 'QT-HEALTH-' and status='pending', accepting Health insurance specific field preExistingConditions
    And query database for both created quotes using their respective quoteReferenceIds
    Then both quote records exist with correct insuranceType values ('Life' and 'Health') and their type-specific fields are properly stored
    And multiple insurance type quotes are created successfully in the system
    And type-specific fields are validated and stored correctly
    And quote reference IDs follow the naming convention for each insurance type
    And system supports diverse insurance product offerings via API

  @medium @tc-func-004
  Scenario: TC-FUNC-004 - Confirm API returns comprehensive quote details in response including all submitted and system-generated fields
    Given valid OAuth2 access token is available
    And aPI endpoint /api/quotes is accessible
    And system is configured to generate additional quote metadata
    When send POST request to /api/quotes with valid OAuth2 token and payload: customerName='Michael Brown', email='michael.brown@example.com', phoneNumber='555-7890', insuranceType='Auto', coverageAmount=75000, effectiveDate='2024-06-01'
    Then aPI returns 201 Created status
    And parse the JSON response body and verify it contains all submitted fields: customerName, email, phoneNumber, insuranceType, coverageAmount, effectiveDate
    Then response JSON includes all submitted fields with exact values matching the request payload
    And verify response contains system-generated fields: quoteReferenceId, status, createdAt, updatedAt, expiresAt
    Then response includes quoteReferenceId (format QT-XXXXXXXX), status='pending', createdAt with ISO 8601 timestamp, updatedAt matching createdAt, and expiresAt set to 30 days from createdAt
    And validate the data types and formats of all response fields
    Then all fields have correct data types: strings for text, numbers for amounts, ISO 8601 format for dates, and no null values for required fields
    And aPI consumer receives complete quote information for downstream processing
    And response structure is consistent and predictable for integration
    And system-generated metadata is properly populated and returned
    And quote expiration date is set according to business rules

  @medium @tc-func-005
  Scenario: TC-FUNC-005 - Validate API supports idempotency for duplicate quote submissions with same data
    Given valid OAuth2 access token is obtained
    And aPI implements idempotency key handling via X-Idempotency-Key header
    And database is configured to handle duplicate detection
    And test client can generate and reuse idempotency keys
    When generate a unique idempotency key: 'idem-key-12345' and send POST request to /api/quotes with header X-Idempotency-Key='idem-key-12345' and payload: customerName='Lisa Anderson', email='lisa.a@example.com', phoneNumber='555-2468', insuranceType='Home', coverageAmount=300000, effectiveDate='2024-07-01'
    Then aPI returns 201 Created with quoteReferenceId='QT-ABC123' and status='pending'
    And send identical POST request to /api/quotes with same X-Idempotency-Key='idem-key-12345' and exact same payload within 24 hours
    Then aPI returns 200 OK (not 201 Created) with the same quoteReferenceId='QT-ABC123' from the first request, indicating duplicate detection
    And query database for quotes with customerName='Lisa Anderson' and email='lisa.a@example.com'
    Then only one quote record exists in database with quoteReferenceId='QT-ABC123', confirming no duplicate quote was created
    And system prevents duplicate quote creation for retry scenarios
    And original quote reference is returned for duplicate requests
    And database maintains data integrity without duplicate records
    And aPI consumers can safely retry requests without side effects

  @medium @tc-func-006
  Scenario: TC-FUNC-006 - Verify API correctly handles and validates different date formats for effectiveDate field
    Given valid OAuth2 access token is available
    And aPI documentation specifies accepted date formats (ISO 8601)
    And system date validation rules are configured
    And current date is known for relative date testing
    When send POST request to /api/quotes with effectiveDate in ISO 8601 format '2024-08-15' and complete valid payload: customerName='David Lee', email='david.lee@example.com', phoneNumber='555-1357', insuranceType='Auto', coverageAmount=60000
    Then aPI returns 201 Created with quoteReferenceId and the effectiveDate is stored as '2024-08-15' in the response
    And send POST request to /api/quotes with effectiveDate in ISO 8601 datetime format '2024-09-20T00:00:00Z' and complete valid payload: customerName='Emily Chen', email='emily.chen@example.com', phoneNumber='555-2460', insuranceType='Life', coverageAmount=400000
    Then aPI returns 201 Created and normalizes the effectiveDate to '2024-09-20' in the response, accepting the datetime format
    And verify both quotes are stored in database with properly formatted effectiveDate values
    Then database contains both quotes with effectiveDate stored in consistent date format (YYYY-MM-DD) regardless of input format variation
    And aPI accepts standard ISO 8601 date formats for flexibility
    And date values are normalized and stored consistently in database
    And quote effective dates are properly set for policy activation
    And aPI consumers can use their preferred ISO 8601 date format

