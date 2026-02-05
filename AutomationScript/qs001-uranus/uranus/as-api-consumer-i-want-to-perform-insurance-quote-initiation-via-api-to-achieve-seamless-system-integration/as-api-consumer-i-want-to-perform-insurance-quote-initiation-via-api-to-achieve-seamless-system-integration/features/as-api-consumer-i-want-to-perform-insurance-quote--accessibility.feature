@accessibility @a11y @wcag
Feature: As API Consumer, I want to perform insurance quote initiation via API to achieve seamless system integration - Accessibility Tests
  As a user
  I want to test accessibility tests
  So that I can ensure quality and reliability

  Background:
    Given the system is ready for testing
    And the test environment is properly configured

  @medium @tc-acce-001
  Scenario: TC-ACCE-001 - Verify API documentation is accessible and provides clear examples for screen reader users
    Given aPI documentation is published and accessible via web interface
    And screen reader software (JAWS, NVDA, or VoiceOver) is installed and running
    And documentation includes code examples and request/response samples
    And user has basic familiarity with screen reader navigation
    When navigate to API documentation page using screen reader and verify page title is announced clearly
    Then screen reader announces descriptive page title 'Insurance Quote API Documentation' and main heading structure is properly announced
    And use screen reader heading navigation (H key) to navigate through documentation sections
    Then all major sections have proper heading hierarchy (h1, h2, h3) and screen reader can jump between sections using heading navigation shortcuts
    And navigate to code example sections and verify code blocks are properly labeled and accessible
    Then code examples have descriptive labels like 'Example Request JSON' and 'Example Response JSON', and code is presented in accessible format with proper ARIA labels
    And verify all interactive elements (copy buttons, expand/collapse sections) are keyboard accessible and announced by screen reader
    Then all interactive elements can be reached via Tab key, have clear focus indicators, and screen reader announces their purpose and state (e.g., 'Copy code button', 'Expand section button, collapsed')
    And aPI documentation is fully navigable using screen reader
    And all code examples and technical content are accessible to assistive technology users
    And documentation meets WCAG 2.1 Level AA standards for accessibility
    And developers with visual impairments can effectively use the API documentation

  @high @tc-acce-002
  Scenario: TC-ACCE-002 - Ensure API error messages are descriptive and machine-readable for assistive technology
    Given valid OAuth2 access token is obtained
    And aPI returns structured JSON error responses
    And error response format includes error codes, messages, and field-level details
    And client application can parse and present error messages to users
    When send POST request to /api/quotes with missing required field and parse the error response JSON structure
    Then error response has clear structure with 'error' object containing 'code', 'message', and 'errors' array with field-specific details that can be programmatically parsed
    And verify error messages use plain language without technical jargon that would confuse non-technical users
    Then error messages like 'customerName is required and cannot be empty' are clear and actionable, avoiding technical terms like 'null pointer exception' or 'validation constraint violation'
    And verify error response includes 'field' property that maps to the exact field name in the request payload
    Then each error in the 'errors' array includes 'field' property with exact field name (e.g., 'customerName', 'email') enabling client applications to associate errors with specific form fields for screen reader announcement
    And test that HTTP status codes are semantically correct (400 for validation, 401 for auth, 500 for server errors) for assistive technology that may announce status
    Then hTTP status codes accurately reflect error type, enabling assistive technology and client applications to provide appropriate user feedback
    And error messages are structured for programmatic parsing by client applications
    And assistive technology can present clear, actionable error information to users
    And error responses follow consistent format enabling predictable error handling
    And users with disabilities receive equivalent error information as visual users

  @medium @tc-acce-003
  Scenario: TC-ACCE-003 - Validate API response times support users with cognitive disabilities who may need more processing time
    Given valid OAuth2 access token is obtained
    And aPI is designed to respond within 500ms under normal load
    And client applications may implement timeout handling
    And users may be using assistive technology that adds processing overhead
    When send POST request to /api/quotes with valid payload and measure total response time including network latency
    Then aPI responds within 500ms, providing quick feedback that supports users who may have difficulty with long wait times
    And verify API does not implement aggressive timeout policies that would disconnect users who take longer to complete actions
    Then oAuth2 token expiration is set to reasonable duration (e.g., 1 hour) allowing users adequate time to complete workflows without rushing
    And test that API supports idempotency allowing users to safely retry requests if they are unsure whether first request succeeded
    Then duplicate requests with same idempotency key return same result without creating duplicate quotes, supporting users who may need to retry due to uncertainty
    And aPI performance supports users who need more time to process information
    And timeout policies are generous enough for users with cognitive disabilities
    And idempotency support enables safe retry behavior for uncertain users
    And system accommodates diverse user processing speeds and capabilities

  @medium @tc-acce-004
  Scenario: TC-ACCE-004 - Verify API documentation provides alternative text descriptions for all diagrams and visual content
    Given aPI documentation includes architecture diagrams, flow charts, or visual examples
    And documentation is published in HTML format supporting alt text
    And screen reader is available for testing
    And wCAG 2.1 requires text alternatives for non-text content
    When navigate to API documentation sections containing diagrams or images using screen reader
    Then screen reader announces presence of images and reads alt text descriptions
    And verify each diagram has descriptive alt text that conveys the same information as the visual (e.g., 'Authentication flow diagram showing OAuth2 token request, validation, and API access steps')
    Then all images have meaningful alt text that describes the content and purpose, not just generic text like 'diagram' or 'image'
    And for complex diagrams, verify long descriptions are provided via aria-describedby or adjacent text
    Then complex diagrams have detailed text descriptions that fully explain the visual information for users who cannot see the diagram
    And verify decorative images (if any) have empty alt text (alt='') so screen readers skip them
    Then decorative images that don't convey information have alt='' to prevent unnecessary screen reader announcements
    And all visual content in API documentation has text alternatives
    And users with visual impairments can access all information conveyed by diagrams
    And documentation meets WCAG 2.1 Level A requirement for text alternatives
    And no information is exclusively presented in visual format

  @low @tc-acce-005
  Scenario: TC-ACCE-005 - Ensure API rate limiting and error responses accommodate assistive technology processing delays
    Given aPI implements rate limiting to prevent abuse
    And rate limiting returns 429 Too Many Requests when threshold exceeded
    And users with assistive technology may have slower interaction speeds
    And rate limits are documented in API documentation
    When review API rate limiting policy documentation to verify limits are reasonable for users with assistive technology (e.g., not less than 10 requests per minute)
    Then rate limits are generous enough (e.g., 60 requests per minute) that users with assistive technology who interact more slowly are not penalized
    And trigger rate limiting by sending requests exceeding the threshold and verify 429 response includes Retry-After header
    Then 429 Too Many Requests response includes Retry-After header with seconds to wait, and clear error message explaining rate limit and when to retry
    And verify rate limiting error message is clear and actionable for users who may not understand technical rate limiting concepts
    Then error message uses plain language like 'Too many requests. Please wait 60 seconds before trying again.' rather than technical jargon
    And rate limiting policies accommodate users with assistive technology
    And rate limit errors provide clear guidance on when to retry
    And users with disabilities are not unfairly penalized by aggressive rate limiting
    And aPI remains accessible while maintaining security and performance

