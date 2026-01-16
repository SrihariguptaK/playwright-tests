import { test, expect } from '@playwright/test';
import type { Page } from '@playwright/test';

interface RatingRequest {
  quoteId: string;
  productType: string;
  coverageAmount: number;
  applicantAge: number;
  riskFactors: string[];
}

interface RatingResponse {
  quoteId: string;
  premium: number;
  status: string;
  timestamp: string;
}

test.describe('Rating Engine API Request and Response Handling', () => {
  let page: Page;
  const API_ENDPOINT = '/api/rate';
  const QUOTING_MODULE_URL = '/quoting';

  test.beforeEach(async ({ page: testPage }) => {
    page = testPage;
    await page.goto(QUOTING_MODULE_URL);
  });

  test('Validate correct serialization of rating request (happy-path)', async () => {
    // Step 1: Navigate to quoting module and create or select an existing quote requiring rating
    await page.goto(QUOTING_MODULE_URL);
    await expect(page).toHaveURL(new RegExp(QUOTING_MODULE_URL));

    // Create new quote or select existing
    const createQuoteButton = page.getByRole('button', { name: /create quote|new quote/i });
    if (await createQuoteButton.isVisible()) {
      await createQuoteButton.click();
    } else {
      await page.getByTestId('quote-list-item').first().click();
    }

    // Step 2: Verify all required rating request fields are present in the quote data
    await expect(page.getByTestId('quote-id')).toBeVisible();
    await expect(page.getByTestId('product-type')).toBeVisible();
    await expect(page.getByTestId('coverage-amount')).toBeVisible();
    await expect(page.getByTestId('applicant-age')).toBeVisible();

    // Fill in required fields
    await page.getByTestId('product-type').selectOption('term-life');
    await page.getByTestId('coverage-amount').fill('500000');
    await page.getByTestId('applicant-age').fill('35');
    await page.getByTestId('risk-factors').fill('non-smoker,healthy');

    // Step 3: Review the data structure against rating engine API schema requirements
    const quoteId = await page.getByTestId('quote-id').textContent();
    expect(quoteId).toBeTruthy();

    // Step 4: Trigger the rating request process from the quoting module
    const requestPromise = page.waitForRequest(request => 
      request.url().includes(API_ENDPOINT) && request.method() === 'POST'
    );

    await page.getByRole('button', { name: /get rating|calculate rate/i }).click();

    // Step 5: Monitor the data serialization process and capture the serialized JSON payload
    const request = await requestPromise;
    const requestPayload = request.postDataJSON() as RatingRequest;

    // Step 6: Validate the JSON payload against the API schema specification
    expect(requestPayload).toHaveProperty('quoteId');
    expect(requestPayload).toHaveProperty('productType');
    expect(requestPayload).toHaveProperty('coverageAmount');
    expect(requestPayload).toHaveProperty('applicantAge');
    expect(requestPayload.quoteId).toBeTruthy();
    expect(requestPayload.productType).toBe('term-life');
    expect(requestPayload.coverageAmount).toBe(500000);
    expect(requestPayload.applicantAge).toBe(35);

    // Step 7: Verify JSON syntax is valid and properly formatted
    expect(() => JSON.stringify(requestPayload)).not.toThrow();
    const serializedPayload = JSON.stringify(requestPayload);
    expect(serializedPayload).toContain('quoteId');
    expect(serializedPayload).toContain('productType');

    // Step 8: Send the serialized JSON payload to the rating engine API
    const responsePromise = page.waitForResponse(response => 
      response.url().includes(API_ENDPOINT) && response.status() === 200
    );

    // Step 9: Monitor the API response to the request
    const response = await responsePromise;
    expect(response.status()).toBe(200);

    // Step 10: Verify API accepts the request without validation errors
    const responseData = await response.json() as RatingResponse;
    expect(responseData.status).not.toBe('error');
    expect(responseData.status).toBe('success');

    // Step 11: Check transaction logs for request details
    await page.getByTestId('transaction-logs').click();
    await expect(page.getByText(new RegExp(quoteId || ''))).toBeVisible();
    await expect(page.getByTestId('log-entry').first()).toContainText('POST');
    await expect(page.getByTestId('log-entry').first()).toContainText(API_ENDPOINT);
  });

  test('Verify response validation and error handling (error-case)', async () => {
    await page.goto(QUOTING_MODULE_URL);

    // Scenario 1: Valid successful response
    // Step 1: Send a rating request that will return a valid successful response
    await page.getByRole('button', { name: /create quote|new quote/i }).click();
    await page.getByTestId('product-type').selectOption('term-life');
    await page.getByTestId('coverage-amount').fill('250000');
    await page.getByTestId('applicant-age').fill('30');

    // Step 2: Receive response JSON from the rating engine API with valid data
    const validResponsePromise = page.waitForResponse(response => 
      response.url().includes(API_ENDPOINT)
    );

    await page.getByRole('button', { name: /get rating|calculate rate/i }).click();

    // Step 3: Capture the response JSON payload
    const validResponse = await validResponsePromise;
    const validResponseData = await validResponse.json() as RatingResponse;

    // Step 4: Trigger automatic schema validation against expected response schema
    expect(validResponseData).toHaveProperty('quoteId');
    expect(validResponseData).toHaveProperty('premium');
    expect(validResponseData).toHaveProperty('status');
    expect(validResponseData).toHaveProperty('timestamp');

    // Step 5: Verify validation results for valid response
    expect(validResponseData.status).toBe('success');
    expect(typeof validResponseData.premium).toBe('number');
    expect(validResponseData.premium).toBeGreaterThan(0);

    // Step 6: Verify response data is parsed and extracted correctly
    await expect(page.getByTestId('premium-amount')).toContainText(validResponseData.premium.toString());

    // Step 7: Check transaction logs for successful response processing
    await page.getByTestId('transaction-logs').click();
    await expect(page.getByTestId('log-status').first()).toContainText('success');

    // Scenario 2: Error response handling
    // Step 8: Send a rating request that will trigger an API error response
    await page.goto(QUOTING_MODULE_URL);
    await page.getByRole('button', { name: /create quote|new quote/i }).click();
    
    // Use invalid data to trigger error
    await page.getByTestId('product-type').selectOption('invalid-product');
    await page.getByTestId('coverage-amount').fill('-1000');
    await page.getByTestId('applicant-age').fill('150');

    // Step 9: Receive response JSON from API with error code
    const errorResponsePromise = page.waitForResponse(response => 
      response.url().includes(API_ENDPOINT) && 
      (response.status() === 400 || response.status() === 422 || response.status() === 500)
    );

    await page.getByRole('button', { name: /get rating|calculate rate/i }).click();

    const errorResponse = await errorResponsePromise;

    // Step 10: Verify system detects the error code in the response
    const errorStatus = errorResponse.status();
    expect([400, 422, 500]).toContain(errorStatus);

    // Step 11: Monitor error handling mechanism activation
    await expect(page.getByTestId('error-notification')).toBeVisible({ timeout: 5000 });
    await expect(page.getByTestId('error-message')).toBeVisible();

    // Step 12: Verify error is logged with complete details
    await page.getByTestId('transaction-logs').click();
    const errorLogEntry = page.getByTestId('log-entry').filter({ hasText: 'error' }).first();
    await expect(errorLogEntry).toBeVisible();
    await expect(errorLogEntry).toContainText(errorStatus.toString());

    // Step 13: Check if retry mechanism is activated for retryable errors
    if (errorStatus === 500) {
      await expect(page.getByTestId('retry-indicator')).toBeVisible({ timeout: 3000 });
      await expect(page.getByTestId('retry-count')).toBeVisible();
      const retryCount = await page.getByTestId('retry-count').textContent();
      expect(parseInt(retryCount || '0')).toBeGreaterThan(0);
    }

    // Step 14: Verify error notification is generated
    await expect(page.getByTestId('error-notification')).toContainText(/error|failed|invalid/i);
    const errorMessage = await page.getByTestId('error-message').textContent();
    expect(errorMessage).toBeTruthy();

    // Step 15: Confirm response processing time for both scenarios
    const processingTimeElement = page.getByTestId('processing-time');
    if (await processingTimeElement.isVisible()) {
      const processingTime = await processingTimeElement.textContent();
      const timeInMs = parseFloat(processingTime || '0');
      expect(timeInMs).toBeLessThan(1000); // Under 1 second as per requirements
    }

    // Verify transaction log shows timestamp
    await page.getByTestId('transaction-logs').click();
    const logTimestamp = page.getByTestId('log-timestamp').first();
    await expect(logTimestamp).toBeVisible();
    const timestamp = await logTimestamp.textContent();
    expect(timestamp).toBeTruthy();
  });
});