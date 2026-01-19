import { test, expect } from '@playwright/test';

test.describe('Performance Metric Data Validation', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const API_URL = process.env.API_URL || 'http://localhost:3000/api';

  test.beforeEach(async ({ page }) => {
    await page.goto(`${BASE_URL}/metrics/data-entry`);
  });

  test('Validate rejection of invalid metric data inputs', async ({ page }) => {
    // Navigate to the metric data entry form (already done in beforeEach)
    await expect(page).toHaveURL(/.*metrics\/data-entry/);

    // Enter invalid data in a mandatory numeric field (e.g., enter text 'abc' in a numeric field)
    const numericField = page.locator('[data-testid="metric-value-input"]').or(page.locator('input[type="number"]').first());
    await numericField.fill('abc');
    await numericField.blur();

    // Verify inline validation error is displayed
    const numericError = page.locator('[data-testid="metric-value-error"]').or(page.locator('text=/.*must be.*number.*/i').first());
    await expect(numericError).toBeVisible({ timeout: 1000 });

    // Leave a mandatory field empty and move to the next field
    const mandatoryField = page.locator('[data-testid="metric-name-input"]').or(page.locator('input[required]').first());
    await mandatoryField.clear();
    await mandatoryField.blur();

    // Verify required field validation error
    const requiredError = page.locator('[data-testid="metric-name-error"]').or(page.locator('text=/.*required.*/i').first());
    await expect(requiredError).toBeVisible({ timeout: 1000 });

    // Enter a numeric value outside the acceptable range (e.g., enter -5 when minimum is 0)
    const rangeField = page.locator('[data-testid="metric-value-input"]').or(page.locator('input[type="number"]').first());
    await rangeField.clear();
    await rangeField.fill('-5');
    await rangeField.blur();

    // Verify range validation error
    const rangeError = page.locator('[data-testid="metric-value-error"]').or(page.locator('text=/.*minimum.*0.*/i, text=/.*must be.*greater.*/i').first());
    await expect(rangeError).toBeVisible({ timeout: 1000 });

    // Verify validation response time for each error (already checked with 1000ms timeout)

    // Attempt to submit the form with validation errors present
    const submitButton = page.locator('[data-testid="submit-metric-data"]').or(page.locator('button[type="submit"]'));
    await submitButton.click();

    // Verify submission is blocked
    await expect(page.locator('[data-testid="success-message"]').or(page.locator('text=/.*success.*/i'))).not.toBeVisible();
    await expect(page.locator('[data-testid="error-summary"]').or(page.locator('text=/.*fix.*error.*/i, text=/.*validation.*failed.*/i'))).toBeVisible();

    // Correct all validation errors by entering valid data in all fields
    await mandatoryField.fill('Revenue Growth');
    await rangeField.clear();
    await rangeField.fill('25.5');

    // Fill other required fields if present
    const categoryField = page.locator('[data-testid="metric-category-input"]');
    if (await categoryField.count() > 0) {
      await categoryField.selectOption('Financial');
    }

    const dateField = page.locator('[data-testid="metric-date-input"]');
    if (await dateField.count() > 0) {
      await dateField.fill('2024-01-15');
    }

    // Submit the form with all valid data
    await submitButton.click();

    // Verify data is accepted and confirmation displayed
    const successMessage = page.locator('[data-testid="success-message"]').or(page.locator('text=/.*successfully.*saved.*/i, text=/.*data.*submitted.*/i'));
    await expect(successMessage).toBeVisible({ timeout: 5000 });
  });

  test('Validate backend rejection of invalid data', async ({ request }) => {
    // Prepare an API request to POST /api/metricdata with invalid data payload
    const invalidPayload = {
      metricName: '', // Missing mandatory field
      metricValue: 'invalid_text', // Invalid data type
      category: 'Financial',
      date: '2024-01-15',
      target: -10 // Out-of-range value
    };

    // Submit the API request with invalid metric data
    const startTime = Date.now();
    const response = await request.post(`${API_URL}/metricdata`, {
      data: invalidPayload,
      headers: {
        'Content-Type': 'application/json'
      }
    });
    const responseTime = Date.now() - startTime;

    // Review the API response body
    const responseBody = await response.json();

    // Verify API returns descriptive validation errors
    expect(response.status()).toBe(400);
    expect(responseBody).toHaveProperty('errors');
    expect(Array.isArray(responseBody.errors) || typeof responseBody.errors === 'object').toBeTruthy();

    // Verify descriptive error messages are present
    const errorString = JSON.stringify(responseBody.errors).toLowerCase();
    expect(errorString).toMatch(/required|mandatory|invalid|must be/i);

    // Verify the response time of the validation (under 1 second)
    expect(responseTime).toBeLessThan(1000);

    // Check the database to confirm no invalid data was saved
    // This would typically be done via a database query or API GET request
    const getResponse = await request.get(`${API_URL}/metricdata?metricName=${invalidPayload.metricName}`);
    const getData = await getResponse.json();
    
    // Verify no data with empty name was saved
    if (Array.isArray(getData)) {
      const invalidEntry = getData.find((item: any) => item.metricName === '' || item.metricValue === 'invalid_text');
      expect(invalidEntry).toBeUndefined();
    }

    // Submit a corrected API request with valid data in all fields
    const validPayload = {
      metricName: 'Revenue Growth',
      metricValue: 25.5,
      category: 'Financial',
      date: '2024-01-15',
      target: 30
    };

    const validResponse = await request.post(`${API_URL}/metricdata`, {
      data: validPayload,
      headers: {
        'Content-Type': 'application/json'
      }
    });

    // Verify valid data is accepted
    expect(validResponse.status()).toBe(200);
    const validResponseBody = await validResponse.json();
    expect(validResponseBody).toHaveProperty('success', true);
    expect(validResponseBody).toHaveProperty('id');
  });
});