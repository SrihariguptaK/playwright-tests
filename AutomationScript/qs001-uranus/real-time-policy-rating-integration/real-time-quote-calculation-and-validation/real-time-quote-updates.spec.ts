import { test, expect } from '@playwright/test';

test.describe('Real-time Quote Updates - Story 15', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the quoting module and login as Quoting Specialist
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'quoting.specialist@company.com');
    await page.fill('[data-testid="password-input"]', 'SecurePassword123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate real-time quote update on rating response (happy-path)', async ({ page }) => {
    // Step 1: Navigate to the quote creation page in the Quoting module UI
    await page.goto('/quoting/create');
    await expect(page.locator('[data-testid="quote-creation-page"]')).toBeVisible();

    // Step 2: Enter valid quote data including customer information, product details, coverage amounts, and risk factors
    await page.fill('[data-testid="customer-name-input"]', 'John Smith');
    await page.fill('[data-testid="customer-email-input"]', 'john.smith@example.com');
    await page.fill('[data-testid="customer-phone-input"]', '555-123-4567');
    
    // Select product details
    await page.selectOption('[data-testid="product-type-select"]', 'commercial-property');
    await page.fill('[data-testid="coverage-amount-input"]', '500000');
    await page.fill('[data-testid="deductible-input"]', '5000');
    
    // Enter risk factors
    await page.fill('[data-testid="property-age-input"]', '15');
    await page.fill('[data-testid="square-footage-input"]', '10000');
    await page.selectOption('[data-testid="construction-type-select"]', 'masonry');
    await page.selectOption('[data-testid="occupancy-type-select"]', 'office');

    // Step 3: Click the Submit or Calculate Quote button to send data to rating engine
    const startTime = Date.now();
    await page.click('[data-testid="calculate-quote-button"]');
    
    // Expected Result: Quote data sent to rating engine
    await expect(page.locator('[data-testid="quote-status-indicator"]')).toContainText(/calculating|processing/i);

    // Step 4: Observe the UI while rating engine processes the request
    await expect(page.locator('[data-testid="loading-spinner"]')).toBeVisible();

    // Step 5: Wait for rating engine response to be received by the system
    await expect(page.locator('[data-testid="quote-premium-amount"]')).toBeVisible({ timeout: 10000 });
    
    // Step 6: Measure the time between receiving rating response and UI update
    const endTime = Date.now();
    const updateTime = endTime - startTime;
    
    // Expected Result: Quote price updates within 1 second (allowing 2 seconds for network)
    expect(updateTime).toBeLessThan(2000);

    // Step 7: Verify the updated quote display shows the calculated premium amount
    const premiumAmount = await page.locator('[data-testid="quote-premium-amount"]').textContent();
    expect(premiumAmount).toMatch(/\$[0-9,]+\.\d{2}/);
    
    // Expected Result: Correct price and status shown
    await expect(page.locator('[data-testid="quote-status-indicator"]')).toContainText(/completed|ready|calculated/i);

    // Step 8: Check the status indicator after quote update completes
    await expect(page.locator('[data-testid="quote-status-indicator"]')).toHaveClass(/success|complete/);

    // Step 9: Review all quote details including breakdown of premium components if available
    await expect(page.locator('[data-testid="base-premium"]')).toBeVisible();
    await expect(page.locator('[data-testid="quote-details-section"]')).toBeVisible();
    
    const basePremium = await page.locator('[data-testid="base-premium"]').textContent();
    expect(basePremium).toBeTruthy();
  });

  test('Verify error message display on rating failure (error-case)', async ({ page }) => {
    // Step 1: Navigate to the quote creation page in the Quoting module UI
    await page.goto('/quoting/create');
    await expect(page.locator('[data-testid="quote-creation-page"]')).toBeVisible();

    // Step 2: Enter valid quote data in all required fields
    await page.fill('[data-testid="customer-name-input"]', 'Jane Doe');
    await page.fill('[data-testid="customer-email-input"]', 'jane.doe@example.com');
    await page.fill('[data-testid="customer-phone-input"]', '555-987-6543');
    await page.selectOption('[data-testid="product-type-select"]', 'commercial-property');
    await page.fill('[data-testid="coverage-amount-input"]', '750000');
    await page.fill('[data-testid="deductible-input"]', '10000');
    await page.fill('[data-testid="property-age-input"]', '20');
    await page.fill('[data-testid="square-footage-input"]', '15000');
    await page.selectOption('[data-testid="construction-type-select"]', 'frame');
    await page.selectOption('[data-testid="occupancy-type-select"]', 'retail');

    // Step 3: Configure test environment or mock service to simulate rating engine failure response
    await page.route('**/api/rate', route => {
      route.fulfill({
        status: 500,
        contentType: 'application/json',
        body: JSON.stringify({ error: 'Rating engine service unavailable' })
      });
    });

    // Step 4: Click Submit or Calculate Quote button to trigger rating request
    await page.click('[data-testid="calculate-quote-button"]');

    // Step 5: Observe the UI when rating engine returns failure response
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible({ timeout: 5000 });

    // Step 6: Verify the error message contains actionable information for the user
    const errorMessage = await page.locator('[data-testid="error-message"]').textContent();
    expect(errorMessage).toMatch(/error|failed|unavailable|try again/i);
    await expect(page.locator('[data-testid="error-message"]')).toContainText(/rating/i);

    // Step 7: Locate and click the manual refresh or retry button on the quote page
    await expect(page.locator('[data-testid="retry-quote-button"]')).toBeVisible();
    await expect(page.locator('[data-testid="retry-quote-button"]')).toBeEnabled();

    // Step 8: Click the manual refresh button to retry the rating request
    // Step 9: Configure rating engine to return successful response for the retry attempt
    await page.unroute('**/api/rate');
    await page.route('**/api/rate', route => {
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          quoteId: 'Q-12345',
          premium: 8750.00,
          basePremium: 7500.00,
          fees: 1250.00,
          status: 'calculated'
        })
      });
    });

    await page.click('[data-testid="retry-quote-button"]');

    // Step 10: Observe the UI after successful rating response is received
    await expect(page.locator('[data-testid="quote-premium-amount"]')).toBeVisible({ timeout: 5000 });

    // Expected Result: Error message removed after successful update
    await expect(page.locator('[data-testid="error-message"]')).not.toBeVisible();

    // Step 11: Verify the quote display shows correct price and status after successful update
    const premiumAmount = await page.locator('[data-testid="quote-premium-amount"]').textContent();
    expect(premiumAmount).toContain('8,750.00');
    
    await expect(page.locator('[data-testid="quote-status-indicator"]')).toContainText(/completed|ready|calculated/i);
    await expect(page.locator('[data-testid="quote-details-section"]')).toBeVisible();
  });

  test('Validate real-time quote update on rating response', async ({ page }) => {
    // Test Case #1 from Test Cases to Automate section
    await page.goto('/quoting/create');
    
    // Action: Enter quote data in UI and submit
    await page.fill('[data-testid="customer-name-input"]', 'Test Customer');
    await page.fill('[data-testid="customer-email-input"]', 'test@example.com');
    await page.selectOption('[data-testid="product-type-select"]', 'commercial-property');
    await page.fill('[data-testid="coverage-amount-input"]', '1000000');
    await page.click('[data-testid="calculate-quote-button"]');
    
    // Expected Result: Quote data sent to rating engine
    await expect(page.locator('[data-testid="quote-status-indicator"]')).toBeVisible();
    
    // Action: Receive rating response
    const startTime = Date.now();
    await expect(page.locator('[data-testid="quote-premium-amount"]')).toBeVisible({ timeout: 10000 });
    const responseTime = Date.now() - startTime;
    
    // Expected Result: Quote price updates within 1 second
    expect(responseTime).toBeLessThan(1000);
    
    // Action: Verify updated quote display
    const premium = await page.locator('[data-testid="quote-premium-amount"]').textContent();
    const status = await page.locator('[data-testid="quote-status-indicator"]').textContent();
    
    // Expected Result: Correct price and status shown
    expect(premium).toBeTruthy();
    expect(status).toMatch(/calculated|completed/i);
  });

  test('Verify error message display on rating failure', async ({ page }) => {
    // Test Case #2 from Test Cases to Automate section
    await page.goto('/quoting/create');
    
    // Action: Simulate rating engine failure response
    await page.route('**/api/rate', route => {
      route.fulfill({
        status: 503,
        contentType: 'application/json',
        body: JSON.stringify({ error: 'Service temporarily unavailable' })
      });
    });
    
    await page.fill('[data-testid="customer-name-input"]', 'Error Test Customer');
    await page.fill('[data-testid="customer-email-input"]', 'error@example.com');
    await page.selectOption('[data-testid="product-type-select"]', 'commercial-property');
    await page.fill('[data-testid="coverage-amount-input"]', '500000');
    await page.click('[data-testid="calculate-quote-button"]');
    
    // Expected Result: Error message displayed on UI
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    const errorText = await page.locator('[data-testid="error-message"]').textContent();
    expect(errorText).toBeTruthy();
    
    // Action: Attempt manual quote refresh
    await page.unroute('**/api/rate');
    await page.click('[data-testid="retry-quote-button"]');
    
    // Expected Result: System retries rating request
    await expect(page.locator('[data-testid="quote-status-indicator"]')).toContainText(/processing|calculating/i);
    
    // Action: Check error message clearance on success
    await expect(page.locator('[data-testid="quote-premium-amount"]')).toBeVisible({ timeout: 5000 });
    
    // Expected Result: Error message removed after successful update
    await expect(page.locator('[data-testid="error-message"]')).not.toBeVisible();
  });
});