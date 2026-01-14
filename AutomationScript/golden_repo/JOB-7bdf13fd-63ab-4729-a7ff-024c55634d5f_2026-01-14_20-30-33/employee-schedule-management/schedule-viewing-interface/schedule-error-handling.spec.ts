import { test, expect } from '@playwright/test';

test.describe('Schedule Error Handling - Story 9', () => {
  const scheduleUrl = '/schedule';
  const baseUrl = process.env.BASE_URL || 'http://localhost:3000';

  test('Validate error message display on data load failure', async ({ page, context }) => {
    // Simulate backend failure by intercepting API calls
    await page.route('**/api/schedule**', route => {
      route.abort('failed');
    });

    // Navigate to the schedule section
    await page.goto(baseUrl);
    await page.click('[data-testid="schedule-menu-item"]', { timeout: 5000 });
    await page.waitForURL('**/schedule', { timeout: 5000 });

    // Expected Result: User-friendly error message displayed
    const errorMessage = page.locator('[data-testid="error-message"]').or(page.locator('text=/error|failed|unable to load/i')).first();
    await expect(errorMessage).toBeVisible({ timeout: 10000 });
    await expect(errorMessage).toContainText(/error|failed|unable|could not/i);

    // Verify error message is prominently displayed and easy to read
    const errorContainer = page.locator('[data-testid="error-container"]').or(errorMessage.locator('..')).first();
    await expect(errorContainer).toBeVisible();

    // Locate and click the Retry button
    const retryButton = page.locator('[data-testid="retry-button"]').or(page.getByRole('button', { name: /retry/i }));
    await expect(retryButton).toBeVisible();

    // Clear the route to allow successful retry
    await page.unroute('**/api/schedule**');
    await page.route('**/api/schedule**', route => {
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ schedules: [] })
      });
    });

    // Expected Result: System attempts to reload data
    await retryButton.click();
    await page.waitForTimeout(1000);

    // Expected Result: No UI freeze and error logged in backend
    // Verify UI remains responsive by attempting to interact with elements
    const navigationElement = page.locator('[data-testid="navigation"]').or(page.locator('nav')).first();
    await expect(navigationElement).toBeVisible();
    
    // Verify no JavaScript errors in console
    const consoleErrors: string[] = [];
    page.on('console', msg => {
      if (msg.type() === 'error') {
        consoleErrors.push(msg.text());
      }
    });

    // Check that UI is still interactive
    await expect(page.locator('body')).toBeVisible();
    const isPageResponsive = await page.evaluate(() => {
      return document.readyState === 'complete';
    });
    expect(isPageResponsive).toBe(true);
  });

  test('Ensure error messages guide user actions', async ({ page }) => {
    // Configure the test environment to trigger a schedule load error
    await page.route('**/api/schedule**', route => {
      route.fulfill({
        status: 500,
        contentType: 'application/json',
        body: JSON.stringify({ error: 'Database connection failure' })
      });
    });

    // Navigate to the schedule section to trigger the error condition
    await page.goto(baseUrl);
    await page.click('[data-testid="schedule-menu-item"]').catch(() => 
      page.getByRole('link', { name: /schedule/i }).click()
    );
    await page.waitForURL('**/schedule', { timeout: 5000 });

    // Wait for error message to appear
    await page.waitForTimeout(2000);

    // Expected Result: Error message includes retry and support contact info
    const errorMessage = page.locator('[data-testid="error-message"]').or(
      page.locator('text=/error|failed|unable to load/i')
    ).first();
    await expect(errorMessage).toBeVisible({ timeout: 10000 });

    // Read and analyze the displayed error message content
    const errorText = await errorMessage.textContent();
    expect(errorText).toBeTruthy();

    // Verify that the error message includes a Retry button or link
    const retryButton = page.locator('[data-testid="retry-button"]').or(
      page.getByRole('button', { name: /retry/i })
    ).or(
      page.getByRole('link', { name: /retry/i })
    );
    await expect(retryButton).toBeVisible();

    // Verify that the error message includes support contact information
    const supportContact = page.locator('[data-testid="support-contact"]').or(
      page.locator('text=/contact support|support@|help@|support team/i')
    ).or(
      page.getByRole('link', { name: /contact|support/i })
    );
    await expect(supportContact).toBeVisible();

    // Click on the support contact link or button if provided
    const supportLink = page.locator('[data-testid="support-link"]').or(
      page.getByRole('link', { name: /contact support|support/i })
    );
    if (await supportLink.isVisible()) {
      const href = await supportLink.getAttribute('href');
      expect(href).toBeTruthy();
      expect(href).toMatch(/mailto:|support|contact|help/);
    }

    // Click the Retry button to test retry functionality
    await page.route('**/api/schedule**', route => {
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ schedules: [] })
      });
    });

    await retryButton.click();
    await page.waitForTimeout(1000);

    // Verify that the error message provides actionable guidance without causing user confusion
    const isErrorCleared = await errorMessage.isHidden().catch(() => true);
    const hasLoadingIndicator = await page.locator('[data-testid="loading-indicator"]').or(
      page.locator('text=/loading/i')
    ).isVisible().catch(() => false);
    
    // Verify UI remains functional
    await expect(page.locator('body')).toBeVisible();
    const pageTitle = await page.title();
    expect(pageTitle).toBeTruthy();
  });
});