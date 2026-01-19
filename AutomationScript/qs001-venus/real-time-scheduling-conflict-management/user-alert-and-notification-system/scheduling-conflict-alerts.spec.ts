import { test, expect } from '@playwright/test';

test.describe('Scheduling Conflict Inline Alerts', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the scheduling form interface
    await page.goto('/scheduling/form');
    await page.waitForLoadState('networkidle');
  });

  test('Display inline alert on scheduling conflict (happy-path)', async ({ page }) => {
    // Enter scheduling details that conflict with an existing booking
    await page.fill('[data-testid="resource-input"]', 'Conference Room A');
    await page.fill('[data-testid="date-input"]', '2024-03-15');
    await page.fill('[data-testid="start-time-input"]', '10:00');
    await page.fill('[data-testid="end-time-input"]', '11:00');
    
    // Trigger conflict detection by blurring the last field
    await page.blur('[data-testid="end-time-input"]');
    
    // Verify inline alert appears next to conflicting field
    const inlineAlert = page.locator('[data-testid="inline-alert"]');
    await expect(inlineAlert).toBeVisible({ timeout: 1000 });
    await expect(inlineAlert).toContainText('scheduling conflict');
    
    // Verify the visual highlighting of the conflicting field
    const conflictingField = page.locator('[data-testid="start-time-input"]');
    await expect(conflictingField).toHaveClass(/error|conflict|highlighted/);
    
    // Modify the scheduling details to resolve the conflict
    await page.fill('[data-testid="start-time-input"]', '14:00');
    await page.fill('[data-testid="end-time-input"]', '15:00');
    await page.blur('[data-testid="end-time-input"]');
    
    // Verify inline alert disappears automatically
    await expect(inlineAlert).not.toBeVisible({ timeout: 1000 });
    
    // Verify the visual highlighting is removed from the previously conflicting field
    await expect(conflictingField).not.toHaveClass(/error|conflict|highlighted/);
    
    // Re-enter conflicting scheduling details
    await page.fill('[data-testid="start-time-input"]', '10:00');
    await page.fill('[data-testid="end-time-input"]', '11:00');
    await page.blur('[data-testid="end-time-input"]');
    
    // Verify alert reappears
    await expect(inlineAlert).toBeVisible({ timeout: 1000 });
    
    // Attempt to submit the form with the unresolved conflict
    const submitButton = page.locator('[data-testid="submit-button"]');
    await submitButton.click();
    
    // Verify submission blocked with alert message
    const errorMessage = page.locator('[data-testid="submission-error"]');
    await expect(errorMessage).toBeVisible();
    await expect(errorMessage).toContainText('resolve conflict');
    
    // Resolve the conflict by modifying the scheduling details
    await page.fill('[data-testid="start-time-input"]', '14:00');
    await page.fill('[data-testid="end-time-input"]', '15:00');
    await page.blur('[data-testid="end-time-input"]');
    
    // Verify alert disappears
    await expect(inlineAlert).not.toBeVisible({ timeout: 1000 });
    
    // Submit the corrected schedule
    await submitButton.click();
    
    // Verify successful submission
    const successMessage = page.locator('[data-testid="success-message"]');
    await expect(successMessage).toBeVisible();
  });

  test('Verify alert display latency under 500ms (boundary)', async ({ page }) => {
    // Start performance tracking
    const startTime = Date.now();
    
    // Trigger a scheduling conflict by entering conflicting data
    await page.fill('[data-testid="resource-input"]', 'Conference Room A');
    await page.fill('[data-testid="date-input"]', '2024-03-15');
    await page.fill('[data-testid="start-time-input"]', '10:00');
    await page.fill('[data-testid="end-time-input"]', '11:00');
    await page.blur('[data-testid="end-time-input"]');
    
    // Wait for inline alert to appear and measure latency
    const inlineAlert = page.locator('[data-testid="inline-alert"]');
    await inlineAlert.waitFor({ state: 'visible', timeout: 1000 });
    const alertDisplayTime = Date.now() - startTime;
    
    // Verify alert display latency is under 500ms
    expect(alertDisplayTime).toBeLessThan(500);
    await expect(inlineAlert).toBeVisible();
    
    // Review the performance metrics
    const performanceMetrics = await page.evaluate(() => {
      const entries = performance.getEntriesByType('measure');
      return entries;
    });
    
    // Resolve the conflict by modifying the scheduling details
    const resolveStartTime = Date.now();
    await page.fill('[data-testid="start-time-input"]', '14:00');
    await page.fill('[data-testid="end-time-input"]', '15:00');
    await page.blur('[data-testid="end-time-input"]');
    
    // Verify the alert removal latency
    await inlineAlert.waitFor({ state: 'hidden', timeout: 1000 });
    const alertRemovalTime = Date.now() - resolveStartTime;
    expect(alertRemovalTime).toBeLessThan(500);
    
    // Submit the corrected schedule
    await page.click('[data-testid="submit-button"]');
    
    // Verify the schedule is saved in the system
    const successMessage = page.locator('[data-testid="success-message"]');
    await expect(successMessage).toBeVisible();
    await expect(successMessage).toContainText('successfully saved');
  });

  test('Ensure alerts prevent form submission until resolved (error-case)', async ({ page }) => {
    // Enter conflicting schedule data
    await page.fill('[data-testid="resource-input"]', 'Conference Room A');
    await page.fill('[data-testid="date-input"]', '2024-03-15');
    await page.fill('[data-testid="start-time-input"]', '10:00');
    await page.fill('[data-testid="end-time-input"]', '11:00');
    await page.blur('[data-testid="end-time-input"]');
    
    // Verify alert displayed and submission disabled
    const inlineAlert = page.locator('[data-testid="inline-alert"]');
    await expect(inlineAlert).toBeVisible({ timeout: 1000 });
    
    // Verify the alert message content
    await expect(inlineAlert).toContainText(/conflict|overlapping|already booked/i);
    
    const submitButton = page.locator('[data-testid="submit-button"]');
    await expect(submitButton).toBeDisabled();
    
    // Set up network request listener to verify no data is sent
    let requestMade = false;
    page.on('request', (request) => {
      if (request.url().includes('/api/schedule') && request.method() === 'POST') {
        requestMade = true;
      }
    });
    
    // Attempt to submit the form by clicking the Submit button
    await submitButton.click({ force: true });
    
    // Verify submission blocked with error message
    const errorMessage = page.locator('[data-testid="submission-error"]');
    await expect(errorMessage).toBeVisible();
    await expect(errorMessage).toContainText(/cannot submit|resolve conflict|fix errors/i);
    
    // Verify that no data is sent to the backend
    await page.waitForTimeout(500);
    expect(requestMade).toBe(false);
    
    // Attempt to submit the form using keyboard shortcut
    await page.press('[data-testid="resource-input"]', 'Enter');
    
    // Verify submission still blocked
    await expect(errorMessage).toBeVisible();
    
    // Resolve the conflict by modifying the scheduling details
    await page.fill('[data-testid="start-time-input"]', '14:00');
    await page.fill('[data-testid="end-time-input"]', '15:00');
    await page.blur('[data-testid="end-time-input"]');
    
    // Verify alert disappears and submit button is enabled
    await expect(inlineAlert).not.toBeVisible({ timeout: 1000 });
    await expect(submitButton).toBeEnabled();
    
    // Submit the corrected schedule
    await submitButton.click();
    
    // Verify confirmation message is displayed
    const confirmationMessage = page.locator('[data-testid="success-message"]');
    await expect(confirmationMessage).toBeVisible();
    await expect(confirmationMessage).toContainText(/success|confirmed|saved/i);
  });
});