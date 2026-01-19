import { test, expect } from '@playwright/test';

test.describe('Error Handling During Conflict Detection', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to scheduling interface
    await page.goto('/scheduling');
    await expect(page).toHaveURL(/.*scheduling/);
  });

  test('Verify graceful handling of backend errors during conflict detection', async ({ page }) => {
    // Navigate to the scheduling interface and prepare to create or modify a schedule
    await page.waitForSelector('[data-testid="schedule-form"]');
    
    // Configure backend to simulate an error during conflict detection
    await page.route('**/api/conflict-detection', async (route) => {
      await route.abort('failed');
    });
    
    // Fill in scheduling details
    await page.fill('[data-testid="appointment-title"]', 'Test Appointment');
    await page.fill('[data-testid="appointment-date"]', '2024-03-15');
    await page.fill('[data-testid="appointment-time"]', '10:00');
    await page.selectOption('[data-testid="resource-select"]', 'Conference Room A');
    
    // Initiate conflict detection by attempting to schedule an appointment
    await page.click('[data-testid="check-conflicts-button"]');
    
    // Observe the error message displayed to the user
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText(/unable to check for conflicts|error occurred/i);
    
    // Verify that retry and cancel options are available in the error message dialog
    await expect(page.locator('[data-testid="retry-button"]')).toBeVisible();
    await expect(page.locator('[data-testid="cancel-button"]')).toBeVisible();
    
    // Click the 'Retry' button to attempt conflict detection again
    await page.click('[data-testid="retry-button"]');
    
    // Wait for retry attempt
    await page.waitForTimeout(1000);
    
    // Trigger the error scenario again and click 'Cancel' button
    await page.click('[data-testid="check-conflicts-button"]');
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await page.click('[data-testid="cancel-button"]');
    
    // Verify system remains stable and responsive after error handling
    await expect(page.locator('[data-testid="schedule-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="appointment-title"]')).toBeEnabled();
  });

  test('Ensure errors are logged with sufficient detail', async ({ page, context }) => {
    // Access the system error logs or logging dashboard before triggering the error
    await page.goto('/admin/logs');
    await expect(page.locator('[data-testid="error-logs-table"]')).toBeVisible();
    
    // Note the current timestamp
    const beforeTimestamp = new Date().toISOString();
    const initialLogCount = await page.locator('[data-testid="log-entry"]').count();
    
    // Navigate back to scheduling interface
    await page.goto('/scheduling');
    
    // Configure backend to simulate a specific error during conflict detection
    await page.route('**/api/conflict-detection', async (route) => {
      await route.fulfill({
        status: 500,
        contentType: 'application/json',
        body: JSON.stringify({
          error: 'Database connection failure',
          code: 'DB_CONNECTION_ERROR'
        })
      });
    });
    
    // Fill in scheduling details
    await page.fill('[data-testid="appointment-title"]', 'Error Test Appointment');
    await page.fill('[data-testid="appointment-date"]', '2024-03-20');
    await page.fill('[data-testid="appointment-time"]', '14:00');
    await page.selectOption('[data-testid="resource-select"]', 'Meeting Room B');
    
    // Trigger the error scenario by initiating conflict detection
    await page.click('[data-testid="check-conflicts-button"]');
    
    // Wait for error to be processed
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await page.waitForTimeout(2000);
    
    // Access the system error logs immediately after the error occurs
    await page.goto('/admin/logs');
    await page.waitForSelector('[data-testid="error-logs-table"]');
    
    // Refresh logs to get latest entries
    await page.click('[data-testid="refresh-logs-button"]');
    await page.waitForTimeout(1000);
    
    // Get the most recent log entry
    const latestLogEntry = page.locator('[data-testid="log-entry"]').first();
    await expect(latestLogEntry).toBeVisible();
    
    // Verify the error log contains accurate timestamp
    const logTimestamp = await latestLogEntry.locator('[data-testid="log-timestamp"]').textContent();
    expect(logTimestamp).toBeTruthy();
    
    // Verify the error log contains user context information
    await expect(latestLogEntry.locator('[data-testid="log-user-context"]')).toBeVisible();
    const userContext = await latestLogEntry.locator('[data-testid="log-user-context"]').textContent();
    expect(userContext).toMatch(/user|session/i);
    
    // Verify the error log contains operation context
    await expect(latestLogEntry.locator('[data-testid="log-operation"]')).toBeVisible();
    const operationContext = await latestLogEntry.locator('[data-testid="log-operation"]').textContent();
    expect(operationContext).toMatch(/conflict detection|scheduling/i);
    
    // Verify the error log contains technical error details
    await latestLogEntry.click();
    await expect(page.locator('[data-testid="log-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="log-error-type"]')).toBeVisible();
    await expect(page.locator('[data-testid="log-error-code"]')).toContainText(/DB_CONNECTION_ERROR|500/i);
    
    // Verify the error log contains severity level classification
    await expect(page.locator('[data-testid="log-severity"]')).toBeVisible();
    const severity = await page.locator('[data-testid="log-severity"]').textContent();
    expect(severity).toMatch(/error|critical|high/i);
    
    // Close details panel
    await page.click('[data-testid="close-details-button"]');
    
    // Trigger multiple different error scenarios and verify each is logged distinctly
    const errorScenarios = [
      { route: '**/api/conflict-detection', status: 503, error: 'Service Unavailable' },
      { route: '**/api/conflict-detection', status: 408, error: 'Request Timeout' },
      { route: '**/api/conflict-detection', status: 502, error: 'Bad Gateway' }
    ];
    
    for (const scenario of errorScenarios) {
      await page.goto('/scheduling');
      
      await page.route(scenario.route, async (route) => {
        await route.fulfill({
          status: scenario.status,
          contentType: 'application/json',
          body: JSON.stringify({ error: scenario.error })
        });
      });
      
      await page.fill('[data-testid="appointment-title"]', `Test ${scenario.error}`);
      await page.fill('[data-testid="appointment-date"]', '2024-03-25');
      await page.fill('[data-testid="appointment-time"]', '16:00');
      await page.click('[data-testid="check-conflicts-button"]');
      await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
      await page.waitForTimeout(1000);
    }
    
    // Verify all errors are logged distinctly
    await page.goto('/admin/logs');
    await page.click('[data-testid="refresh-logs-button"]');
    await page.waitForTimeout(1000);
    
    const finalLogCount = await page.locator('[data-testid="log-entry"]').count();
    expect(finalLogCount).toBeGreaterThan(initialLogCount);
    expect(finalLogCount).toBeGreaterThanOrEqual(initialLogCount + errorScenarios.length);
  });

  test('User can retry conflict detection after error', async ({ page }) => {
    // Navigate to scheduling interface
    await page.waitForSelector('[data-testid="schedule-form"]');
    
    let requestCount = 0;
    
    // Configure backend to fail first attempt, succeed on retry
    await page.route('**/api/conflict-detection', async (route) => {
      requestCount++;
      if (requestCount === 1) {
        await route.fulfill({
          status: 500,
          contentType: 'application/json',
          body: JSON.stringify({ error: 'Temporary error' })
        });
      } else {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ conflicts: [], message: 'No conflicts found' })
        });
      }
    });
    
    // Fill in scheduling details
    await page.fill('[data-testid="appointment-title"]', 'Retry Test Appointment');
    await page.fill('[data-testid="appointment-date"]', '2024-04-01');
    await page.fill('[data-testid="appointment-time"]', '09:00');
    
    // Initiate conflict detection
    await page.click('[data-testid="check-conflicts-button"]');
    
    // Verify error message appears
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    
    // User retries conflict detection
    await page.click('[data-testid="retry-button"]');
    
    // Expected Result: System processes retry successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText(/no conflicts/i);
    await expect(page.locator('[data-testid="error-message"]')).not.toBeVisible();
  });

  test('User can cancel operation after error', async ({ page }) => {
    // Navigate to scheduling interface
    await page.waitForSelector('[data-testid="schedule-form"]');
    
    // Configure backend to simulate error
    await page.route('**/api/conflict-detection', async (route) => {
      await route.fulfill({
        status: 500,
        contentType: 'application/json',
        body: JSON.stringify({ error: 'Service error' })
      });
    });
    
    // Fill in scheduling details
    await page.fill('[data-testid="appointment-title"]', 'Cancel Test Appointment');
    await page.fill('[data-testid="appointment-date"]', '2024-04-05');
    await page.fill('[data-testid="appointment-time"]', '11:00');
    
    // Initiate conflict detection
    await page.click('[data-testid="check-conflicts-button"]');
    
    // Verify error message appears
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    
    // User cancels the operation
    await page.click('[data-testid="cancel-button"]');
    
    // Expected Result: System allows cancellation and returns to stable state
    await expect(page.locator('[data-testid="error-message"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="schedule-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="appointment-title"]')).toHaveValue('Cancel Test Appointment');
  });
});