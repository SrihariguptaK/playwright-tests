import { test, expect } from '@playwright/test';

test.describe('Conflict Management Interface', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the scheduling system and login
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'scheduler@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Verify conflict list display and filtering', async ({ page }) => {
    // Navigate to the conflict management interface from the main dashboard
    await page.click('[data-testid="conflict-management-link"]');
    await expect(page).toHaveURL(/.*conflicts/);
    
    // Verify the initial conflict list contains all active conflicts
    await expect(page.locator('[data-testid="conflict-list"]')).toBeVisible();
    const initialConflictCount = await page.locator('[data-testid="conflict-item"]').count();
    expect(initialConflictCount).toBeGreaterThan(0);
    
    // Apply date filter by selecting a specific date range (e.g., last 7 days)
    await page.click('[data-testid="date-filter-dropdown"]');
    await page.click('[data-testid="date-filter-last-7-days"]');
    await page.waitForTimeout(500);
    
    // Apply resource filter by selecting a specific resource from the dropdown
    await page.click('[data-testid="resource-filter-dropdown"]');
    await page.click('[data-testid="resource-filter-option-1"]');
    await page.waitForTimeout(500);
    
    // Verify list updates to show filtered conflicts
    const filteredConflictCount = await page.locator('[data-testid="conflict-item"]').count();
    expect(filteredConflictCount).toBeLessThanOrEqual(initialConflictCount);
    
    // Click on the severity column header to sort conflicts by severity
    await page.click('[data-testid="severity-column-header"]');
    await page.waitForTimeout(300);
    
    // Verify list is sorted accordingly
    const firstConflictSeverity = await page.locator('[data-testid="conflict-item"]').first().locator('[data-testid="severity-value"]').textContent();
    expect(firstConflictSeverity).toBeTruthy();
    
    // Click on the severity column header again to reverse sort order
    await page.click('[data-testid="severity-column-header"]');
    await page.waitForTimeout(300);
    
    const firstConflictSeverityReversed = await page.locator('[data-testid="conflict-item"]').first().locator('[data-testid="severity-value"]').textContent();
    expect(firstConflictSeverityReversed).toBeTruthy();
    
    // Clear all applied filters
    await page.click('[data-testid="clear-filters-button"]');
    await page.waitForTimeout(500);
    
    const clearedConflictCount = await page.locator('[data-testid="conflict-item"]').count();
    expect(clearedConflictCount).toBe(initialConflictCount);
  });

  test('Test editing and resolving conflicts', async ({ page }) => {
    // Navigate to conflict management interface
    await page.click('[data-testid="conflict-management-link"]');
    await expect(page).toHaveURL(/.*conflicts/);
    
    // Select a specific conflict from the active conflicts list by clicking on it
    await page.click('[data-testid="conflict-item"]');
    
    // Verify conflict details are displayed
    await expect(page.locator('[data-testid="conflict-details-panel"]')).toBeVisible();
    
    // Review the conflict details to understand the scheduling issue
    const conflictId = await page.locator('[data-testid="conflict-id"]').textContent();
    expect(conflictId).toBeTruthy();
    
    // Click the 'Edit Schedule' button within the conflict details panel
    await page.click('[data-testid="edit-schedule-button"]');
    await expect(page.locator('[data-testid="schedule-editor"]')).toBeVisible();
    
    // Modify the schedule by changing the time slot or resource to resolve the conflict
    await page.click('[data-testid="time-slot-dropdown"]');
    await page.click('[data-testid="time-slot-option-2"]');
    await page.click('[data-testid="resource-dropdown"]');
    await page.click('[data-testid="resource-option-3"]');
    
    // Click the 'Save Changes' button to commit the schedule modification
    await page.click('[data-testid="save-changes-button"]');
    
    // Verify changes are saved successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Changes saved successfully');
    
    // Return to the active conflicts list view
    await page.click('[data-testid="back-to-list-button"]');
    
    // Verify conflict is marked resolved and removed from active list
    const conflictExists = await page.locator(`[data-testid="conflict-item"][data-conflict-id="${conflictId}"]`).count();
    expect(conflictExists).toBe(0);
    
    // Navigate to the resolved conflicts section or history
    await page.click('[data-testid="resolved-conflicts-tab"]');
    await expect(page.locator('[data-testid="resolved-conflicts-list"]')).toBeVisible();
    
    // Verify the resolved conflict appears in the resolved list
    const resolvedConflict = page.locator(`[data-testid="resolved-conflict-item"][data-conflict-id="${conflictId}"]`);
    await expect(resolvedConflict).toBeVisible();
  });

  test('Ensure real-time conflict status updates', async ({ page, context }) => {
    // Navigate to conflict management interface in first session
    await page.click('[data-testid="conflict-management-link"]');
    await expect(page).toHaveURL(/.*conflicts/);
    
    // In the first session, note the current list of active conflicts and their count
    const initialConflictCount = await page.locator('[data-testid="conflict-item"]').count();
    const firstConflictId = await page.locator('[data-testid="conflict-item"]').first().getAttribute('data-conflict-id');
    
    // Open a second session (new page in same context)
    const secondPage = await context.newPage();
    await secondPage.goto('/login');
    await secondPage.fill('[data-testid="username-input"]', 'scheduler@example.com');
    await secondPage.fill('[data-testid="password-input"]', 'password123');
    await secondPage.click('[data-testid="login-button"]');
    await expect(secondPage).toHaveURL(/.*dashboard/);
    
    // In the second session, navigate to conflicts
    await secondPage.click('[data-testid="conflict-management-link"]');
    await expect(secondPage).toHaveURL(/.*conflicts/);
    
    // Select and resolve one of the active conflicts by editing the schedule and saving changes
    await secondPage.click(`[data-testid="conflict-item"][data-conflict-id="${firstConflictId}"]`);
    await expect(secondPage.locator('[data-testid="conflict-details-panel"]')).toBeVisible();
    await secondPage.click('[data-testid="edit-schedule-button"]');
    await secondPage.click('[data-testid="time-slot-dropdown"]');
    await secondPage.click('[data-testid="time-slot-option-3"]');
    await secondPage.click('[data-testid="save-changes-button"]');
    await expect(secondPage.locator('[data-testid="success-message"]')).toBeVisible();
    
    // In the first session, observe the conflict list without manually refreshing the page
    // Wait for real-time update (WebSocket or polling)
    await page.waitForTimeout(3000);
    
    // Verify conflict status updates in real-time on interface
    const updatedConflictCount = await page.locator('[data-testid="conflict-item"]').count();
    expect(updatedConflictCount).toBeLessThan(initialConflictCount);
    
    // Manually refresh the conflict list in the first session by clicking the refresh button
    await page.click('[data-testid="refresh-button"]');
    await page.waitForTimeout(1000);
    
    // Verify resolved conflict no longer appears
    const conflictStillExists = await page.locator(`[data-testid="conflict-item"][data-conflict-id="${firstConflictId}"]`).count();
    expect(conflictStillExists).toBe(0);
    
    // Click on the 'Resolution History' or 'Audit Trail' link from the conflict management interface
    await page.click('[data-testid="resolution-history-link"]');
    await expect(page.locator('[data-testid="resolution-history-panel"]')).toBeVisible();
    
    // Locate the recently resolved conflict in the resolution history
    const resolvedConflictInHistory = page.locator(`[data-testid="history-item"][data-conflict-id="${firstConflictId}"]`);
    await expect(resolvedConflictInHistory).toBeVisible();
    
    // Verify the audit trail entry for completeness
    await expect(resolvedConflictInHistory.locator('[data-testid="resolution-timestamp"]')).toBeVisible();
    await expect(resolvedConflictInHistory.locator('[data-testid="resolved-by"]')).toContainText('scheduler@example.com');
    await expect(resolvedConflictInHistory.locator('[data-testid="resolution-action"]')).toContainText('Schedule Modified');
    
    // Verify history shows accurate resolution details
    const resolutionDetails = await resolvedConflictInHistory.locator('[data-testid="resolution-details"]').textContent();
    expect(resolutionDetails).toBeTruthy();
    
    // Close second page
    await secondPage.close();
  });
});