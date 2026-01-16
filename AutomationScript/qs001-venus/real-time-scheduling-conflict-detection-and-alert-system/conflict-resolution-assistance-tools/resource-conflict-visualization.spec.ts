import { test, expect } from '@playwright/test';

test.describe('Resource Conflict Visualization Dashboard', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the resource conflict dashboard
    await page.goto('/resource-conflicts/dashboard');
    // Wait for dashboard to be fully loaded
    await page.waitForLoadState('networkidle');
  });

  test('Validate visual display of double booking conflicts', async ({ page }) => {
    // Action: Access the resource conflict dashboard
    // Expected Result: Dashboard displays current double booking conflicts visually
    await expect(page.locator('[data-testid="conflict-dashboard"]')).toBeVisible();
    
    // Observe the visual display of the dashboard
    const conflictsList = page.locator('[data-testid="conflicts-list"]');
    await expect(conflictsList).toBeVisible();
    
    // Review the conflict details shown on the dashboard
    const conflictItems = page.locator('[data-testid="conflict-item"]');
    const initialConflictCount = await conflictItems.count();
    
    // Verify the visual indicators for conflict severity
    if (initialConflictCount > 0) {
      await expect(conflictItems.first().locator('[data-testid="severity-indicator"]')).toBeVisible();
      await expect(conflictItems.first().locator('[data-testid="priority-marker"]')).toBeVisible();
    }
    
    // Note the timestamp when dashboard is fully loaded
    const loadStartTime = Date.now();
    
    // Action: Trigger a new double booking conflict
    // Create a new double booking conflict by scheduling the same resource for overlapping time slots
    await page.click('[data-testid="create-test-conflict-btn"]');
    await page.fill('[data-testid="resource-id-input"]', 'CONF-ROOM-101');
    await page.fill('[data-testid="start-time-input"]', '2024-01-15T10:00');
    await page.fill('[data-testid="end-time-input"]', '2024-01-15T11:00');
    await page.click('[data-testid="submit-booking-btn"]');
    
    // Create overlapping booking for the same resource
    await page.click('[data-testid="create-test-conflict-btn"]');
    await page.fill('[data-testid="resource-id-input"]', 'CONF-ROOM-101');
    await page.fill('[data-testid="start-time-input"]', '2024-01-15T10:30');
    await page.fill('[data-testid="end-time-input"]', '2024-01-15T11:30');
    await page.click('[data-testid="submit-booking-btn"]');
    
    // Expected Result: Dashboard updates to show new conflict within 3 seconds
    // Monitor the resource conflict dashboard for automatic updates
    await page.waitForTimeout(500); // Brief wait for conflict detection
    
    const updateStartTime = Date.now();
    await page.waitForSelector('[data-testid="conflict-item"]:has-text("CONF-ROOM-101")', { timeout: 3000 });
    const updateEndTime = Date.now();
    const updateDuration = updateEndTime - updateStartTime;
    
    // Verify the newly created conflict appears on the dashboard
    const newConflictItem = page.locator('[data-testid="conflict-item"]').filter({ hasText: 'CONF-ROOM-101' });
    await expect(newConflictItem).toBeVisible();
    
    // Confirm all conflict details are accurate for the new conflict
    await expect(newConflictItem.locator('[data-testid="resource-name"]')).toContainText('CONF-ROOM-101');
    await expect(newConflictItem.locator('[data-testid="conflict-time"]')).toBeVisible();
    
    // Verify update happened within 3 seconds
    expect(updateDuration).toBeLessThan(3000);
  });

  test('Verify filtering by resource type and date', async ({ page }) => {
    // Locate the filter controls on the resource conflict dashboard
    const filterSection = page.locator('[data-testid="filter-section"]');
    await expect(filterSection).toBeVisible();
    
    // Click on the resource type filter dropdown
    await page.click('[data-testid="resource-type-filter"]');
    
    // Select a specific resource type from the dropdown (e.g., 'Conference Rooms')
    await page.click('[data-testid="filter-option-conference-rooms"]');
    
    // Observe the conflicts displayed on the dashboard
    await page.waitForTimeout(500); // Wait for filter to apply
    
    // Expected Result: Displayed conflicts match filter criteria
    const filteredConflicts = page.locator('[data-testid="conflict-item"]');
    const conflictCount = await filteredConflicts.count();
    
    // Verify the conflict count updates to reflect filtered results
    const conflictCountDisplay = page.locator('[data-testid="conflict-count"]');
    await expect(conflictCountDisplay).toContainText(conflictCount.toString());
    
    // Verify each displayed conflict matches the resource type filter
    if (conflictCount > 0) {
      for (let i = 0; i < conflictCount; i++) {
        const conflictItem = filteredConflicts.nth(i);
        const resourceType = await conflictItem.locator('[data-testid="resource-type"]').textContent();
        expect(resourceType).toContain('Conference Room');
      }
    }
    
    // Locate the date filter control and click to open date picker
    await page.click('[data-testid="date-filter"]');
    
    // Select a specific date or date range for filtering
    await page.fill('[data-testid="date-from-input"]', '2024-01-15');
    await page.fill('[data-testid="date-to-input"]', '2024-01-20');
    await page.click('[data-testid="apply-date-filter-btn"]');
    
    // Review the displayed conflicts after applying date filter
    await page.waitForTimeout(500);
    const dateFilteredConflicts = page.locator('[data-testid="conflict-item"]');
    const dateFilteredCount = await dateFilteredConflicts.count();
    
    // Verify each displayed conflict matches the applied filter criteria
    if (dateFilteredCount > 0) {
      for (let i = 0; i < dateFilteredCount; i++) {
        const conflictItem = dateFilteredConflicts.nth(i);
        const resourceType = await conflictItem.locator('[data-testid="resource-type"]').textContent();
        expect(resourceType).toContain('Conference Room');
        
        const conflictDate = await conflictItem.locator('[data-testid="conflict-date"]').textContent();
        expect(conflictDate).toBeTruthy();
      }
    }
    
    // Clear one filter (e.g., resource type) while keeping the date filter active
    await page.click('[data-testid="clear-resource-type-filter"]');
    await page.waitForTimeout(500);
    
    // Verify conflicts update after clearing one filter
    const partialFilteredConflicts = page.locator('[data-testid="conflict-item"]');
    await expect(partialFilteredConflicts.first()).toBeVisible();
    
    // Clear all filters
    await page.click('[data-testid="clear-all-filters-btn"]');
    await page.waitForTimeout(500);
    
    // Verify all conflicts are displayed after clearing filters
    const allConflicts = page.locator('[data-testid="conflict-item"]');
    await expect(allConflicts.first()).toBeVisible();
  });

  test('Test integration with resolution tools', async ({ page }) => {
    // Identify a double booking conflict on the dashboard
    const conflictItem = page.locator('[data-testid="conflict-item"]').first();
    await expect(conflictItem).toBeVisible();
    
    // Store conflict data for verification
    const conflictResourceName = await conflictItem.locator('[data-testid="resource-name"]').textContent();
    const conflictTime = await conflictItem.locator('[data-testid="conflict-time"]').textContent();
    
    // Click or select the identified conflict
    await conflictItem.click();
    
    // Verify conflict is selected
    await expect(conflictItem).toHaveClass(/selected|active/);
    
    // Locate the resolution action button or option (e.g., 'Resolve', 'Manage', or 'Open Resolution Tool')
    const resolutionButton = page.locator('[data-testid="resolve-conflict-btn"]');
    await expect(resolutionButton).toBeVisible();
    await expect(resolutionButton).toBeEnabled();
    
    // Action: Click the resolution action button to initiate the resolution workflow
    await resolutionButton.click();
    
    // Expected Result: Resolution tool launches with selected conflict data
    // Wait for the resolution tool to open
    const resolutionTool = page.locator('[data-testid="resolution-tool"]');
    await expect(resolutionTool).toBeVisible({ timeout: 5000 });
    
    // Verify the resolution tool displays the selected conflict data
    const resolutionResourceName = page.locator('[data-testid="resolution-resource-name"]');
    await expect(resolutionResourceName).toBeVisible();
    await expect(resolutionResourceName).toContainText(conflictResourceName || '');
    
    // Check that all relevant conflict data is accurately transferred
    const resolutionConflictTime = page.locator('[data-testid="resolution-conflict-time"]');
    await expect(resolutionConflictTime).toBeVisible();
    await expect(resolutionConflictTime).toContainText(conflictTime || '');
    
    const resolutionConflictDetails = page.locator('[data-testid="resolution-conflict-details"]');
    await expect(resolutionConflictDetails).toBeVisible();
    
    // Verify resolution options are available in the tool
    const resolutionOptions = page.locator('[data-testid="resolution-options"]');
    await expect(resolutionOptions).toBeVisible();
    
    const reassignOption = page.locator('[data-testid="resolution-option-reassign"]');
    const cancelOption = page.locator('[data-testid="resolution-option-cancel"]');
    const modifyOption = page.locator('[data-testid="resolution-option-modify"]');
    
    await expect(reassignOption).toBeVisible();
    await expect(cancelOption).toBeVisible();
    await expect(modifyOption).toBeVisible();
    
    // Confirm the integration maintains context and user session
    const userContext = page.locator('[data-testid="user-context"]');
    await expect(userContext).toBeVisible();
    
    const sessionIndicator = page.locator('[data-testid="session-indicator"]');
    await expect(sessionIndicator).toHaveClass(/active|authenticated/);
  });
});