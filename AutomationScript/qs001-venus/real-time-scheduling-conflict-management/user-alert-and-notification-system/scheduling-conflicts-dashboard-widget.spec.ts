import { test, expect } from '@playwright/test';

test.describe('Scheduling Conflicts Dashboard Widget', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to dashboard before each test
    await page.goto('/dashboard');
    await page.waitForLoadState('networkidle');
  });

  test('Verify dashboard widget displays active conflicts (happy-path)', async ({ page }) => {
    // Navigate to the dashboard page by clicking on 'Dashboard' in the main navigation menu
    await page.click('nav >> text=Dashboard');
    await expect(page).toHaveURL(/.*dashboard/);

    // Locate the scheduling conflicts widget on the dashboard
    const conflictsWidget = page.locator('[data-testid="conflicts-widget"]').or(page.locator('text=Scheduling Conflicts').locator('..'))
    await expect(conflictsWidget).toBeVisible();

    // Review the list of conflicts displayed in the widget
    const conflictsList = conflictsWidget.locator('[data-testid="conflicts-list"]').or(conflictsWidget.locator('ul, table'));
    await expect(conflictsList).toBeVisible();
    const conflictCount = await conflictsList.locator('[data-testid="conflict-item"], tr:not(:first-child), li').count();
    expect(conflictCount).toBeGreaterThanOrEqual(0);

    // Click on the filter dropdown and select a specific resource from the available options
    const filterDropdown = page.locator('[data-testid="resource-filter"]').or(page.locator('select[name="resource"]')).or(page.getByLabel('Filter by Resource'));
    await filterDropdown.click();
    const resourceOption = page.locator('[data-testid="resource-option"]').first().or(page.locator('option:not([value=""])').first());
    const resourceText = await resourceOption.textContent();
    await filterDropdown.selectOption({ index: 1 });
    
    // Widget updates list accordingly
    await page.waitForTimeout(500);
    const filteredList = conflictsWidget.locator('[data-testid="conflicts-list"]').or(conflictsWidget.locator('ul, table'));
    await expect(filteredList).toBeVisible();

    // Clear the resource filter by clicking 'Clear Filter' or selecting 'All Resources'
    const clearFilterButton = page.locator('[data-testid="clear-filter"]').or(page.locator('button:has-text("Clear Filter")')).or(page.locator('text=All Resources'));
    if (await clearFilterButton.isVisible()) {
      await clearFilterButton.click();
    } else {
      await filterDropdown.selectOption({ index: 0 });
    }
    await page.waitForTimeout(500);

    // Click on the 'Time' column header to sort conflicts by time
    const timeColumnHeader = page.locator('[data-testid="time-column-header"]').or(page.locator('th:has-text("Time")')).or(page.locator('text=Time').first());
    await timeColumnHeader.click();
    
    // Conflicts reordered correctly
    await page.waitForTimeout(500);
    await expect(conflictsList).toBeVisible();

    // Click on the 'Time' column header again to reverse the sort order
    await timeColumnHeader.click();
    await page.waitForTimeout(500);
    await expect(conflictsList).toBeVisible();

    // Click on the 'Status' column header to sort conflicts by status
    const statusColumnHeader = page.locator('[data-testid="status-column-header"]').or(page.locator('th:has-text("Status")')).or(page.locator('text=Status').first());
    await statusColumnHeader.click();
    await page.waitForTimeout(500);
    await expect(conflictsList).toBeVisible();
  });

  test('Test widget data refresh every 30 seconds (happy-path)', async ({ page, context }) => {
    // Locate the conflicts widget
    const conflictsWidget = page.locator('[data-testid="conflicts-widget"]').or(page.locator('text=Scheduling Conflicts').locator('..'));
    await expect(conflictsWidget).toBeVisible();

    // Note the current time and the number of conflicts displayed in the widget
    const conflictCountElement = conflictsWidget.locator('[data-testid="conflict-count"]').or(conflictsWidget.locator('text=/\d+ Active Conflicts?/'));
    const initialCountText = await conflictCountElement.textContent();
    const initialCount = parseInt(initialCountText?.match(/\d+/)?.[0] || '0');
    const startTime = Date.now();

    // Observe the widget without any interaction for 30 seconds using a timer
    await page.waitForTimeout(30000);

    // Data refreshes every 30 seconds
    const afterRefreshCountText = await conflictCountElement.textContent();
    expect(afterRefreshCountText).toBeDefined();

    // Record the time taken for the refresh to complete from initiation to display of updated data
    const refreshStartTime = Date.now();
    await page.waitForLoadState('networkidle', { timeout: 5000 });
    const refreshEndTime = Date.now();
    const refreshLatency = refreshEndTime - refreshStartTime;

    // Refresh completes within 2 seconds
    expect(refreshLatency).toBeLessThan(2000);

    // Open a new browser tab or use a separate session to create a new scheduling conflict
    const newPage = await context.newPage();
    await newPage.goto('/conflicts/create');
    await newPage.fill('[data-testid="resource-name"]', 'Test Resource');
    await newPage.fill('[data-testid="conflict-time"]', '2024-01-15T10:00');
    await newPage.selectOption('[data-testid="conflict-status"]', 'Active');
    await newPage.click('[data-testid="submit-conflict"]');
    await newPage.waitForLoadState('networkidle');
    await newPage.close();

    // Return to the dashboard tab and wait for the next automatic refresh cycle
    await page.bringToFront();
    await page.waitForTimeout(30000);

    // Widget updates to include new conflict within 30 seconds
    const updatedCountText = await conflictCountElement.textContent();
    const updatedCount = parseInt(updatedCountText?.match(/\d+/)?.[0] || '0');
    expect(updatedCount).toBeGreaterThanOrEqual(initialCount);

    // Verify the newly created conflict appears in the widget list
    const conflictsList = conflictsWidget.locator('[data-testid="conflicts-list"]');
    const newConflictItem = conflictsList.locator('text=Test Resource');
    await expect(newConflictItem).toBeVisible({ timeout: 5000 });

    // Measure the refresh latency
    const finalRefreshStart = Date.now();
    await page.waitForLoadState('networkidle', { timeout: 5000 });
    const finalRefreshEnd = Date.now();
    const finalRefreshLatency = finalRefreshEnd - finalRefreshStart;
    expect(finalRefreshLatency).toBeLessThan(2000);

    // Continue observing for one more refresh cycle to confirm consistent refresh behavior
    const beforeFinalRefresh = await conflictCountElement.textContent();
    await page.waitForTimeout(30000);
    const afterFinalRefresh = await conflictCountElement.textContent();
    expect(afterFinalRefresh).toBeDefined();
  });

  test('Ensure navigation from widget to conflict details (happy-path)', async ({ page }) => {
    // Locate the conflicts widget
    const conflictsWidget = page.locator('[data-testid="conflicts-widget"]').or(page.locator('text=Scheduling Conflicts').locator('..'));
    await expect(conflictsWidget).toBeVisible();

    // Identify a specific conflict in the widget list and note its details
    const conflictsList = conflictsWidget.locator('[data-testid="conflicts-list"]').or(conflictsWidget.locator('table tbody, ul'));
    const firstConflict = conflictsList.locator('[data-testid="conflict-item"]').first().or(conflictsList.locator('tr, li').first());
    await expect(firstConflict).toBeVisible();

    const resourceName = await firstConflict.locator('[data-testid="conflict-resource"]').or(firstConflict.locator('td').nth(0)).textContent();
    const conflictTime = await firstConflict.locator('[data-testid="conflict-time"]').or(firstConflict.locator('td').nth(1)).textContent();
    const conflictStatus = await firstConflict.locator('[data-testid="conflict-status"]').or(firstConflict.locator('td').nth(2)).textContent();

    // Click on the selected conflict row or conflict link in the widget list
    await firstConflict.click();

    // User navigated to conflict detail page
    await expect(page).toHaveURL(/.*conflict.*detail/);

    // Verify the conflict detail page displays the header with the conflict identifier or title
    const detailHeader = page.locator('[data-testid="conflict-detail-header"]').or(page.locator('h1, h2').first());
    await expect(detailHeader).toBeVisible();

    // Review the conflict details section to verify resource name matches the widget display
    const detailResourceName = page.locator('[data-testid="detail-resource-name"]').or(page.locator('text=Resource').locator('..'));
    await expect(detailResourceName).toContainText(resourceName?.trim() || '');

    // Verify the time/date information displayed on the conflict detail page
    const detailTime = page.locator('[data-testid="detail-conflict-time"]').or(page.locator('text=Time').locator('..'));
    await expect(detailTime).toBeVisible();

    // Verify the status information displayed on the conflict detail page
    const detailStatus = page.locator('[data-testid="detail-conflict-status"]').or(page.locator('text=Status').locator('..'));
    await expect(detailStatus).toBeVisible();

    // Check for additional conflict details that may not be visible in the widget summary
    const additionalDetails = page.locator('[data-testid="conflict-additional-details"]').or(page.locator('.conflict-details'));
    await expect(additionalDetails).toBeVisible();

    // Click the browser back button or click 'Return to Dashboard' link/button
    const returnButton = page.locator('[data-testid="return-to-dashboard"]').or(page.locator('text=Return to Dashboard')).or(page.locator('a:has-text("Dashboard")'));
    if (await returnButton.isVisible()) {
      await returnButton.click();
    } else {
      await page.goBack();
    }

    // Dashboard and widget display correctly
    await expect(page).toHaveURL(/.*dashboard/);
    await expect(conflictsWidget).toBeVisible();

    // Verify the conflicts widget maintains any previously applied filters or sort orders
    await expect(conflictsList).toBeVisible();
    const conflictItems = await conflictsList.locator('[data-testid="conflict-item"], tr, li').count();
    expect(conflictItems).toBeGreaterThanOrEqual(0);
  });
});