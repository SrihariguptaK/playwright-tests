import { test, expect } from '@playwright/test';

test.describe('Employee Presence Heatmaps', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to dashboard before each test
    await page.goto('/dashboard');
    // Wait for dashboard to load
    await page.waitForLoadState('networkidle');
  });

  test('Validate heatmap display and filtering', async ({ page }) => {
    // Navigate to the dashboard page
    await page.goto('/dashboard');
    await page.waitForSelector('[data-testid="heatmap-section"]', { timeout: 10000 });

    // Locate the date filter dropdown on the heatmap section
    const dateFilter = page.locator('[data-testid="heatmap-date-filter"]');
    await expect(dateFilter).toBeVisible();

    // Select a specific date from the date filter dropdown
    await dateFilter.click();
    await page.locator('[data-testid="date-option-2024-01-15"]').click();

    // Locate the department filter dropdown on the heatmap section
    const departmentFilter = page.locator('[data-testid="heatmap-department-filter"]');
    await expect(departmentFilter).toBeVisible();

    // Select a specific department from the department filter dropdown
    await departmentFilter.click();
    await page.locator('[data-testid="department-option-engineering"]').click();

    // Wait for heatmap to update after filters are applied
    await page.waitForResponse(response => 
      response.url().includes('/api/dashboard/heatmap') && response.status() === 200
    );

    // Verify the heatmap displays color-coded presence data matching the applied filters
    const heatmap = page.locator('[data-testid="heatmap-visualization"]');
    await expect(heatmap).toBeVisible();
    await expect(heatmap).toHaveAttribute('data-filtered', 'true');

    // Verify heatmap has rendered with data
    const heatmapCanvas = page.locator('[data-testid="heatmap-canvas"]');
    await expect(heatmapCanvas).toBeVisible();

    // Use mouse scroll or zoom controls to zoom into a specific area of the heatmap
    const zoomInButton = page.locator('[data-testid="heatmap-zoom-in"]');
    await zoomInButton.click();
    await page.waitForTimeout(500);

    // Hover mouse cursor over a specific location on the heatmap
    const heatmapArea = page.locator('[data-testid="heatmap-canvas"]');
    await heatmapArea.hover({ position: { x: 100, y: 100 } });

    // Verify detailed presence information is displayed on hover
    const hoverTooltip = page.locator('[data-testid="heatmap-tooltip"]');
    await expect(hoverTooltip).toBeVisible({ timeout: 3000 });
    await expect(hoverTooltip).toContainText(/employees|presence|count/i);

    // Move cursor to different locations on the heatmap
    await heatmapArea.hover({ position: { x: 200, y: 150 } });
    await expect(hoverTooltip).toBeVisible();

    // Locate and click the 'Export' or 'Download' button for the heatmap
    const exportButton = page.locator('[data-testid="heatmap-export-button"]');
    await expect(exportButton).toBeVisible();

    // Set up download listener before clicking export
    const downloadPromise = page.waitForEvent('download');
    await exportButton.click();

    // Confirm the export action if prompted and wait for download to complete
    const confirmDialog = page.locator('[data-testid="export-confirm-dialog"]');
    if (await confirmDialog.isVisible({ timeout: 2000 }).catch(() => false)) {
      await page.locator('[data-testid="confirm-export-button"]').click();
    }

    // Wait for download and verify PNG image downloads correctly
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toMatch(/heatmap.*\.png$/i);
    
    // Verify download completed successfully
    const path = await download.path();
    expect(path).toBeTruthy();
  });

  test('Test heatmap load performance', async ({ page }) => {
    // Start timer to measure load time
    const startTime = Date.now();

    // Navigate to the dashboard page containing the heatmap visualization
    const navigationPromise = page.goto('/dashboard');

    // Wait for the heatmap API call to complete
    const apiResponsePromise = page.waitForResponse(
      response => response.url().includes('/api/dashboard/heatmap') && response.status() === 200,
      { timeout: 5000 }
    );

    await navigationPromise;
    const apiResponse = await apiResponsePromise;

    // Verify API call completed successfully with 200 status code
    expect(apiResponse.status()).toBe(200);

    // Wait for the heatmap visualization to fully render with all visual elements displayed
    await page.waitForSelector('[data-testid="heatmap-visualization"]', { state: 'visible' });
    await page.waitForSelector('[data-testid="heatmap-canvas"]', { state: 'visible' });

    // Wait for heatmap to be fully loaded (check for loading indicator to disappear)
    await page.waitForSelector('[data-testid="heatmap-loading"]', { state: 'hidden', timeout: 5000 }).catch(() => {});

    // Ensure all heatmap elements are rendered
    const heatmapLegend = page.locator('[data-testid="heatmap-legend"]');
    await expect(heatmapLegend).toBeVisible();

    // Stop timer and record the total load time
    const endTime = Date.now();
    const loadTime = endTime - startTime;

    // Verify heatmap loads within 4 seconds (4000ms)
    expect(loadTime).toBeLessThan(4000);
    console.log(`Heatmap load time: ${loadTime}ms`);

    // Interact with the heatmap by hovering over a location to confirm full functionality
    const heatmapCanvas = page.locator('[data-testid="heatmap-canvas"]');
    await heatmapCanvas.hover({ position: { x: 150, y: 150 } });

    // Verify hover interaction works (tooltip appears)
    const tooltip = page.locator('[data-testid="heatmap-tooltip"]');
    await expect(tooltip).toBeVisible({ timeout: 2000 });

    // Verify tooltip contains presence data
    await expect(tooltip).toContainText(/location|department|employees|presence/i);

    // Verify heatmap is interactive and responsive
    const zoomControls = page.locator('[data-testid="heatmap-zoom-controls"]');
    await expect(zoomControls).toBeVisible();
  });
});