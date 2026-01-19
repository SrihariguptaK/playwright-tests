import { test, expect } from '@playwright/test';

test.describe('Schedule Report Team Filtering', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as Project Manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'project.manager@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Filter schedule report by valid team (happy-path)', async ({ page }) => {
    // Step 1: Navigate to Schedule Reporting section from the main dashboard
    await page.click('[data-testid="schedule-reporting-link"]');
    
    // Expected Result: Schedule report UI is displayed
    await expect(page.locator('[data-testid="schedule-report-container"]')).toBeVisible();
    await expect(page.locator('h1, h2').filter({ hasText: /Schedule Report/i })).toBeVisible();
    
    // Step 2: Click on the team filter dropdown to view available teams
    await page.click('[data-testid="team-filter-dropdown"]');
    await expect(page.locator('[data-testid="team-filter-options"]')).toBeVisible();
    
    // Step 3: Select a valid team from the filter dropdown
    await page.click('[data-testid="team-option-development-team-a"]', { timeout: 5000 });
    
    // Expected Result: Team filter is applied
    await expect(page.locator('[data-testid="team-filter-dropdown"]')).toContainText('Development Team A');
    
    // Step 4: Click the 'Generate Report' button to generate the filtered report
    await page.click('[data-testid="generate-report-button"]');
    
    // Wait for report generation (max 5 seconds as per technical requirements)
    await page.waitForSelector('[data-testid="report-results"]', { timeout: 5000 });
    
    // Expected Result: Report displays schedule data only for selected team
    await expect(page.locator('[data-testid="report-results"]')).toBeVisible();
    
    // Step 5: Verify all displayed activities, resources, and timelines belong to the selected team
    const reportRows = page.locator('[data-testid="report-row"]');
    await expect(reportRows).toHaveCountGreaterThan(0);
    
    const teamLabels = page.locator('[data-testid="report-row"] [data-testid="team-name"]');
    const count = await teamLabels.count();
    for (let i = 0; i < count; i++) {
      await expect(teamLabels.nth(i)).toContainText('Development Team A');
    }
    
    // Step 6: Check report header or filter summary section
    await expect(page.locator('[data-testid="report-header"]')).toContainText('Development Team A');
    await expect(page.locator('[data-testid="filter-summary"]')).toContainText('Team: Development Team A');
  });

  test('Handle invalid team filter input (error-case)', async ({ page }) => {
    // Step 1: Navigate to Schedule Reporting section
    await page.click('[data-testid="schedule-reporting-link"]');
    await expect(page.locator('[data-testid="schedule-report-container"]')).toBeVisible();
    
    // Step 2: Enter an invalid team identifier in the team filter field
    await page.click('[data-testid="team-filter-dropdown"]');
    await page.fill('[data-testid="team-filter-input"]', 'INVALID_TEAM_999');
    await page.press('[data-testid="team-filter-input"]', 'Enter');
    
    // Expected Result: System displays validation error
    await expect(page.locator('[data-testid="team-filter-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="team-filter-error"]')).toContainText(/invalid team/i);
    
    // Step 3: Verify the error message is clearly visible and user-friendly
    const errorMessage = await page.locator('[data-testid="team-filter-error"]').textContent();
    expect(errorMessage).toBeTruthy();
    expect(errorMessage?.length).toBeGreaterThan(10);
    
    // Step 4: Attempt to click the 'Generate Report' button with invalid team filter
    await page.click('[data-testid="generate-report-button"]');
    
    // Expected Result: Report generation is blocked until valid input is provided
    await expect(page.locator('[data-testid="report-results"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="team-filter-error"]')).toBeVisible();
    
    // Verify generate button is disabled or shows error state
    const generateButton = page.locator('[data-testid="generate-report-button"]');
    const isDisabled = await generateButton.isDisabled().catch(() => false);
    if (!isDisabled) {
      // If button is not disabled, verify error persists
      await expect(page.locator('[data-testid="team-filter-error"]')).toBeVisible();
    }
    
    // Step 5: Clear the invalid input and select a valid team from the dropdown
    await page.click('[data-testid="team-filter-dropdown"]');
    await page.fill('[data-testid="team-filter-input"]', '');
    await page.click('[data-testid="team-option-development-team-a"]');
    
    // Verify error message is cleared
    await expect(page.locator('[data-testid="team-filter-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="team-filter-dropdown"]')).toContainText('Development Team A');
    
    // Step 6: Click 'Generate Report' button with valid team filter
    await page.click('[data-testid="generate-report-button"]');
    
    // Expected Result: Report generates successfully
    await page.waitForSelector('[data-testid="report-results"]', { timeout: 5000 });
    await expect(page.locator('[data-testid="report-results"]')).toBeVisible();
  });

  test('Export filtered schedule reports correctly', async ({ page }) => {
    // Navigate to Schedule Reporting section
    await page.click('[data-testid="schedule-reporting-link"]');
    await expect(page.locator('[data-testid="schedule-report-container"]')).toBeVisible();
    
    // Select a valid team from filter dropdown
    await page.click('[data-testid="team-filter-dropdown"]');
    await page.click('[data-testid="team-option-development-team-a"]');
    await expect(page.locator('[data-testid="team-filter-dropdown"]')).toContainText('Development Team A');
    
    // Generate report
    await page.click('[data-testid="generate-report-button"]');
    await page.waitForSelector('[data-testid="report-results"]', { timeout: 5000 });
    await expect(page.locator('[data-testid="report-results"]')).toBeVisible();
    
    // Setup download listener
    const downloadPromise = page.waitForEvent('download');
    
    // Click export button
    await page.click('[data-testid="export-report-button"]');
    
    // Wait for download to complete
    const download = await downloadPromise;
    
    // Verify download occurred
    expect(download.suggestedFilename()).toMatch(/schedule.*report/i);
    expect(download.suggestedFilename()).toContain('Development-Team-A');
    
    // Verify success message
    await expect(page.locator('[data-testid="export-success-message"]')).toBeVisible();
  });
});