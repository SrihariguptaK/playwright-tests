import { test, expect } from '@playwright/test';

test.describe('Schedule Reports - Project Filter', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'operations.manager@company.com');
    await page.fill('[data-testid="password-input"]', 'SecurePass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Filter schedule report by project', async ({ page }) => {
    // Step 1: Open schedule reporting module
    await page.click('[data-testid="schedule-reporting-link"]');
    await expect(page.locator('[data-testid="schedule-reporting-module"]')).toBeVisible();
    await expect(page).toHaveURL(/.*reports\/schedules/);

    // Step 2: Select project filter and other filters
    await page.click('[data-testid="project-filter-dropdown"]');
    await page.click('[data-testid="project-option-project-alpha"]');
    await expect(page.locator('[data-testid="project-filter-dropdown"]')).toContainText('Project Alpha');

    // Select date range filter
    await page.fill('[data-testid="date-range-start"]', '2024-01-01');
    await page.fill('[data-testid="date-range-end"]', '2024-12-31');

    // Select team filter
    await page.click('[data-testid="team-filter-dropdown"]');
    await page.click('[data-testid="team-option-engineering"]');
    await expect(page.locator('[data-testid="team-filter-dropdown"]')).toContainText('Engineering');

    // Step 3: Generate report
    await page.click('[data-testid="generate-report-button"]');
    
    // Wait for report generation (max 5 seconds as per technical requirements)
    await page.waitForSelector('[data-testid="schedule-report-table"]', { timeout: 5000 });
    
    // Verify report displays schedule data filtered by project
    await expect(page.locator('[data-testid="schedule-report-table"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-title"]')).toContainText('Schedule Report');
    
    // Verify filtered data contains only Project Alpha entries
    const projectCells = page.locator('[data-testid="report-row-project"]');
    const projectCount = await projectCells.count();
    expect(projectCount).toBeGreaterThan(0);
    
    for (let i = 0; i < projectCount; i++) {
      await expect(projectCells.nth(i)).toContainText('Project Alpha');
    }
    
    // Verify report contains schedule data
    await expect(page.locator('[data-testid="report-row"]').first()).toBeVisible();
    await expect(page.locator('[data-testid="report-no-data"]')).not.toBeVisible();
  });

  test('Persist filter selections during session', async ({ page }) => {
    // Step 1: Navigate to the schedule reporting module
    await page.click('[data-testid="schedule-reporting-link"]');
    await expect(page.locator('[data-testid="schedule-reporting-module"]')).toBeVisible();

    // Select a specific project from the project filter dropdown
    await page.click('[data-testid="project-filter-dropdown"]');
    await page.click('[data-testid="project-option-project-beta"]');
    await expect(page.locator('[data-testid="project-filter-dropdown"]')).toContainText('Project Beta');

    // Select a date range filter by choosing start and end dates
    await page.fill('[data-testid="date-range-start"]', '2024-03-01');
    await page.fill('[data-testid="date-range-end"]', '2024-06-30');

    // Select a team from the team filter dropdown
    await page.click('[data-testid="team-filter-dropdown"]');
    await page.click('[data-testid="team-option-operations"]');
    await expect(page.locator('[data-testid="team-filter-dropdown"]')).toContainText('Operations');

    // Click 'Generate Report' or 'Apply Filters' button to apply all filters
    await page.click('[data-testid="generate-report-button"]');
    await page.waitForSelector('[data-testid="schedule-report-table"]', { timeout: 5000 });
    await expect(page.locator('[data-testid="schedule-report-table"]')).toBeVisible();

    // Step 2: Navigate away from the schedule reporting module
    await page.click('[data-testid="dashboard-link"]');
    await expect(page).toHaveURL(/.*dashboard/);
    await expect(page.locator('[data-testid="dashboard-container"]')).toBeVisible();

    // Navigate back to the schedule reporting module
    await page.click('[data-testid="schedule-reporting-link"]');
    await expect(page.locator('[data-testid="schedule-reporting-module"]')).toBeVisible();

    // Verify the filter selections are retained
    await expect(page.locator('[data-testid="project-filter-dropdown"]')).toContainText('Project Beta');
    
    const startDateValue = await page.inputValue('[data-testid="date-range-start"]');
    expect(startDateValue).toBe('2024-03-01');
    
    const endDateValue = await page.inputValue('[data-testid="date-range-end"]');
    expect(endDateValue).toBe('2024-06-30');
    
    await expect(page.locator('[data-testid="team-filter-dropdown"]')).toContainText('Operations');

    // Verify the report data displayed matches the persisted filters
    await expect(page.locator('[data-testid="schedule-report-table"]')).toBeVisible();
    
    const projectCells = page.locator('[data-testid="report-row-project"]');
    const projectCount = await projectCells.count();
    
    if (projectCount > 0) {
      for (let i = 0; i < projectCount; i++) {
        await expect(projectCells.nth(i)).toContainText('Project Beta');
      }
    }
  });
});