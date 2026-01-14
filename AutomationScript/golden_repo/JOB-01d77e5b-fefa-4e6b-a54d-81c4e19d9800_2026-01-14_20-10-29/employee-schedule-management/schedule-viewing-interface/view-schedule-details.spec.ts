import { test, expect } from '@playwright/test';

test.describe('Story-19: View Schedule Details - Location and Role', () => {
  test.beforeEach(async ({ page }) => {
    // Login as Employee A
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'employeeA@company.com');
    await page.fill('[data-testid="password-input"]', 'Password123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate shift detail display accuracy (happy-path)', async ({ page }) => {
    // Navigate to the schedule view from the main dashboard
    await page.click('[data-testid="schedule-menu-item"]');
    await expect(page).toHaveURL(/.*schedule/);
    await expect(page.locator('[data-testid="schedule-view"]')).toBeVisible();

    // Identify a shift from the schedule list that has complete details
    const shiftWithDetails = page.locator('[data-testid="shift-item"]').first();
    await expect(shiftWithDetails).toBeVisible();

    // Store expected data from the shift list for verification
    const expectedLocation = await shiftWithDetails.locator('[data-testid="shift-location"]').textContent();
    const expectedRole = await shiftWithDetails.locator('[data-testid="shift-role"]').textContent();

    // Click or tap on the selected shift to open the shift detail view
    await shiftWithDetails.click();

    // Wait for shift detail view to load
    await expect(page.locator('[data-testid="shift-detail-view"]')).toBeVisible({ timeout: 2000 });

    // Verify that the shift location is displayed in the detail view
    const detailLocation = page.locator('[data-testid="detail-location"]');
    await expect(detailLocation).toBeVisible();
    await expect(detailLocation).toContainText(expectedLocation || '');

    // Verify that the assigned role is displayed in the detail view
    const detailRole = page.locator('[data-testid="detail-role"]');
    await expect(detailRole).toBeVisible();
    await expect(detailRole).toContainText(expectedRole || '');

    // Verify that shift notes are displayed if available
    const detailNotes = page.locator('[data-testid="detail-notes"]');
    if (await detailNotes.isVisible()) {
      await expect(detailNotes).not.toBeEmpty();
    }

    // Check if special instructions are highlighted or displayed prominently
    const specialInstructions = page.locator('[data-testid="special-instructions"]');
    if (await specialInstructions.isVisible()) {
      await expect(specialInstructions).toBeVisible();
      // Verify special instructions have highlighting class or style
      const hasHighlight = await specialInstructions.evaluate((el) => {
        const styles = window.getComputedStyle(el);
        return styles.fontWeight === 'bold' || styles.backgroundColor !== 'rgba(0, 0, 0, 0)';
      });
      expect(hasHighlight).toBeTruthy();
    }

    // Cross-reference all displayed details with backend data
    const response = await page.request.get('/api/schedules/details', {
      params: {
        shiftId: await shiftWithDetails.getAttribute('data-shift-id') || ''
      }
    });
    expect(response.ok()).toBeTruthy();
    const backendData = await response.json();
    
    const displayedLocation = await detailLocation.textContent();
    const displayedRole = await detailRole.textContent();
    
    expect(displayedLocation).toContain(backendData.location);
    expect(displayedRole).toContain(backendData.role);

    // Click the back button or close button to return to schedule overview
    await page.click('[data-testid="back-button"]');
    await expect(page.locator('[data-testid="schedule-view"]')).toBeVisible();
  });

  test('Ensure access control on shift details (error-case)', async ({ page }) => {
    // Log in as Employee A and navigate to the schedule view
    await page.click('[data-testid="schedule-menu-item"]');
    await expect(page).toHaveURL(/.*schedule/);

    // Obtain or identify a shift ID that belongs to Employee B
    const employeeBShiftId = 'shift-employee-b-12345';

    // Attempt to access the shift detail view by directly manipulating the URL
    const unauthorizedResponse = page.waitForResponse(
      response => response.url().includes('/api/schedules/details') && response.status() === 403
    );

    await page.goto(`/schedule/details?shiftId=${employeeBShiftId}`);

    // Observe the system response to the unauthorized access attempt
    const response = await unauthorizedResponse;
    expect(response.status()).toBe(403);

    // Verify that no shift details from Employee B are displayed to Employee A
    const shiftDetailView = page.locator('[data-testid="shift-detail-view"]');
    await expect(shiftDetailView).not.toBeVisible();

    // Verify error message or access denied notification
    const errorMessage = page.locator('[data-testid="error-message"]');
    await expect(errorMessage).toBeVisible();
    await expect(errorMessage).toContainText(/access denied|unauthorized|not authorized/i);

    // Verify that Employee A is redirected back to their own schedule view or an error page
    await page.waitForURL(/.*schedule|.*error|.*unauthorized/, { timeout: 3000 });
    const currentUrl = page.url();
    expect(currentUrl).toMatch(/schedule|error|unauthorized/);

    // Verify Employee A can still access their own schedule
    if (currentUrl.includes('schedule')) {
      await expect(page.locator('[data-testid="schedule-view"]')).toBeVisible();
    }

    // Alternative: Attempt unauthorized access via API call directly
    const apiResponse = await page.request.get('/api/schedules/details', {
      params: {
        shiftId: employeeBShiftId
      }
    });

    // Check application logs or security logs for the unauthorized access attempt
    expect(apiResponse.status()).toBe(403);
    const responseBody = await apiResponse.json();
    expect(responseBody).toHaveProperty('error');
    expect(responseBody.error).toMatch(/access denied|unauthorized|forbidden/i);
  });
});