import { test, expect } from '@playwright/test';

test.describe('Story-10: Detailed Conflict Information in Alerts', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the scheduling application
    await page.goto('/scheduling');
    // Login as scheduler if needed
    await page.fill('[data-testid="username-input"]', 'scheduler@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();
  });

  test('Verify detailed conflict information in alerts (happy-path)', async ({ page }) => {
    // Create a scheduling scenario with multiple simultaneous conflicts
    // Book first appointment
    await page.click('[data-testid="new-appointment-button"]');
    await page.fill('[data-testid="appointment-title"]', 'Appointment 1');
    await page.selectOption('[data-testid="resource-select"]', 'Conference Room A');
    await page.fill('[data-testid="appointment-date"]', '2024-02-15');
    await page.fill('[data-testid="appointment-start-time"]', '10:00');
    await page.fill('[data-testid="appointment-end-time"]', '11:00');
    await page.click('[data-testid="save-appointment-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // Attempt to book second overlapping appointment
    await page.click('[data-testid="new-appointment-button"]');
    await page.fill('[data-testid="appointment-title"]', 'Appointment 2');
    await page.selectOption('[data-testid="resource-select"]', 'Conference Room A');
    await page.fill('[data-testid="appointment-date"]', '2024-02-15');
    await page.fill('[data-testid="appointment-start-time"]', '10:30');
    await page.fill('[data-testid="appointment-end-time"]', '11:30');
    await page.click('[data-testid="save-appointment-button"]');

    // Attempt to book third overlapping appointment
    await page.click('[data-testid="new-appointment-button"]');
    await page.fill('[data-testid="appointment-title"]', 'Appointment 3');
    await page.selectOption('[data-testid="resource-select"]', 'Conference Room A');
    await page.fill('[data-testid="appointment-date"]', '2024-02-15');
    await page.fill('[data-testid="appointment-start-time"]', '10:45');
    await page.fill('[data-testid="appointment-end-time"]', '11:45');
    
    // Trigger conflict detection and measure alert generation time
    const startTime = Date.now();
    await page.click('[data-testid="save-appointment-button"]');
    
    // Wait for the alert to be generated
    const conflictAlert = page.locator('[data-testid="conflict-alert"]');
    await expect(conflictAlert).toBeVisible({ timeout: 5000 });
    const endTime = Date.now();
    const alertGenerationTime = endTime - startTime;

    // Verify alert generation time is within 1 second
    expect(alertGenerationTime).toBeLessThanOrEqual(1000);

    // Review the alert content and verify it includes full details of all conflicting appointments
    const alertContent = await conflictAlert.textContent();
    expect(alertContent).toContain('Appointment 1');
    expect(alertContent).toContain('Appointment 2');
    expect(alertContent).toContain('Appointment 3');

    // Verify the alert includes appointment IDs, titles, times, and durations
    const conflictDetails = page.locator('[data-testid="conflict-details"]');
    await expect(conflictDetails).toBeVisible();
    
    const appointment1Details = page.locator('[data-testid="conflict-appointment-1"]');
    await expect(appointment1Details).toContainText('Appointment 1');
    await expect(appointment1Details).toContainText('10:00');
    await expect(appointment1Details).toContainText('11:00');

    const appointment2Details = page.locator('[data-testid="conflict-appointment-2"]');
    await expect(appointment2Details).toContainText('Appointment 2');
    await expect(appointment2Details).toContainText('10:30');
    await expect(appointment2Details).toContainText('11:30');

    const appointment3Details = page.locator('[data-testid="conflict-appointment-3"]');
    await expect(appointment3Details).toContainText('Appointment 3');
    await expect(appointment3Details).toContainText('10:45');
    await expect(appointment3Details).toContainText('11:45');

    // Verify the alert includes resource names and time slots for each conflict
    await expect(conflictAlert).toContainText('Conference Room A');
    await expect(conflictAlert).toContainText('2024-02-15');

    // Identify and verify the presence of clickable links to each conflicting schedule
    const firstConflictLink = page.locator('[data-testid="conflict-link-1"]');
    const secondConflictLink = page.locator('[data-testid="conflict-link-2"]');
    const thirdConflictLink = page.locator('[data-testid="conflict-link-3"]');
    
    await expect(firstConflictLink).toBeVisible();
    await expect(secondConflictLink).toBeVisible();
    await expect(thirdConflictLink).toBeVisible();

    // Click on the first link in the alert to navigate to the first conflicting schedule
    await firstConflictLink.click();
    await expect(page).toHaveURL(/.*schedule.*appointment-1/);
    await expect(page.locator('[data-testid="appointment-detail-title"]')).toContainText('Appointment 1');

    // Return to the alert and click on the second link to navigate to the second conflicting schedule
    await page.goBack();
    await expect(conflictAlert).toBeVisible();
    await secondConflictLink.click();
    await expect(page).toHaveURL(/.*schedule.*appointment-2/);
    await expect(page.locator('[data-testid="appointment-detail-title"]')).toContainText('Appointment 2');

    // Return to the alert and click on the third link to navigate to the third conflicting schedule
    await page.goBack();
    await expect(conflictAlert).toBeVisible();
    await thirdConflictLink.click();
    await expect(page).toHaveURL(/.*schedule.*appointment-3/);
    await expect(page.locator('[data-testid="appointment-detail-title"]')).toContainText('Appointment 3');

    // Return to verify the alert remains accessible
    await page.goBack();
    await expect(conflictAlert).toBeVisible();
    
    // Verify all information is readable and properly formatted
    const alertBox = await conflictAlert.boundingBox();
    expect(alertBox).not.toBeNull();
    expect(alertBox!.width).toBeGreaterThan(0);
    expect(alertBox!.height).toBeGreaterThan(0);
    
    // Verify alert has proper styling and is readable
    const alertStyles = await conflictAlert.evaluate((el) => {
      const styles = window.getComputedStyle(el);
      return {
        display: styles.display,
        visibility: styles.visibility,
        opacity: styles.opacity
      };
    });
    
    expect(alertStyles.display).not.toBe('none');
    expect(alertStyles.visibility).toBe('visible');
    expect(parseFloat(alertStyles.opacity)).toBeGreaterThan(0);
  });

  test('Verify detailed conflict information in alerts - multiple conflicts', async ({ page }) => {
    // Trigger scheduling conflict with multiple conflicts
    await page.click('[data-testid="bulk-schedule-button"]');
    await page.fill('[data-testid="bulk-appointments-input"]', '3');
    await page.selectOption('[data-testid="bulk-resource-select"]', 'Conference Room B');
    await page.fill('[data-testid="bulk-date"]', '2024-02-20');
    await page.fill('[data-testid="bulk-time"]', '14:00');
    await page.click('[data-testid="create-bulk-appointments"]');

    // Wait for conflict alert
    const conflictAlert = page.locator('[data-testid="conflict-alert"]');
    await expect(conflictAlert).toBeVisible({ timeout: 2000 });

    // Verify alert displays all conflict details accurately
    const conflictCount = await page.locator('[data-testid="conflict-item"]').count();
    expect(conflictCount).toBeGreaterThanOrEqual(2);

    // Verify each conflict has complete information
    for (let i = 0; i < conflictCount; i++) {
      const conflictItem = page.locator('[data-testid="conflict-item"]').nth(i);
      await expect(conflictItem).toContainText(/Appointment/);
      await expect(conflictItem).toContainText(/\d{2}:\d{2}/);
      await expect(conflictItem).toContainText('Conference Room B');
    }
  });

  test('Verify clickable links in conflict alerts', async ({ page }) => {
    // Create initial appointment
    await page.click('[data-testid="new-appointment-button"]');
    await page.fill('[data-testid="appointment-title"]', 'Base Appointment');
    await page.selectOption('[data-testid="resource-select"]', 'Meeting Room 1');
    await page.fill('[data-testid="appointment-date"]', '2024-03-01');
    await page.fill('[data-testid="appointment-start-time"]', '09:00');
    await page.fill('[data-testid="appointment-end-time"]', '10:00');
    await page.click('[data-testid="save-appointment-button"]');

    // Create conflicting appointment
    await page.click('[data-testid="new-appointment-button"]');
    await page.fill('[data-testid="appointment-title"]', 'Conflicting Appointment');
    await page.selectOption('[data-testid="resource-select"]', 'Meeting Room 1');
    await page.fill('[data-testid="appointment-date"]', '2024-03-01');
    await page.fill('[data-testid="appointment-start-time"]', '09:30');
    await page.fill('[data-testid="appointment-end-time"]', '10:30');
    await page.click('[data-testid="save-appointment-button"]');

    // Wait for alert
    const conflictAlert = page.locator('[data-testid="conflict-alert"]');
    await expect(conflictAlert).toBeVisible();

    // Click links in alert and verify navigation
    const scheduleLinks = page.locator('[data-testid^="conflict-link-"]');
    const linkCount = await scheduleLinks.count();
    expect(linkCount).toBeGreaterThan(0);

    // Click first link and verify navigation to conflicting schedule
    await scheduleLinks.first().click();
    await expect(page.locator('[data-testid="schedule-view"]')).toBeVisible();
    await expect(page.locator('[data-testid="appointment-details"]')).toBeVisible();
  });

  test('Verify alert generation time within 1 second', async ({ page }) => {
    // Prepare conflict scenario
    await page.click('[data-testid="new-appointment-button"]');
    await page.fill('[data-testid="appointment-title"]', 'Time Test Appointment 1');
    await page.selectOption('[data-testid="resource-select"]', 'Lab A');
    await page.fill('[data-testid="appointment-date"]', '2024-03-15');
    await page.fill('[data-testid="appointment-start-time"]', '13:00');
    await page.fill('[data-testid="appointment-end-time"]', '14:00');
    await page.click('[data-testid="save-appointment-button"]');
    await page.waitForTimeout(500);

    // Create conflict and measure time
    await page.click('[data-testid="new-appointment-button"]');
    await page.fill('[data-testid="appointment-title"]', 'Time Test Appointment 2');
    await page.selectOption('[data-testid="resource-select"]', 'Lab A');
    await page.fill('[data-testid="appointment-date"]', '2024-03-15');
    await page.fill('[data-testid="appointment-start-time"]', '13:30');
    await page.fill('[data-testid="appointment-end-time"]', '14:30');
    
    const measurementStart = Date.now();
    await page.click('[data-testid="save-appointment-button"]');
    
    const conflictAlert = page.locator('[data-testid="conflict-alert"]');
    await expect(conflictAlert).toBeVisible({ timeout: 1500 });
    
    const measurementEnd = Date.now();
    const elapsedTime = measurementEnd - measurementStart;

    // Verify alert appears within 1 second
    expect(elapsedTime).toBeLessThanOrEqual(1000);
    
    // Log performance metric
    console.log(`Alert generation time: ${elapsedTime}ms`);
  });
});