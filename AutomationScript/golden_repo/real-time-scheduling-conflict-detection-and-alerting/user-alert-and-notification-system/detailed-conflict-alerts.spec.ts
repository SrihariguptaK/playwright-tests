import { test, expect } from '@playwright/test';

test.describe('Story-20: Detailed Conflict Information in Alerts', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the scheduling application
    await page.goto('/scheduler');
    // Login as scheduler user
    await page.fill('[data-testid="username-input"]', 'scheduler@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();
  });

  test('Verify detailed conflict information in alerts (happy-path)', async ({ page }) => {
    // Step 1: Create or identify a scheduling conflict by attempting to book the same resource for overlapping time slots
    await page.click('[data-testid="new-booking-button"]');
    await page.fill('[data-testid="resource-search"]', 'Conference Room A');
    await page.click('[data-testid="resource-option-room-a"]');
    await page.fill('[data-testid="booking-date"]', '2024-03-15');
    await page.fill('[data-testid="start-time"]', '10:00');
    await page.fill('[data-testid="end-time"]', '11:00');
    await page.click('[data-testid="create-booking-button"]');
    await expect(page.locator('[data-testid="booking-success-message"]')).toBeVisible();
    const firstBookingId = await page.locator('[data-testid="booking-id"]').textContent();

    // Create conflicting booking
    await page.click('[data-testid="new-booking-button"]');
    await page.fill('[data-testid="resource-search"]', 'Conference Room A');
    await page.click('[data-testid="resource-option-room-a"]');
    await page.fill('[data-testid="booking-date"]', '2024-03-15');
    await page.fill('[data-testid="start-time"]', '10:30');
    await page.fill('[data-testid="end-time"]', '11:30');
    await page.click('[data-testid="create-booking-button"]');

    // Step 2: Wait for conflict alert to be generated
    await page.waitForSelector('[data-testid="conflict-alert"]', { timeout: 3000 });
    const conflictAlert = page.locator('[data-testid="conflict-alert"]');
    await expect(conflictAlert).toBeVisible();

    // Step 3: Review the alert content received via in-app notification
    const alertContent = await conflictAlert.textContent();
    expect(alertContent).toBeTruthy();

    // Step 4: Verify the booking IDs displayed in the alert
    const bookingIdPattern = /BK-\d+/g;
    const bookingIdsInAlert = alertContent?.match(bookingIdPattern);
    expect(bookingIdsInAlert).toBeTruthy();
    expect(bookingIdsInAlert?.length).toBeGreaterThanOrEqual(2);
    await expect(conflictAlert.locator('[data-testid="booking-id-1"]')).toBeVisible();
    await expect(conflictAlert.locator('[data-testid="booking-id-2"]')).toBeVisible();

    // Step 5: Verify the resource names displayed in the alert
    await expect(conflictAlert.locator('[data-testid="resource-name"]')).toContainText('Conference Room A');
    const resourceName = await conflictAlert.locator('[data-testid="resource-name"]').textContent();
    expect(resourceName).toContain('Conference Room A');

    // Step 6: Verify the time slots displayed in the alert
    await expect(conflictAlert.locator('[data-testid="time-slot-1"]')).toBeVisible();
    await expect(conflictAlert.locator('[data-testid="time-slot-2"]')).toBeVisible();
    const timeSlot1 = await conflictAlert.locator('[data-testid="time-slot-1"]').textContent();
    const timeSlot2 = await conflictAlert.locator('[data-testid="time-slot-2"]').textContent();
    expect(timeSlot1).toMatch(/10:00.*11:00/);
    expect(timeSlot2).toMatch(/10:30.*11:30/);

    // Step 7: Check email inbox for the same conflict alert
    await page.click('[data-testid="notifications-menu"]');
    await page.click('[data-testid="email-notifications-tab"]');
    await expect(page.locator('[data-testid="email-notification-conflict"]').first()).toBeVisible();

    // Step 8: Review the email alert formatting and content structure
    const emailAlert = page.locator('[data-testid="email-notification-conflict"]').first();
    await expect(emailAlert.locator('[data-testid="email-subject"]')).toContainText('Scheduling Conflict Detected');
    await expect(emailAlert.locator('[data-testid="email-body"]')).toBeVisible();
    const emailBody = await emailAlert.locator('[data-testid="email-body"]').textContent();
    expect(emailBody).toBeTruthy();

    // Step 9: Compare in-app notification format with email notification format
    expect(emailBody).toContain('Conference Room A');
    expect(emailBody).toMatch(/BK-\d+/);
    expect(emailBody).toMatch(/10:00/);
    expect(emailBody).toMatch(/10:30/);

    // Step 10: Locate and identify the clickable link to the first conflicting booking in the alert
    await page.click('[data-testid="notifications-menu"]');
    await page.click('[data-testid="in-app-notifications-tab"]');
    const firstBookingLink = conflictAlert.locator('[data-testid="conflict-booking-link-1"]');
    await expect(firstBookingLink).toBeVisible();
    await expect(firstBookingLink).toHaveAttribute('href', /.+/);

    // Step 11: Click on the link to the first conflicting booking
    await firstBookingLink.click();
    await page.waitForLoadState('networkidle');

    // Step 12: Verify the booking details page displays correct information matching the alert
    await expect(page.locator('[data-testid="booking-details-page"]')).toBeVisible();
    await expect(page.locator('[data-testid="booking-detail-resource"]')).toContainText('Conference Room A');
    await expect(page.locator('[data-testid="booking-detail-date"]')).toContainText('2024-03-15');
    await expect(page.locator('[data-testid="booking-detail-time"]')).toContainText('10:00');
    const bookingDetailId = await page.locator('[data-testid="booking-detail-id"]').textContent();
    expect(bookingDetailId).toMatch(/BK-\d+/);

    // Step 13: Navigate back to the alert and click on the link to the second conflicting booking
    await page.goBack();
    await page.waitForSelector('[data-testid="conflict-alert"]');
    const secondBookingLink = page.locator('[data-testid="conflict-booking-link-2"]');
    await expect(secondBookingLink).toBeVisible();
    await secondBookingLink.click();
    await page.waitForLoadState('networkidle');

    // Step 14: Verify the second booking details page displays correct information
    await expect(page.locator('[data-testid="booking-details-page"]')).toBeVisible();
    await expect(page.locator('[data-testid="booking-detail-resource"]')).toContainText('Conference Room A');
    await expect(page.locator('[data-testid="booking-detail-date"]')).toContainText('2024-03-15');
    await expect(page.locator('[data-testid="booking-detail-time"]')).toContainText('10:30');
    const secondBookingDetailId = await page.locator('[data-testid="booking-detail-id"]').textContent();
    expect(secondBookingDetailId).toMatch(/BK-\d+/);
    expect(secondBookingDetailId).not.toBe(bookingDetailId);

    // Step 15: Review the suggested resolution steps provided in the alert
    await page.goBack();
    await page.waitForSelector('[data-testid="conflict-alert"]');
    const resolutionSteps = page.locator('[data-testid="resolution-suggestions"]');
    await expect(resolutionSteps).toBeVisible();
    await expect(resolutionSteps).toContainText(/cancel|reschedule|modify/i);
    const resolutionText = await resolutionSteps.textContent();
    expect(resolutionText).toBeTruthy();
    expect(resolutionText?.length).toBeGreaterThan(20);
  });

  test('Verify alert contains booking IDs, resource names, and time slots', async ({ page }) => {
    // Trigger conflict alert
    await page.click('[data-testid="test-conflict-trigger"]');
    await page.waitForSelector('[data-testid="conflict-alert"]', { timeout: 3000 });
    
    const alert = page.locator('[data-testid="conflict-alert"]');
    
    // Expected Result: Alert contains booking IDs, resource names, and time slots
    await expect(alert.locator('[data-testid="booking-id-1"]')).toBeVisible();
    await expect(alert.locator('[data-testid="booking-id-2"]')).toBeVisible();
    await expect(alert.locator('[data-testid="resource-name"]')).toBeVisible();
    await expect(alert.locator('[data-testid="time-slot-1"]')).toBeVisible();
    await expect(alert.locator('[data-testid="time-slot-2"]')).toBeVisible();
    
    const alertText = await alert.textContent();
    expect(alertText).toMatch(/BK-\d+/);
  });

  test('Verify alert content is clear and formatted correctly across channels', async ({ page }) => {
    // Trigger conflict alert
    await page.click('[data-testid="test-conflict-trigger"]');
    await page.waitForSelector('[data-testid="conflict-alert"]', { timeout: 3000 });
    
    // Receive alert via email and in-app notification
    const inAppAlert = page.locator('[data-testid="conflict-alert"]');
    await expect(inAppAlert).toBeVisible();
    
    // Expected Result: Alert content is clear and formatted correctly
    const inAppContent = await inAppAlert.textContent();
    expect(inAppContent).toBeTruthy();
    expect(inAppContent?.length).toBeGreaterThan(50);
    
    // Check email notification
    await page.click('[data-testid="notifications-menu"]');
    await page.click('[data-testid="email-notifications-tab"]');
    const emailAlert = page.locator('[data-testid="email-notification-conflict"]').first();
    await expect(emailAlert).toBeVisible();
    
    const emailContent = await emailAlert.textContent();
    expect(emailContent).toBeTruthy();
    expect(emailContent).toContain('Conflict');
  });

  test('Verify clicking link in alert navigates to conflicting booking details', async ({ page }) => {
    // Trigger conflict alert
    await page.click('[data-testid="test-conflict-trigger"]');
    await page.waitForSelector('[data-testid="conflict-alert"]', { timeout: 3000 });
    
    const alert = page.locator('[data-testid="conflict-alert"]');
    const bookingLink = alert.locator('[data-testid="conflict-booking-link-1"]');
    
    // Click link in alert
    await bookingLink.click();
    await page.waitForLoadState('networkidle');
    
    // Expected Result: Navigates to conflicting booking details in UI
    await expect(page.locator('[data-testid="booking-details-page"]')).toBeVisible();
    await expect(page.locator('[data-testid="booking-detail-id"]')).toBeVisible();
    await expect(page.locator('[data-testid="booking-detail-resource"]')).toBeVisible();
    await expect(page.locator('[data-testid="booking-detail-time"]')).toBeVisible();
    
    const url = page.url();
    expect(url).toContain('/booking/');
  });
});