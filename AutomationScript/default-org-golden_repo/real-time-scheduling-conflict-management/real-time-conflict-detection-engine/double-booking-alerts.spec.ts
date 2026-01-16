import { test, expect } from '@playwright/test';

test.describe('Double Booking Alerts - Story 2', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application
    await page.goto('/');
    // Assume user is already logged in as Scheduler or perform login
    // await page.fill('[data-testid="username"]', 'scheduler@example.com');
    // await page.fill('[data-testid="password"]', 'password123');
    // await page.click('[data-testid="login-button"]');
  });

  test('Validate detection of double bookings in real-time (happy-path)', async ({ page }) => {
    // Step 1: Navigate to booking creation page
    await page.click('text=Create New Booking');
    await expect(page.locator('[data-testid="booking-form"]')).toBeVisible();
    
    // Step 2: Enter booking details that cause double booking
    await page.selectOption('[data-testid="customer-select"]', { label: 'Customer A' });
    await page.selectOption('[data-testid="service-select"]', { label: 'Service X' });
    await page.fill('[data-testid="booking-date"]', '2024-01-15');
    await page.fill('[data-testid="booking-time"]', '13:30');
    
    // Wait for alert to appear immediately
    const alert = page.locator('[data-testid="double-booking-alert"]');
    await expect(alert).toBeVisible({ timeout: 2000 });
    await expect(alert).toContainText('double booking');
    await expect(alert).toContainText('Customer A');
    await expect(alert).toContainText('Service X');
    
    // Step 3: Attempt to save booking without resolving alert
    await page.click('[data-testid="save-booking-button"]');
    
    // System blocks save and requests confirmation
    const confirmationDialog = page.locator('[data-testid="override-confirmation-dialog"]');
    await expect(confirmationDialog).toBeVisible();
    await expect(confirmationDialog).toContainText('confirm');
    
    // Verify booking is not saved without confirmation
    const saveButton = page.locator('[data-testid="save-booking-button"]');
    await expect(saveButton).toBeDisabled();
  });

  test('Verify alert latency is under 1 second (boundary)', async ({ page }) => {
    // Navigate to booking creation page
    await page.click('text=Create New Booking');
    await expect(page.locator('[data-testid="booking-form"]')).toBeVisible();
    
    // Monitor API response time
    const responsePromise = page.waitForResponse(
      response => response.url().includes('/bookings/check-double-booking') && response.status() === 200
    );
    
    // Record start time
    const startTime = Date.now();
    
    // Input conflicting booking details
    await page.selectOption('[data-testid="customer-select"]', { label: 'Customer A' });
    await page.selectOption('[data-testid="service-select"]', { label: 'Service X' });
    await page.fill('[data-testid="booking-date"]', '2024-01-15');
    await page.fill('[data-testid="booking-time"]', '13:00');
    
    // Trigger validation by blurring the time field
    await page.locator('[data-testid="booking-time"]').blur();
    
    // Wait for API response
    const response = await responsePromise;
    const endTime = Date.now();
    const latency = endTime - startTime;
    
    // Verify alert appears within 1 second
    const alert = page.locator('[data-testid="double-booking-alert"]');
    await expect(alert).toBeVisible({ timeout: 1000 });
    
    // Assert latency is under 1 second (1000ms)
    expect(latency).toBeLessThan(1000);
    console.log(`Alert latency: ${latency}ms`);
  });

  test('Ensure detection supports all booking categories (happy-path)', async ({ page }) => {
    const categories = ['Consultation', 'Treatment', 'Follow-up', 'Emergency'];
    
    for (const category of categories) {
      // Navigate to booking creation page
      await page.click('text=Create New Booking');
      await expect(page.locator('[data-testid="booking-form"]')).toBeVisible();
      
      // Select booking category
      await page.selectOption('[data-testid="category-select"]', { label: category });
      
      // Create booking with conflicting details for this category
      await page.selectOption('[data-testid="customer-select"]', { label: 'Customer B' });
      await page.fill('[data-testid="booking-date"]', '2024-01-16');
      await page.fill('[data-testid="booking-time"]', '10:00');
      
      // Trigger validation
      await page.locator('[data-testid="booking-time"]').blur();
      
      // Verify alert is generated for this category conflict
      const alert = page.locator('[data-testid="double-booking-alert"]');
      await expect(alert).toBeVisible({ timeout: 2000 });
      await expect(alert).toContainText('double booking');
      await expect(alert).toContainText(category);
      
      // Clear form or cancel to prepare for next category
      const cancelButton = page.locator('[data-testid="cancel-booking-button"]');
      if (await cancelButton.isVisible()) {
        await cancelButton.click();
      } else {
        await page.click('[data-testid="clear-form-button"]');
      }
      
      // Wait for form to reset
      await page.waitForTimeout(500);
    }
  });
});