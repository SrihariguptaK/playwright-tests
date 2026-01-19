import { test, expect } from '@playwright/test';

test.describe('Manual Attendance Input Validation', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to manual attendance entry page
    await page.goto('/attendance/manual-entry');
    // Wait for page to load
    await page.waitForLoadState('networkidle');
  });

  test('Validate rejection of manual attendance with invalid employee ID', async ({ page }) => {
    // Step 1: Manager enters manual attendance with non-existent employee ID
    await page.fill('[data-testid="employee-id-input"]', 'EMP99999');
    await page.fill('[data-testid="attendance-date-input"]', '2024-01-15');
    await page.fill('[data-testid="attendance-time-input"]', '09:00');
    
    // Attempt to submit
    await page.click('[data-testid="submit-attendance-button"]');
    
    // Expected Result: System displays validation error and prevents submission
    await expect(page.locator('[data-testid="employee-id-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="employee-id-error"]')).toContainText(/employee.*not found|invalid employee|employee.*does not exist/i);
    
    // Verify record was not saved (form still visible)
    await expect(page.locator('[data-testid="employee-id-input"]')).toBeVisible();
    
    // Step 2: Manager corrects employee ID to valid one
    await page.fill('[data-testid="employee-id-input"]', 'EMP00001');
    
    // Wait for validation to clear
    await page.waitForTimeout(500);
    
    // Expected Result: Validation error cleared
    await expect(page.locator('[data-testid="employee-id-error"]')).not.toBeVisible();
    
    // Step 3: Manager submits attendance record
    await page.click('[data-testid="submit-attendance-button"]');
    
    // Expected Result: Record saved successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText(/saved successfully|record created|attendance recorded/i);
  });

  test('Verify detection of duplicate attendance entries', async ({ page }) => {
    // First, create an initial attendance record
    await page.fill('[data-testid="employee-id-input"]', 'EMP00002');
    await page.fill('[data-testid="attendance-date-input"]', '2024-01-15');
    await page.fill('[data-testid="attendance-time-input"]', '10:00');
    await page.click('[data-testid="submit-attendance-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    
    // Navigate back to entry form or wait for form reset
    await page.goto('/attendance/manual-entry');
    await page.waitForLoadState('networkidle');
    
    // Step 1: Manager attempts to enter duplicate attendance record for same employee and time
    await page.fill('[data-testid="employee-id-input"]', 'EMP00002');
    await page.fill('[data-testid="attendance-date-input"]', '2024-01-15');
    await page.fill('[data-testid="attendance-time-input"]', '10:00');
    await page.click('[data-testid="submit-attendance-button"]');
    
    // Expected Result: System rejects duplicate entry with error message
    await expect(page.locator('[data-testid="duplicate-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="duplicate-error"]')).toContainText(/duplicate|already exists|record already present/i);
    
    // Step 2: Manager modifies time to unique value
    await page.fill('[data-testid="attendance-time-input"]', '10:30');
    
    // Wait for validation
    await page.waitForTimeout(500);
    
    // Expected Result: Validation passes
    await expect(page.locator('[data-testid="duplicate-error"]')).not.toBeVisible();
    
    // Step 3: Manager submits record
    await page.click('[data-testid="submit-attendance-button"]');
    
    // Expected Result: Record saved successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText(/saved successfully|record created|attendance recorded/i);
  });

  test('Ensure real-time validation feedback during manual input', async ({ page }) => {
    // Step 1: Manager enters invalid date format
    await page.fill('[data-testid="attendance-date-input"]', '32/13/2023');
    
    // Move focus to another field to trigger validation
    await page.click('[data-testid="attendance-time-input"]');
    
    // Wait briefly for validation to trigger
    await page.waitForTimeout(300);
    
    // Expected Result: Validation error displayed immediately
    await expect(page.locator('[data-testid="date-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="date-error"]')).toContainText(/invalid date|date format|invalid format/i);
    
    // Step 2: Manager corrects date format
    await page.fill('[data-testid="attendance-date-input"]', '2024-01-15');
    
    // Move focus to another field
    await page.click('[data-testid="employee-id-input"]');
    
    // Wait briefly for validation
    await page.waitForTimeout(300);
    
    // Expected Result: Validation error removed
    await expect(page.locator('[data-testid="date-error"]')).not.toBeVisible();
    
    // Verify form is in valid state
    await page.fill('[data-testid="employee-id-input"]', 'EMP00003');
    await page.fill('[data-testid="attendance-time-input"]', '11:00');
    await page.click('[data-testid="submit-attendance-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
  });
});