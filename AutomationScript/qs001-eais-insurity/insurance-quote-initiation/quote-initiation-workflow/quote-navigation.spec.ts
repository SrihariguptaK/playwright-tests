import { test, expect } from '@playwright/test';

test.describe('Quote Initiation Navigation Flow', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to quote initiation page
    await page.goto('/quote-initiation');
    // Wait for page to be fully loaded
    await page.waitForLoadState('networkidle');
  });

  test('Validate step-by-step navigation with progress indicators', async ({ page }) => {
    // Step 1: Start quote initiation process
    await page.click('[data-testid="start-quote-button"]');
    
    // Expected Result: Navigation controls and progress indicators are visible
    await expect(page.locator('[data-testid="progress-indicator"]')).toBeVisible();
    await expect(page.locator('[data-testid="navigation-controls"]')).toBeVisible();
    await expect(page.locator('[data-testid="step-1-indicator"]')).toHaveClass(/active/);
    
    // Step 2: Navigate through each step forward and backward
    // Fill applicant data on step 1
    await page.fill('[data-testid="applicant-first-name"]', 'John');
    await page.fill('[data-testid="applicant-last-name"]', 'Doe');
    await page.fill('[data-testid="applicant-email"]', 'john.doe@example.com');
    await page.fill('[data-testid="applicant-phone"]', '555-123-4567');
    
    // Navigate forward to step 2
    await page.click('[data-testid="next-button"]');
    await page.waitForTimeout(500);
    
    // Expected Result: Progress indicator updates to step 2
    await expect(page.locator('[data-testid="step-2-indicator"]')).toHaveClass(/active/);
    await expect(page.locator('[data-testid="step-1-indicator"]')).toHaveClass(/completed/);
    
    // Fill risk data on step 2
    await page.fill('[data-testid="property-address"]', '123 Main Street');
    await page.fill('[data-testid="property-city"]', 'Springfield');
    await page.selectOption('[data-testid="property-state"]', 'IL');
    await page.fill('[data-testid="property-zip"]', '62701');
    await page.fill('[data-testid="coverage-amount"]', '500000');
    
    // Navigate forward to step 3 (review)
    await page.click('[data-testid="next-button"]');
    await page.waitForTimeout(500);
    
    // Expected Result: Progress indicator updates to step 3
    await expect(page.locator('[data-testid="step-3-indicator"]')).toHaveClass(/active/);
    await expect(page.locator('[data-testid="step-2-indicator"]')).toHaveClass(/completed/);
    
    // Navigate backward to step 2
    await page.click('[data-testid="back-button"]');
    await page.waitForTimeout(500);
    
    // Expected Result: Data is retained and progress indicators update correctly
    await expect(page.locator('[data-testid="step-2-indicator"]')).toHaveClass(/active/);
    await expect(page.locator('[data-testid="property-address"]')).toHaveValue('123 Main Street');
    await expect(page.locator('[data-testid="property-city"]')).toHaveValue('Springfield');
    await expect(page.locator('[data-testid="coverage-amount"]')).toHaveValue('500000');
    
    // Navigate backward to step 1
    await page.click('[data-testid="back-button"]');
    await page.waitForTimeout(500);
    
    // Expected Result: Applicant data is retained
    await expect(page.locator('[data-testid="step-1-indicator"]')).toHaveClass(/active/);
    await expect(page.locator('[data-testid="applicant-first-name"]')).toHaveValue('John');
    await expect(page.locator('[data-testid="applicant-last-name"]')).toHaveValue('Doe');
    await expect(page.locator('[data-testid="applicant-email"]')).toHaveValue('john.doe@example.com');
    await expect(page.locator('[data-testid="applicant-phone"]')).toHaveValue('555-123-4567');
    
    // Step 3: Complete all steps and submit quote
    // Navigate forward through all steps again
    await page.click('[data-testid="next-button"]');
    await page.waitForTimeout(500);
    await page.click('[data-testid="next-button"]');
    await page.waitForTimeout(500);
    
    // Review page - verify all data is displayed
    await expect(page.locator('[data-testid="review-applicant-name"]')).toContainText('John Doe');
    await expect(page.locator('[data-testid="review-property-address"]')).toContainText('123 Main Street');
    
    // Submit quote
    await page.click('[data-testid="submit-quote-button"]');
    
    // Expected Result: Quote is submitted successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Quote submitted successfully');
    await expect(page.locator('[data-testid="quote-reference-number"]')).toBeVisible();
  });

  test('Ensure navigation is responsive and accessible', async ({ page, context }) => {
    // Step 1: Access quote initiation on various devices and screen sizes
    // Test desktop viewport
    await page.setViewportSize({ width: 1920, height: 1080 });
    await page.click('[data-testid="start-quote-button"]');
    
    // Expected Result: Navigation controls render correctly on desktop
    await expect(page.locator('[data-testid="navigation-controls"]')).toBeVisible();
    await expect(page.locator('[data-testid="progress-indicator"]')).toBeVisible();
    const desktopNavWidth = await page.locator('[data-testid="navigation-controls"]').boundingBox();
    expect(desktopNavWidth).not.toBeNull();
    
    // Test tablet viewport
    await page.setViewportSize({ width: 768, height: 1024 });
    await page.waitForTimeout(300);
    
    // Expected Result: Navigation controls render correctly on tablet
    await expect(page.locator('[data-testid="navigation-controls"]')).toBeVisible();
    await expect(page.locator('[data-testid="progress-indicator"]')).toBeVisible();
    const tabletNavWidth = await page.locator('[data-testid="navigation-controls"]').boundingBox();
    expect(tabletNavWidth).not.toBeNull();
    
    // Test mobile viewport
    await page.setViewportSize({ width: 375, height: 667 });
    await page.waitForTimeout(300);
    
    // Expected Result: Navigation controls render correctly and are usable on mobile
    await expect(page.locator('[data-testid="navigation-controls"]')).toBeVisible();
    await expect(page.locator('[data-testid="progress-indicator"]')).toBeVisible();
    
    // Verify navigation buttons are clickable on mobile
    await page.fill('[data-testid="applicant-first-name"]', 'Jane');
    await page.fill('[data-testid="applicant-last-name"]', 'Smith');
    await page.click('[data-testid="next-button"]');
    await expect(page.locator('[data-testid="step-2-indicator"]')).toHaveClass(/active/);
    
    // Reset to desktop for accessibility testing
    await page.setViewportSize({ width: 1920, height: 1080 });
    await page.goto('/quote-initiation');
    await page.click('[data-testid="start-quote-button"]');
    
    // Step 2: Use keyboard navigation and screen readers
    // Test keyboard navigation - Tab through form fields
    await page.keyboard.press('Tab');
    await expect(page.locator('[data-testid="applicant-first-name"]')).toBeFocused();
    
    await page.keyboard.type('Robert');
    await page.keyboard.press('Tab');
    await expect(page.locator('[data-testid="applicant-last-name"]')).toBeFocused();
    
    await page.keyboard.type('Johnson');
    await page.keyboard.press('Tab');
    await expect(page.locator('[data-testid="applicant-email"]')).toBeFocused();
    
    await page.keyboard.type('robert.johnson@example.com');
    await page.keyboard.press('Tab');
    await expect(page.locator('[data-testid="applicant-phone"]')).toBeFocused();
    
    await page.keyboard.type('555-987-6543');
    
    // Navigate to next button using Tab and activate with Enter
    await page.keyboard.press('Tab');
    await expect(page.locator('[data-testid="next-button"]')).toBeFocused();
    await page.keyboard.press('Enter');
    
    // Expected Result: Navigation is accessible and compliant with standards
    await expect(page.locator('[data-testid="step-2-indicator"]')).toHaveClass(/active/);
    
    // Verify ARIA labels and roles are present
    await expect(page.locator('[data-testid="progress-indicator"]')).toHaveAttribute('role', 'progressbar');
    await expect(page.locator('[data-testid="next-button"]')).toHaveAttribute('aria-label');
    await expect(page.locator('[data-testid="back-button"]')).toHaveAttribute('aria-label');
    
    // Test back navigation with keyboard
    await page.keyboard.press('Shift+Tab');
    await page.keyboard.press('Shift+Tab');
    await expect(page.locator('[data-testid="back-button"]')).toBeFocused();
    await page.keyboard.press('Enter');
    
    await expect(page.locator('[data-testid="step-1-indicator"]')).toHaveClass(/active/);
    
    // Verify form fields retained data after keyboard navigation
    await expect(page.locator('[data-testid="applicant-first-name"]')).toHaveValue('Robert');
    await expect(page.locator('[data-testid="applicant-last-name"]')).toHaveValue('Johnson');
    
    // Verify skip links for accessibility
    await page.goto('/quote-initiation');
    await page.keyboard.press('Tab');
    const skipLink = page.locator('[data-testid="skip-to-content"]');
    if (await skipLink.isVisible()) {
      await expect(skipLink).toHaveAttribute('href', '#main-content');
    }
  });
});