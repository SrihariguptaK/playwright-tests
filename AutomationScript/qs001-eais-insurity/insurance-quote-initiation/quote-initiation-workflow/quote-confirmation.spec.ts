import { test, expect } from '@playwright/test';

test.describe('Quote Initiation Confirmation - Story 8', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  
  test.beforeEach(async ({ page }) => {
    await page.goto(`${baseURL}/quote-initiation`);
  });

  test('Validate display of quote initiation confirmation', async ({ page }) => {
    // Step 1: Submit a completed quote
    await page.click('[data-testid="start-new-quote-btn"]');
    
    // Fill applicant data
    await page.fill('[data-testid="applicant-name"]', 'John Smith');
    await page.fill('[data-testid="applicant-email"]', 'john.smith@example.com');
    await page.fill('[data-testid="applicant-phone"]', '555-123-4567');
    await page.fill('[data-testid="applicant-address"]', '123 Main Street');
    await page.fill('[data-testid="applicant-city"]', 'Springfield');
    await page.fill('[data-testid="applicant-state"]', 'IL');
    await page.fill('[data-testid="applicant-zip"]', '62701');
    
    await page.click('[data-testid="next-btn"]');
    
    // Fill risk data
    await page.selectOption('[data-testid="property-type"]', 'Single Family Home');
    await page.fill('[data-testid="coverage-amount"]', '500000');
    await page.selectOption('[data-testid="risk-assessment"]', 'Low');
    await page.fill('[data-testid="property-age"]', '15');
    
    await page.click('[data-testid="next-btn"]');
    
    // Complete additional fields
    await page.fill('[data-testid="additional-info"]', 'No prior claims');
    
    await page.click('[data-testid="next-btn"]');
    
    // Review and submit
    await page.click('[data-testid="submit-quote-btn"]');
    
    // Expected Result: Confirmation screen is displayed
    await expect(page.locator('[data-testid="confirmation-screen"]')).toBeVisible({ timeout: 2000 });
    await expect(page.locator('[data-testid="confirmation-title"]')).toContainText('Quote Successfully Initiated');
    
    // Step 2: Verify unique quote ID and data summary are shown
    const quoteIdElement = page.locator('[data-testid="quote-id"]');
    await expect(quoteIdElement).toBeVisible();
    
    const quoteId = await quoteIdElement.textContent();
    expect(quoteId).toMatch(/^[A-Z0-9]{8,12}$/);
    
    // Verify data summary matches submitted data
    await expect(page.locator('[data-testid="summary-applicant-name"]')).toContainText('John Smith');
    await expect(page.locator('[data-testid="summary-applicant-email"]')).toContainText('john.smith@example.com');
    await expect(page.locator('[data-testid="summary-property-type"]')).toContainText('Single Family Home');
    await expect(page.locator('[data-testid="summary-coverage-amount"]')).toContainText('500000');
    
    // Step 3: Use print or save options
    const printButton = page.locator('[data-testid="print-confirmation-btn"]');
    await expect(printButton).toBeVisible();
    await expect(printButton).toBeEnabled();
    
    const saveButton = page.locator('[data-testid="save-confirmation-btn"]');
    await expect(saveButton).toBeVisible();
    await expect(saveButton).toBeEnabled();
    
    // Test save functionality
    const downloadPromise = page.waitForEvent('download');
    await saveButton.click();
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toMatch(/quote.*confirmation/i);
    
    // Verify next steps guidance is displayed
    await expect(page.locator('[data-testid="next-steps-section"]')).toBeVisible();
    await expect(page.locator('[data-testid="next-steps-section"]')).toContainText('Next Steps');
  });

  test('Ensure confirmation is only visible to submitting user', async ({ page, context }) => {
    // Step 1: Submit quote as User A
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="username"]', 'agent.usera@insurance.com');
    await page.fill('[data-testid="password"]', 'SecurePass123!');
    await page.click('[data-testid="login-btn"]');
    
    await page.goto(`${baseURL}/quote-initiation`);
    await page.click('[data-testid="start-new-quote-btn"]');
    
    // Fill and submit quote
    await page.fill('[data-testid="applicant-name"]', 'Jane Doe');
    await page.fill('[data-testid="applicant-email"]', 'jane.doe@example.com');
    await page.fill('[data-testid="applicant-phone"]', '555-987-6543');
    await page.fill('[data-testid="applicant-address"]', '456 Oak Avenue');
    await page.fill('[data-testid="applicant-city"]', 'Chicago');
    await page.fill('[data-testid="applicant-state"]', 'IL');
    await page.fill('[data-testid="applicant-zip"]', '60601');
    await page.click('[data-testid="next-btn"]');
    
    await page.selectOption('[data-testid="property-type"]', 'Condo');
    await page.fill('[data-testid="coverage-amount"]', '350000');
    await page.selectOption('[data-testid="risk-assessment"]', 'Medium');
    await page.fill('[data-testid="property-age"]', '10');
    await page.click('[data-testid="next-btn"]');
    
    await page.fill('[data-testid="additional-info"]', 'First time buyer');
    await page.click('[data-testid="next-btn"]');
    
    await page.click('[data-testid="submit-quote-btn"]');
    
    // Expected Result: Confirmation displayed to User A
    await expect(page.locator('[data-testid="confirmation-screen"]')).toBeVisible({ timeout: 2000 });
    
    const quoteIdElement = page.locator('[data-testid="quote-id"]');
    await expect(quoteIdElement).toBeVisible();
    const userAQuoteId = await quoteIdElement.textContent();
    
    // Get the confirmation URL
    const confirmationURL = page.url();
    
    // Step 2: User B attempts to access User A's confirmation
    const userBPage = await context.newPage();
    await userBPage.goto(`${baseURL}/login`);
    await userBPage.fill('[data-testid="username"]', 'agent.userb@insurance.com');
    await userBPage.fill('[data-testid="password"]', 'SecurePass456!');
    await userBPage.click('[data-testid="login-btn"]');
    
    // Attempt to access User A's confirmation URL
    await userBPage.goto(confirmationURL);
    
    // Expected Result: Access is denied
    await expect(userBPage.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(userBPage.locator('[data-testid="access-denied-message"]')).toContainText(/access denied|unauthorized|not authorized/i);
    
    // Verify User B cannot see the quote ID
    const userBQuoteId = userBPage.locator(`[data-testid="quote-id"]:has-text("${userAQuoteId}")`);
    await expect(userBQuoteId).not.toBeVisible();
    
    await userBPage.close();
  });

  test('Validate step-by-step navigation with progress indicators (happy-path)', async ({ page }) => {
    // Navigate to the quote initiation page and click 'Start New Quote' button
    await page.click('[data-testid="start-new-quote-btn"]');
    
    // Verify progress indicator shows Step 1
    await expect(page.locator('[data-testid="progress-indicator"]')).toBeVisible();
    await expect(page.locator('[data-testid="progress-step-1"]')).toHaveClass(/active|current/);
    
    // Enter valid applicant data in all required fields
    await page.fill('[data-testid="applicant-name"]', 'Michael Johnson');
    await page.fill('[data-testid="applicant-email"]', 'michael.johnson@example.com');
    await page.fill('[data-testid="applicant-phone"]', '555-234-5678');
    await page.fill('[data-testid="applicant-address"]', '789 Pine Street');
    await page.fill('[data-testid="applicant-city"]', 'Naperville');
    await page.fill('[data-testid="applicant-state"]', 'IL');
    await page.fill('[data-testid="applicant-zip"]', '60540');
    
    // Click 'Next' button to proceed to the next step
    await page.click('[data-testid="next-btn"]');
    
    // Verify progress indicator shows Step 2
    await expect(page.locator('[data-testid="progress-step-2"]')).toHaveClass(/active|current/);
    await expect(page.locator('[data-testid="progress-step-1"]')).toHaveClass(/completed/);
    
    // Enter valid risk data in all required fields
    await page.selectOption('[data-testid="property-type"]', 'Townhouse');
    await page.fill('[data-testid="coverage-amount"]', '425000');
    await page.selectOption('[data-testid="risk-assessment"]', 'Low');
    await page.fill('[data-testid="property-age"]', '8');
    
    // Click 'Previous' button to return to the Applicant Data step
    await page.click('[data-testid="previous-btn"]');
    
    // Verify returned to Step 1 with data preserved
    await expect(page.locator('[data-testid="progress-step-1"]')).toHaveClass(/active|current/);
    await expect(page.locator('[data-testid="applicant-name"]')).toHaveValue('Michael Johnson');
    
    // Click 'Next' button to return to Risk Data step
    await page.click('[data-testid="next-btn"]');
    
    // Verify returned to Step 2 with data preserved
    await expect(page.locator('[data-testid="progress-step-2"]')).toHaveClass(/active|current/);
    await expect(page.locator('[data-testid="coverage-amount"]')).toHaveValue('425000');
    
    // Click 'Next' button to proceed to Step 3
    await page.click('[data-testid="next-btn"]');
    
    // Verify progress indicator shows Step 3
    await expect(page.locator('[data-testid="progress-step-3"]')).toHaveClass(/active|current/);
    await expect(page.locator('[data-testid="progress-step-2"]')).toHaveClass(/completed/);
    
    // Complete Step 3 fields and click 'Next' to proceed to the Review step
    await page.fill('[data-testid="additional-info"]', 'Property has security system');
    await page.selectOption('[data-testid="occupancy-type"]', 'Owner Occupied');
    await page.click('[data-testid="next-btn"]');
    
    // Verify progress indicator shows Review step
    await expect(page.locator('[data-testid="progress-step-review"]')).toHaveClass(/active|current/);
    await expect(page.locator('[data-testid="progress-step-3"]')).toHaveClass(/completed/);
    
    // Review all entered information and click 'Submit Quote' button
    await expect(page.locator('[data-testid="review-applicant-name"]')).toContainText('Michael Johnson');
    await expect(page.locator('[data-testid="review-property-type"]')).toContainText('Townhouse');
    await expect(page.locator('[data-testid="review-coverage-amount"]')).toContainText('425000');
    
    await page.click('[data-testid="submit-quote-btn"]');
    
    // Verify confirmation screen is displayed
    await expect(page.locator('[data-testid="confirmation-screen"]')).toBeVisible({ timeout: 2000 });
    await expect(page.locator('[data-testid="quote-id"]')).toBeVisible();
  });

  test('Ensure navigation is responsive and accessible (happy-path)', async ({ page, browser }) => {
    // Access quote initiation page on a desktop browser with 1920x1080 resolution
    await page.setViewportSize({ width: 1920, height: 1080 });
    await page.goto(`${baseURL}/quote-initiation`);
    await expect(page.locator('[data-testid="start-new-quote-btn"]')).toBeVisible();
    
    // Resize browser window to 1366x768 resolution
    await page.setViewportSize({ width: 1366, height: 768 });
    await expect(page.locator('[data-testid="start-new-quote-btn"]')).toBeVisible();
    await expect(page.locator('[data-testid="quote-initiation-form"]')).toBeVisible();
    
    // Access quote initiation page on a tablet device in portrait orientation (768x1024)
    await page.setViewportSize({ width: 768, height: 1024 });
    await page.reload();
    await expect(page.locator('[data-testid="start-new-quote-btn"]')).toBeVisible();
    await page.click('[data-testid="start-new-quote-btn"]');
    await expect(page.locator('[data-testid="applicant-name"]')).toBeVisible();
    
    // Rotate tablet to landscape orientation and verify navigation
    await page.setViewportSize({ width: 1024, height: 768 });
    await expect(page.locator('[data-testid="applicant-name"]')).toBeVisible();
    await expect(page.locator('[data-testid="next-btn"]')).toBeVisible();
    
    // Access quote initiation page on a mobile device with 375x667 resolution
    await page.setViewportSize({ width: 375, height: 667 });
    await page.reload();
    await expect(page.locator('[data-testid="start-new-quote-btn"]')).toBeVisible();
    await page.click('[data-testid="start-new-quote-btn"]');
    await expect(page.locator('[data-testid="applicant-name"]')).toBeVisible();
    
    // Reset to desktop for keyboard navigation test
    await page.setViewportSize({ width: 1920, height: 1080 });
    await page.reload();
    
    // Navigate through all steps using only keyboard
    await page.keyboard.press('Tab');
    await page.keyboard.press('Enter'); // Start new quote
    
    // Fill form using keyboard
    await page.keyboard.press('Tab');
    await page.keyboard.type('Sarah Williams');
    await page.keyboard.press('Tab');
    await page.keyboard.type('sarah.williams@example.com');
    await page.keyboard.press('Tab');
    await page.keyboard.type('555-345-6789');
    await page.keyboard.press('Tab');
    await page.keyboard.type('321 Elm Street');
    await page.keyboard.press('Tab');
    await page.keyboard.type('Aurora');
    await page.keyboard.press('Tab');
    await page.keyboard.type('IL');
    await page.keyboard.press('Tab');
    await page.keyboard.type('60505');
    
    // Navigate to Next button and press Enter
    let tabCount = 0;
    while (tabCount < 10) {
      await page.keyboard.press('Tab');
      const focusedElement = await page.evaluateHandle(() => document.activeElement);
      const testId = await focusedElement.evaluate(el => el.getAttribute('data-testid'));
      if (testId === 'next-btn') {
        await page.keyboard.press('Enter');
        break;
      }
      tabCount++;
    }
    
    // Verify moved to next step
    await expect(page.locator('[data-testid="progress-step-2"]')).toHaveClass(/active|current/);
    
    // Test accessibility with axe
    await page.evaluate(() => {
      const script = document.createElement('script');
      script.src = 'https://cdnjs.cloudflare.com/ajax/libs/axe-core/4.7.2/axe.min.js';
      document.head.appendChild(script);
    });
    
    await page.waitForTimeout(1000);
    
    const accessibilityResults = await page.evaluate(async () => {
      if (typeof (window as any).axe !== 'undefined') {
        return await (window as any).axe.run();
      }
      return { violations: [] };
    });
    
    // Verify no critical accessibility violations
    const criticalViolations = accessibilityResults.violations?.filter(
      (v: any) => v.impact === 'critical' || v.impact === 'serious'
    ) || [];
    
    expect(criticalViolations.length).toBe(0);
    
    // Verify color contrast (basic check)
    const contrastRatio = await page.evaluate(() => {
      const button = document.querySelector('[data-testid="next-btn"]') as HTMLElement;
      if (!button) return 0;
      
      const styles = window.getComputedStyle(button);
      const bgColor = styles.backgroundColor;
      const textColor = styles.color;
      
      return { bgColor, textColor };
    });
    
    expect(contrastRatio).toBeTruthy();
    
    // Verify navigation performance across all tested devices
    const navigationMetrics = await page.evaluate(() => {
      const perfData = performance.getEntriesByType('navigation')[0] as PerformanceNavigationTiming;
      return {
        loadTime: perfData.loadEventEnd - perfData.loadEventStart,
        domContentLoaded: perfData.domContentLoadedEventEnd - perfData.domContentLoadedEventStart
      };
    });
    
    expect(navigationMetrics.loadTime).toBeLessThan(3000);
  });
});