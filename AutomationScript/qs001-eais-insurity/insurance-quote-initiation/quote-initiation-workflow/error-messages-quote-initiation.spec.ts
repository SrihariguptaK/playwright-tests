import { test, expect } from '@playwright/test';

test.describe('Error Messages During Quote Initiation', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to quote initiation page
    await page.goto('/quote/initiate');
    // Wait for page to be fully loaded
    await page.waitForLoadState('networkidle');
  });

  test('Validate display of specific error messages on invalid submission', async ({ page }) => {
    // Step 1: Submit quote with missing mandatory fields
    // Leave mandatory fields empty
    await page.fill('[data-testid="applicant-name"]', '');
    await page.fill('[data-testid="policy-type"]', '');
    await page.fill('[data-testid="coverage-amount"]', '');
    await page.fill('[data-testid="effective-date"]', '');
    
    // Click submit button
    await page.click('[data-testid="submit-quote-button"]');
    
    // Wait for error messages to appear
    await page.waitForSelector('[data-testid="error-message"]', { timeout: 1000 });
    
    // Expected Result: Specific error messages are displayed for each missing field
    const errorMessages = await page.locator('[data-testid="error-message"]').all();
    expect(errorMessages.length).toBeGreaterThan(0);
    
    // Verify specific error messages for each field
    await expect(page.locator('[data-testid="applicant-name-error"]')).toContainText('Applicant name is required');
    await expect(page.locator('[data-testid="policy-type-error"]')).toContainText('Policy type is required');
    await expect(page.locator('[data-testid="coverage-amount-error"]')).toContainText('Coverage amount is required');
    await expect(page.locator('[data-testid="effective-date-error"]')).toContainText('Effective date is required');
    
    // Step 2: Verify related fields are highlighted
    // Expected Result: Fields with errors are visually distinguished
    const applicantNameField = page.locator('[data-testid="applicant-name"]');
    const policyTypeField = page.locator('[data-testid="policy-type"]');
    const coverageAmountField = page.locator('[data-testid="coverage-amount"]');
    const effectiveDateField = page.locator('[data-testid="effective-date"]');
    
    // Check for error styling (border color, background, or error class)
    await expect(applicantNameField).toHaveClass(/error|invalid/);
    await expect(policyTypeField).toHaveClass(/error|invalid/);
    await expect(coverageAmountField).toHaveClass(/error|invalid/);
    await expect(effectiveDateField).toHaveClass(/error|invalid/);
    
    // Verify error icon or indicator is present
    await expect(page.locator('[data-testid="applicant-name-error-icon"]')).toBeVisible();
    await expect(page.locator('[data-testid="policy-type-error-icon"]')).toBeVisible();
    await expect(page.locator('[data-testid="coverage-amount-error-icon"]')).toBeVisible();
    await expect(page.locator('[data-testid="effective-date-error-icon"]')).toBeVisible();
    
    // Step 3: Correct errors and resubmit
    // Fill in all mandatory fields with valid data
    await page.fill('[data-testid="applicant-name"]', 'John Smith');
    await page.selectOption('[data-testid="policy-type"]', { label: 'Auto Insurance' });
    await page.fill('[data-testid="coverage-amount"]', '500000');
    await page.fill('[data-testid="effective-date"]', '2024-12-31');
    
    // Additional required fields
    await page.fill('[data-testid="applicant-email"]', 'john.smith@example.com');
    await page.fill('[data-testid="applicant-phone"]', '555-123-4567');
    await page.fill('[data-testid="applicant-address"]', '123 Main Street');
    await page.fill('[data-testid="applicant-city"]', 'Springfield');
    await page.selectOption('[data-testid="applicant-state"]', { label: 'Illinois' });
    await page.fill('[data-testid="applicant-zip"]', '62701');
    
    // Resubmit the quote
    await page.click('[data-testid="submit-quote-button"]');
    
    // Expected Result: Submission succeeds without errors
    // Wait for success message or redirect
    await page.waitForSelector('[data-testid="success-message"]', { timeout: 5000 });
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Quote submitted successfully');
    
    // Verify no error messages are displayed
    await expect(page.locator('[data-testid="error-message"]')).toHaveCount(0);
    
    // Verify error styling is removed from fields
    await expect(applicantNameField).not.toHaveClass(/error|invalid/);
    await expect(policyTypeField).not.toHaveClass(/error|invalid/);
    await expect(coverageAmountField).not.toHaveClass(/error|invalid/);
    await expect(effectiveDateField).not.toHaveClass(/error|invalid/);
  });

  test('Ensure error messages do not expose sensitive data', async ({ page }) => {
    // Step 1: Submit quote with invalid data triggering errors
    // Fill fields with invalid data that might contain sensitive information
    await page.fill('[data-testid="applicant-name"]', 'Test User');
    await page.fill('[data-testid="applicant-ssn"]', '123-45-6789');
    await page.fill('[data-testid="applicant-credit-card"]', '4111111111111111');
    await page.fill('[data-testid="applicant-bank-account"]', '9876543210');
    await page.fill('[data-testid="applicant-password"]', 'SecurePass123!');
    await page.fill('[data-testid="coverage-amount"]', 'invalid-amount');
    await page.fill('[data-testid="effective-date"]', 'invalid-date');
    
    // Submit the form to trigger validation errors
    await page.click('[data-testid="submit-quote-button"]');
    
    // Wait for error messages to appear
    await page.waitForSelector('[data-testid="error-message"]', { timeout: 1000 });
    
    // Expected Result: Error messages contain no sensitive or confidential information
    const allErrorMessages = await page.locator('[data-testid="error-message"]').allTextContents();
    const pageContent = await page.content();
    
    // Verify SSN is not exposed in error messages
    for (const errorMessage of allErrorMessages) {
      expect(errorMessage).not.toContain('123-45-6789');
      expect(errorMessage).not.toContain('123456789');
    }
    expect(pageContent).not.toContain('123-45-6789');
    
    // Verify credit card number is not exposed
    for (const errorMessage of allErrorMessages) {
      expect(errorMessage).not.toContain('4111111111111111');
      expect(errorMessage).not.toContain('4111');
    }
    expect(pageContent).not.toContain('4111111111111111');
    
    // Verify bank account is not exposed
    for (const errorMessage of allErrorMessages) {
      expect(errorMessage).not.toContain('9876543210');
    }
    expect(pageContent).not.toContain('9876543210');
    
    // Verify password is not exposed
    for (const errorMessage of allErrorMessages) {
      expect(errorMessage).not.toContain('SecurePass123!');
    }
    expect(pageContent).not.toContain('SecurePass123!');
    
    // Verify error messages are generic and helpful without exposing data
    const ssnErrorMessage = await page.locator('[data-testid="applicant-ssn-error"]').textContent();
    expect(ssnErrorMessage).toMatch(/invalid format|required|must be valid/i);
    expect(ssnErrorMessage).not.toContain('123');
    
    const creditCardErrorMessage = await page.locator('[data-testid="applicant-credit-card-error"]').textContent();
    expect(creditCardErrorMessage).toMatch(/invalid format|required|must be valid/i);
    expect(creditCardErrorMessage).not.toContain('4111');
    
    const coverageAmountErrorMessage = await page.locator('[data-testid="coverage-amount-error"]').textContent();
    expect(coverageAmountErrorMessage).toMatch(/must be a number|invalid amount|numeric value required/i);
    
    const effectiveDateErrorMessage = await page.locator('[data-testid="effective-date-error"]').textContent();
    expect(effectiveDateErrorMessage).toMatch(/invalid date|date format required|must be valid date/i);
    
    // Verify error messages provide guidance without exposing input values
    expect(ssnErrorMessage).toBeTruthy();
    expect(creditCardErrorMessage).toBeTruthy();
    expect(coverageAmountErrorMessage).toBeTruthy();
    expect(effectiveDateErrorMessage).toBeTruthy();
  });
});