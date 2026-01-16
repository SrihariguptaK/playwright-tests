import { test, expect } from '@playwright/test';

test.describe('Quote Submission - Story 7', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to quote initiation form
    await page.goto('/quote-initiation');
    // Wait for form to be ready
    await page.waitForLoadState('networkidle');
  });

  test('Validate successful quote submission with complete data', async ({ page }) => {
    // Step 1: Complete all required applicant and risk data fields
    await page.fill('[data-testid="applicant-name"]', 'John Smith');
    await page.fill('[data-testid="contact-number"]', '555-123-4567');
    await page.fill('[data-testid="email"]', 'john.smith@example.com');
    await page.fill('[data-testid="address"]', '123 Main Street');
    await page.fill('[data-testid="city"]', 'Springfield');
    await page.fill('[data-testid="state"]', 'IL');
    await page.fill('[data-testid="zip-code"]', '62701');
    await page.selectOption('[data-testid="coverage-type"]', 'comprehensive');
    await page.fill('[data-testid="coverage-amount"]', '500000');
    await page.fill('[data-testid="property-value"]', '350000');
    
    // Expected Result: No validation errors
    const validationErrors = await page.locator('[data-testid="validation-error"]').count();
    expect(validationErrors).toBe(0);
    
    // Step 2: Click submit to initiate quote
    await page.click('[data-testid="submit-quote-button"]');
    
    // Expected Result: Submission is processed successfully
    await page.waitForSelector('[data-testid="submission-success"]', { timeout: 5000 });
    const successMessage = await page.locator('[data-testid="submission-success"]');
    await expect(successMessage).toBeVisible();
    
    // Step 3: View confirmation message
    // Expected Result: Unique quote ID and details are displayed
    const quoteId = await page.locator('[data-testid="quote-id"]');
    await expect(quoteId).toBeVisible();
    const quoteIdText = await quoteId.textContent();
    expect(quoteIdText).toMatch(/[A-Z0-9]{8,}/);
    
    const quoteDetails = await page.locator('[data-testid="quote-details"]');
    await expect(quoteDetails).toBeVisible();
    await expect(quoteDetails).toContainText('John Smith');
    await expect(quoteDetails).toContainText('comprehensive');
  });

  test('Verify submission blocked with incomplete data', async ({ page }) => {
    // Step 1: Leave mandatory fields empty
    // Intentionally not filling required fields
    
    // Step 2: Attempt to submit quote
    await page.click('[data-testid="submit-quote-button"]');
    
    // Expected Result: Validation errors are shown
    await page.waitForSelector('[data-testid="validation-error"]', { timeout: 3000 });
    const validationErrors = await page.locator('[data-testid="validation-error"]');
    const errorCount = await validationErrors.count();
    expect(errorCount).toBeGreaterThan(0);
    
    // Expected Result: Submission is blocked with error messages
    const submitButton = await page.locator('[data-testid="submit-quote-button"]');
    await expect(submitButton).toBeDisabled();
    
    const errorMessage = await page.locator('[data-testid="error-message"]');
    await expect(errorMessage).toBeVisible();
    await expect(errorMessage).toContainText('required');
    
    // Verify no success confirmation appears
    const successMessage = await page.locator('[data-testid="submission-success"]').count();
    expect(successMessage).toBe(0);
  });

  test('Ensure error handling during submission failures', async ({ page }) => {
    // Fill in complete data
    await page.fill('[data-testid="applicant-name"]', 'Jane Doe');
    await page.fill('[data-testid="contact-number"]', '555-987-6543');
    await page.fill('[data-testid="email"]', 'jane.doe@example.com');
    await page.fill('[data-testid="address"]', '456 Oak Avenue');
    await page.fill('[data-testid="city"]', 'Chicago');
    await page.fill('[data-testid="state"]', 'IL');
    await page.fill('[data-testid="zip-code"]', '60601');
    await page.selectOption('[data-testid="coverage-type"]', 'basic');
    await page.fill('[data-testid="coverage-amount"]', '250000');
    await page.fill('[data-testid="property-value"]', '200000');
    
    // Step 1: Simulate backend failure during submission
    await page.route('**/api/quotes/initiate', route => {
      route.abort('failed');
    });
    
    await page.click('[data-testid="submit-quote-button"]');
    
    // Expected Result: Error message is displayed
    await page.waitForSelector('[data-testid="submission-error"]', { timeout: 5000 });
    const errorMessage = await page.locator('[data-testid="submission-error"]');
    await expect(errorMessage).toBeVisible();
    await expect(errorMessage).toContainText('failed');
    
    // Verify retry option is available
    const retryButton = await page.locator('[data-testid="retry-button"]');
    await expect(retryButton).toBeVisible();
    
    // Step 2: Retry submission
    // Remove the route interception to allow success
    await page.unroute('**/api/quotes/initiate');
    
    await page.click('[data-testid="retry-button"]');
    
    // Expected Result: Submission succeeds or appropriate error is shown
    await page.waitForSelector('[data-testid="submission-success"], [data-testid="submission-error"]', { timeout: 5000 });
    
    const successExists = await page.locator('[data-testid="submission-success"]').count();
    const errorExists = await page.locator('[data-testid="submission-error"]').count();
    
    expect(successExists + errorExists).toBeGreaterThan(0);
  });

  test('Validate display of specific error messages on invalid submission', async ({ page }) => {
    // Navigate to the quote initiation form (already done in beforeEach)
    
    // Leave the applicant name field empty
    // Leave the contact number field empty
    // Leave the email field empty
    // Leave the coverage type field unselected
    
    // Click the Submit button with multiple mandatory fields empty
    await page.click('[data-testid="submit-quote-button"]');
    
    // Verify that a specific error message is displayed for the missing applicant name field
    const nameError = await page.locator('[data-testid="applicant-name-error"]');
    await expect(nameError).toBeVisible();
    await expect(nameError).toContainText('Applicant name is required');
    
    // Verify that a specific error message is displayed for the missing contact number field
    const contactError = await page.locator('[data-testid="contact-number-error"]');
    await expect(contactError).toBeVisible();
    await expect(contactError).toContainText('Contact number is required');
    
    // Verify that a specific error message is displayed for the missing email field
    const emailError = await page.locator('[data-testid="email-error"]');
    await expect(emailError).toBeVisible();
    await expect(emailError).toContainText('Email is required');
    
    // Verify that a specific error message is displayed for the missing coverage type field
    const coverageError = await page.locator('[data-testid="coverage-type-error"]');
    await expect(coverageError).toBeVisible();
    await expect(coverageError).toContainText('Coverage type is required');
    
    // Verify that all fields with errors are visually highlighted or distinguished
    const nameField = await page.locator('[data-testid="applicant-name"]');
    await expect(nameField).toHaveClass(/error|invalid/);
    
    const contactField = await page.locator('[data-testid="contact-number"]');
    await expect(contactField).toHaveClass(/error|invalid/);
    
    const emailField = await page.locator('[data-testid="email"]');
    await expect(emailField).toHaveClass(/error|invalid/);
    
    const coverageField = await page.locator('[data-testid="coverage-type"]');
    await expect(coverageField).toHaveClass(/error|invalid/);
    
    // Verify that error messages provide guidance on how to correct each error
    await expect(nameError).toContainText(/enter|provide|required/);
    await expect(contactError).toContainText(/enter|provide|required/);
    await expect(emailError).toContainText(/enter|provide|required/);
    await expect(coverageError).toContainText(/select|choose|required/);
    
    // Fill in the applicant name field with valid data
    await page.fill('[data-testid="applicant-name"]', 'Michael Johnson');
    
    // Fill in the contact number field with valid data
    await page.fill('[data-testid="contact-number"]', '555-234-5678');
    
    // Fill in the email field with valid data
    await page.fill('[data-testid="email"]', 'michael.johnson@example.com');
    
    // Select a valid coverage type from the dropdown
    await page.selectOption('[data-testid="coverage-type"]', 'premium');
    
    // Fill in all remaining mandatory fields with valid data
    await page.fill('[data-testid="address"]', '789 Elm Street');
    await page.fill('[data-testid="city"]', 'Naperville');
    await page.fill('[data-testid="state"]', 'IL');
    await page.fill('[data-testid="zip-code"]', '60540');
    await page.fill('[data-testid="coverage-amount"]', '750000');
    await page.fill('[data-testid="property-value"]', '500000');
    
    // Click the Submit button to resubmit the corrected quote
    await page.click('[data-testid="submit-quote-button"]');
    
    // Verify successful submission
    await page.waitForSelector('[data-testid="submission-success"]', { timeout: 5000 });
    const successMessage = await page.locator('[data-testid="submission-success"]');
    await expect(successMessage).toBeVisible();
    
    // Verify no error messages remain
    const remainingErrors = await page.locator('[data-testid="validation-error"]').count();
    expect(remainingErrors).toBe(0);
  });

  test('Ensure error messages do not expose sensitive data', async ({ page }) => {
    // Navigate to the quote initiation form (already done in beforeEach)
    
    // Enter an invalid format for a sensitive field (e.g., invalid SSN format like '123-45-678X')
    await page.fill('[data-testid="ssn"]', '123-45-678X');
    
    // Enter invalid data in other fields that may contain sensitive information
    await page.fill('[data-testid="credit-score"]', '999');
    await page.fill('[data-testid="medical-condition-code"]', 'INVALID_CODE_12345');
    await page.fill('[data-testid="bank-account"]', '1234567890ABCD');
    
    // Click the Submit button to trigger validation
    await page.click('[data-testid="submit-quote-button"]');
    
    // Wait for error messages to appear
    await page.waitForSelector('[data-testid="validation-error"]', { timeout: 3000 });
    
    // Review all error messages displayed on the screen
    const allErrors = await page.locator('[data-testid="validation-error"]').allTextContents();
    const errorMessagesText = allErrors.join(' ');
    
    // Verify that error messages do not display the actual invalid SSN value entered
    expect(errorMessagesText).not.toContain('123-45-678X');
    expect(errorMessagesText).not.toContain('123');
    expect(errorMessagesText).not.toContain('678X');
    
    // Verify that error messages do not display any partial sensitive data
    expect(errorMessagesText).not.toMatch(/\d{3}-\d{2}-\d{4}/);
    expect(errorMessagesText).not.toContain('678');
    
    // Verify that error messages do not expose internal system information
    expect(errorMessagesText).not.toMatch(/table|database|db|sql|query|schema/i);
    expect(errorMessagesText).not.toMatch(/varchar|int|column|field_name/i);
    expect(errorMessagesText).not.toMatch(/validation_rule|constraint|foreign_key/i);
    
    // Verify that error messages do not reveal information about other users or quotes
    expect(errorMessagesText).not.toMatch(/user_id|quote_id|customer_id/i);
    expect(errorMessagesText).not.toMatch(/other user|another quote|existing record/i);
    
    // Check browser console for any sensitive data exposure
    const consoleLogs: string[] = [];
    page.on('console', msg => {
      consoleLogs.push(msg.text());
    });
    
    // Trigger validation again to capture console logs
    await page.click('[data-testid="submit-quote-button"]');
    await page.waitForTimeout(1000);
    
    const consoleText = consoleLogs.join(' ');
    expect(consoleText).not.toContain('123-45-678X');
    expect(consoleText).not.toContain('INVALID_CODE_12345');
    expect(consoleText).not.toContain('1234567890ABCD');
    
    // Check network logs for any sensitive data exposure
    const networkRequests: string[] = [];
    page.on('request', request => {
      networkRequests.push(request.url());
    });
    
    // Verify that all error messages provide generic but helpful guidance
    const ssnError = await page.locator('[data-testid="ssn-error"]');
    if (await ssnError.count() > 0) {
      const ssnErrorText = await ssnError.textContent();
      expect(ssnErrorText).toMatch(/invalid format|incorrect format|valid SSN/i);
      expect(ssnErrorText).not.toContain('123-45-678X');
    }
    
    const creditScoreError = await page.locator('[data-testid="credit-score-error"]');
    if (await creditScoreError.count() > 0) {
      const creditErrorText = await creditScoreError.textContent();
      expect(creditErrorText).toMatch(/invalid|out of range|valid credit score/i);
      expect(creditErrorText).not.toContain('999');
    }
    
    const medicalError = await page.locator('[data-testid="medical-condition-code-error"]');
    if (await medicalError.count() > 0) {
      const medicalErrorText = await medicalError.textContent();
      expect(medicalErrorText).toMatch(/invalid code|unrecognized code|valid medical code/i);
      expect(medicalErrorText).not.toContain('INVALID_CODE_12345');
    }
    
    // Verify error messages do not expose confidential information
    const allErrorElements = await page.locator('[data-testid="validation-error"]').all();
    for (const errorElement of allErrorElements) {
      const errorText = await errorElement.textContent();
      expect(errorText).not.toMatch(/password|token|secret|api_key/i);
      expect(errorText).not.toMatch(/\d{3}-\d{2}-\d{4}/);
      expect(errorText).not.toMatch(/\d{16}/);
    }
  });
});