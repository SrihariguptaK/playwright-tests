import { test, expect } from '@playwright/test';

test.describe('Demographic Data Format Validation', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the demographic data entry form before each test
    await page.goto('/demographic-data-entry');
    await expect(page).toHaveTitle(/Demographic Data Entry/i);
  });

  test('Validate acceptance of correct email formats', async ({ page }) => {
    // Enter a valid email address in standard format
    await page.fill('[data-testid="email-input"]', 'user@example.com');
    await page.blur('[data-testid="email-input"]');
    
    // Verify no validation error is displayed
    await expect(page.locator('[data-testid="email-error"]')).not.toBeVisible();
    
    // Enter another valid email with subdomain
    await page.fill('[data-testid="email-input"]', 'user.name@mail.example.com');
    await page.blur('[data-testid="email-input"]');
    
    // Verify no validation error is displayed
    await expect(page.locator('[data-testid="email-error"]')).not.toBeVisible();
    
    // Enter a valid email with numbers
    await page.fill('[data-testid="email-input"]', 'user123@example.org');
    await page.blur('[data-testid="email-input"]');
    
    // Verify no validation error is displayed
    await expect(page.locator('[data-testid="email-error"]')).not.toBeVisible();
    
    // Complete all other required demographic fields with valid data
    await page.fill('[data-testid="first-name-input"]', 'John');
    await page.fill('[data-testid="last-name-input"]', 'Doe');
    await page.fill('[data-testid="phone-input"]', '+1-555-123-4567');
    await page.fill('[data-testid="date-of-birth-input"]', '01/15/1990');
    await page.fill('[data-testid="address-input"]', '123 Main Street');
    
    // Click the Submit button
    await page.click('[data-testid="submit-button"]');
    
    // Verify form submitted successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText(/submitted successfully/i);
  });

  test('Verify rejection of invalid email formats', async ({ page }) => {
    // Enter an email address missing the @ symbol
    await page.fill('[data-testid="email-input"]', 'userexample.com');
    await page.blur('[data-testid="email-input"]');
    
    // Verify inline error message is displayed
    await expect(page.locator('[data-testid="email-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="email-error"]')).toContainText(/invalid email/i);
    
    // Clear the email field and enter an email with invalid domain
    await page.fill('[data-testid="email-input"]', 'user@domain');
    await page.blur('[data-testid="email-input"]');
    
    // Verify inline error message is displayed
    await expect(page.locator('[data-testid="email-error"]')).toBeVisible();
    
    // Clear the email field and enter an email with special characters
    await page.fill('[data-testid="email-input"]', 'user@@example.com');
    await page.blur('[data-testid="email-input"]');
    
    // Verify inline error message is displayed
    await expect(page.locator('[data-testid="email-error"]')).toBeVisible();
    
    // Clear the email field and enter an email without domain extension
    await page.fill('[data-testid="email-input"]', 'user@example');
    await page.blur('[data-testid="email-input"]');
    
    // Verify inline error message is displayed
    await expect(page.locator('[data-testid="email-error"]')).toBeVisible();
    
    // Complete all other required demographic fields with valid data
    await page.fill('[data-testid="first-name-input"]', 'Jane');
    await page.fill('[data-testid="last-name-input"]', 'Smith');
    await page.fill('[data-testid="phone-input"]', '+1-555-987-6543');
    await page.fill('[data-testid="date-of-birth-input"]', '03/20/1985');
    await page.fill('[data-testid="address-input"]', '456 Oak Avenue');
    
    // Attempt to click the Submit button while email error is still present
    await page.click('[data-testid="submit-button"]');
    
    // Verify submission is blocked - submit button should be disabled or form not submitted
    await expect(page.locator('[data-testid="submit-button"]')).toBeDisabled();
    
    // Correct the email field with a valid email address
    await page.fill('[data-testid="email-input"]', 'user@example.com');
    await page.blur('[data-testid="email-input"]');
    
    // Verify error message is no longer displayed
    await expect(page.locator('[data-testid="email-error"]')).not.toBeVisible();
    
    // Verify submit button is now enabled
    await expect(page.locator('[data-testid="submit-button"]')).toBeEnabled();
    
    // Click the Submit button
    await page.click('[data-testid="submit-button"]');
    
    // Verify form submitted successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
  });

  test('Validate phone number format validation', async ({ page }) => {
    // Enter a valid phone number with country code
    await page.fill('[data-testid="phone-input"]', '+1-555-123-4567');
    await page.blur('[data-testid="phone-input"]');
    
    // Verify no validation error is displayed
    await expect(page.locator('[data-testid="phone-error"]')).not.toBeVisible();
    
    // Clear the phone field and enter a valid phone number without country code
    await page.fill('[data-testid="phone-input"]', '555-123-4567');
    await page.blur('[data-testid="phone-input"]');
    
    // Verify no validation error is displayed
    await expect(page.locator('[data-testid="phone-error"]')).not.toBeVisible();
    
    // Clear the phone field and enter an international phone number
    await page.fill('[data-testid="phone-input"]', '+44-20-7123-4567');
    await page.blur('[data-testid="phone-input"]');
    
    // Verify no validation error is displayed
    await expect(page.locator('[data-testid="phone-error"]')).not.toBeVisible();
    
    // Clear the phone field and enter an invalid phone number with letters
    await page.fill('[data-testid="phone-input"]', '555-ABC-1234');
    await page.blur('[data-testid="phone-input"]');
    
    // Verify inline error message is displayed for invalid format
    await expect(page.locator('[data-testid="phone-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="phone-error"]')).toContainText(/invalid phone/i);
    
    // Clear the phone field and enter an invalid phone number with insufficient digits
    await page.fill('[data-testid="phone-input"]', '123-45');
    await page.blur('[data-testid="phone-input"]');
    
    // Verify inline error message is displayed for invalid format
    await expect(page.locator('[data-testid="phone-error"]')).toBeVisible();
    
    // Correct the phone field with a valid phone number
    await page.fill('[data-testid="phone-input"]', '+1-555-987-6543');
    await page.blur('[data-testid="phone-input"]');
    
    // Verify error message is no longer displayed
    await expect(page.locator('[data-testid="phone-error"]')).not.toBeVisible();
    
    // Complete all other required demographic fields with valid data
    await page.fill('[data-testid="email-input"]', 'testuser@example.com');
    await page.fill('[data-testid="first-name-input"]', 'Michael');
    await page.fill('[data-testid="last-name-input"]', 'Johnson');
    await page.fill('[data-testid="date-of-birth-input"]', '07/10/1992');
    await page.fill('[data-testid="address-input"]', '789 Pine Road');
    
    // Click the Submit button
    await page.click('[data-testid="submit-button"]');
    
    // Verify form submitted successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText(/submitted successfully/i);
  });
});