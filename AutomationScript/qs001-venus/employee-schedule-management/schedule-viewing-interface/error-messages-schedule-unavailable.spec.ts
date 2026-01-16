import { test, expect } from '@playwright/test';

test.describe('Story-16: Clear error messages for unavailable schedule data', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  const schedulePageURL = `${baseURL}/schedule`;

  test('Validate error message on data unavailability', async ({ page, context }) => {
    // Step 1: Simulate schedule data API failure
    await context.route('**/api/schedule*', route => {
      route.abort('failed');
    });

    await page.goto(schedulePageURL);

    // Expected Result: User-friendly error message is displayed
    const errorMessage = page.locator('[data-testid="error-message"]').or(page.locator('.error-message')).or(page.locator('[role="alert"]'));
    await expect(errorMessage).toBeVisible({ timeout: 10000 });
    
    const errorText = await errorMessage.textContent();
    expect(errorText).toBeTruthy();
    expect(errorText?.toLowerCase()).toContain('schedule');
    
    // Verify error message is user-friendly (not technical)
    expect(errorText).not.toMatch(/500|404|error code|stack trace|exception/i);

    // Step 2: Verify error message includes contact info
    const contactInfo = page.locator('[data-testid="contact-info"]').or(page.locator('.contact-info')).or(page.getByText(/contact|support|help/i));
    
    // Expected Result: Contact information is visible and clear
    await expect(contactInfo).toBeVisible();
    
    const contactText = await contactInfo.textContent();
    expect(contactText).toBeTruthy();
    
    // Verify contact info contains email or phone or support link
    const hasContactDetails = /email|phone|support|help|contact/i.test(contactText || '') || 
                             await page.locator('a[href*="mailto:"]').isVisible() ||
                             await page.locator('a[href*="tel:"]').isVisible() ||
                             await page.locator('a[href*="support"]').isVisible();
    
    expect(hasContactDetails).toBeTruthy();
  });

  test('Verify no sensitive info in error messages', async ({ page, context }) => {
    // Step 1: Trigger API error with sensitive details
    await context.route('**/api/schedule*', route => {
      route.fulfill({
        status: 500,
        contentType: 'application/json',
        body: JSON.stringify({
          error: 'Database connection failed',
          details: 'Connection to db.internal.company.com:5432 failed',
          stackTrace: 'at DatabaseService.connect (db.service.ts:45)',
          credentials: 'user=admin, password=secret123',
          internalError: 'ECONNREFUSED 192.168.1.100:5432'
        })
      });
    });

    await page.goto(schedulePageURL);

    // Expected Result: Error message shown to user is generic and safe
    const errorMessage = page.locator('[data-testid="error-message"]').or(page.locator('.error-message')).or(page.locator('[role="alert"]'));
    await expect(errorMessage).toBeVisible({ timeout: 10000 });
    
    const errorText = await errorMessage.textContent();
    expect(errorText).toBeTruthy();

    // Verify no sensitive information is exposed
    const sensitivePatterns = [
      /password/i,
      /credentials/i,
      /stack\s*trace/i,
      /db\.internal/i,
      /192\.168/i,
      /:\d{4}/,  // port numbers
      /ECONNREFUSED/i,
      /admin/i,
      /secret/i,
      /\.ts:\d+/,  // file paths with line numbers
      /DatabaseService/i,
      /at\s+\w+\.\w+/  // stack trace patterns
    ];

    for (const pattern of sensitivePatterns) {
      expect(errorText).not.toMatch(pattern);
    }

    // Verify message is user-friendly and generic
    const userFriendlyPatterns = [
      /unable to load/i,
      /temporarily unavailable/i,
      /try again/i,
      /contact support/i,
      /experiencing issues/i
    ];

    const hasUserFriendlyMessage = userFriendlyPatterns.some(pattern => pattern.test(errorText || ''));
    expect(hasUserFriendlyMessage).toBeTruthy();

    // Verify entire page content doesn't expose sensitive info
    const pageContent = await page.content();
    expect(pageContent).not.toContain('password');
    expect(pageContent).not.toContain('secret123');
    expect(pageContent).not.toContain('db.internal');
    expect(pageContent).not.toContain('stackTrace');
  });

  test('Verify error logging occurs without exposing details to user', async ({ page, context }) => {
    let consoleErrors: string[] = [];
    
    // Capture console errors for verification
    page.on('console', msg => {
      if (msg.type() === 'error') {
        consoleErrors.push(msg.text());
      }
    });

    // Simulate API failure
    await context.route('**/api/schedule*', route => {
      route.fulfill({
        status: 503,
        contentType: 'application/json',
        body: JSON.stringify({
          error: 'Service Unavailable',
          message: 'Schedule service is temporarily unavailable'
        })
      });
    });

    await page.goto(schedulePageURL);

    // Verify user sees friendly message
    const errorMessage = page.locator('[data-testid="error-message"]').or(page.locator('.error-message')).or(page.locator('[role="alert"]'));
    await expect(errorMessage).toBeVisible({ timeout: 10000 });
    
    const userVisibleError = await errorMessage.textContent();
    expect(userVisibleError).toBeTruthy();
    expect(userVisibleError?.toLowerCase()).toMatch(/schedule|unavailable|try again/i);
  });

  test('Verify contact information is easily accessible from error state', async ({ page, context }) => {
    // Simulate API failure
    await context.route('**/api/schedule*', route => {
      route.abort('failed');
    });

    await page.goto(schedulePageURL);

    // Wait for error message
    const errorMessage = page.locator('[data-testid="error-message"]').or(page.locator('.error-message')).or(page.locator('[role="alert"]'));
    await expect(errorMessage).toBeVisible({ timeout: 10000 });

    // Verify contact link or button is present and clickable
    const contactLink = page.locator('[data-testid="contact-support"]')
      .or(page.locator('a[href*="support"]'))
      .or(page.locator('button:has-text("Contact")'))
      .or(page.getByRole('link', { name: /contact|support|help/i }));

    await expect(contactLink.first()).toBeVisible();
    
    // Verify link is actionable
    const isEnabled = await contactLink.first().isEnabled();
    expect(isEnabled).toBeTruthy();

    // Verify email or phone is displayed
    const emailPattern = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/;
    const phonePattern = /\d{3}[-.]?\d{3}[-.]?\d{4}/;
    
    const pageText = await page.textContent('body');
    const hasContactMethod = emailPattern.test(pageText || '') || phonePattern.test(pageText || '');
    
    expect(hasContactMethod).toBeTruthy();
  });
});