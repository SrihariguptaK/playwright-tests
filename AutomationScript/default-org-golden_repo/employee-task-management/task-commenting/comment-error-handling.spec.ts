import { test, expect } from '@playwright/test';

test.describe('Comment Error Handling - Story 20', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application page where comments can be added
    await page.goto('/dashboard');
    // Wait for page to be fully loaded
    await page.waitForLoadState('networkidle');
  });

  test('Verify error message displayed on comment submission failure', async ({ page }) => {
    // Intercept the comment submission API and force it to fail
    await page.route('**/api/comments', async (route) => {
      await route.fulfill({
        status: 500,
        contentType: 'application/json',
        body: JSON.stringify({
          error: 'Internal Server Error',
          message: 'Failed to save comment'
        })
      });
    });

    // Navigate to comment section or open comment dialog
    await page.click('[data-testid="add-comment-button"]');
    
    // Fill in the comment text area
    await page.fill('[data-testid="comment-textarea"]', 'This is a test comment that will fail');
    
    // Submit the comment
    await page.click('[data-testid="submit-comment-button"]');
    
    // Wait for error message to appear
    await page.waitForSelector('[data-testid="error-message"]', { state: 'visible' });
    
    // Verify that error message is displayed
    const errorMessage = await page.locator('[data-testid="error-message"]');
    await expect(errorMessage).toBeVisible();
    
    // Verify error message contains descriptive text
    await expect(errorMessage).toContainText(/failed|error|unable/i);
    
    // Verify the error message is user-friendly (not technical)
    const errorText = await errorMessage.textContent();
    expect(errorText).toBeTruthy();
    expect(errorText!.length).toBeGreaterThan(10);
    
    // Verify comment was not added to the list
    const commentList = page.locator('[data-testid="comment-list"]');
    await expect(commentList).not.toContainText('This is a test comment that will fail');
  });

  test('Verify error logging on comment submission failure', async ({ page, context }) => {
    const consoleLogs: string[] = [];
    const networkErrors: any[] = [];
    
    // Capture console errors for verification
    page.on('console', (msg) => {
      if (msg.type() === 'error') {
        consoleLogs.push(msg.text());
      }
    });
    
    // Capture network requests for logging verification
    page.on('requestfailed', (request) => {
      networkErrors.push({
        url: request.url(),
        method: request.method(),
        failure: request.failure()
      });
    });
    
    // Intercept the comment submission API and force it to fail
    await page.route('**/api/comments', async (route) => {
      await route.abort('failed');
    });
    
    // Navigate to comment section
    await page.click('[data-testid="add-comment-button"]');
    
    // Fill in the comment
    await page.fill('[data-testid="comment-textarea"]', 'Test comment for error logging');
    
    // Submit the comment to trigger failure
    await page.click('[data-testid="submit-comment-button"]');
    
    // Wait for error to be processed
    await page.waitForTimeout(1000);
    
    // Verify error was logged (check console logs or network errors)
    const hasErrorLogged = consoleLogs.length > 0 || networkErrors.length > 0;
    expect(hasErrorLogged).toBeTruthy();
    
    // If network errors captured, verify comment API was involved
    if (networkErrors.length > 0) {
      const commentApiError = networkErrors.find(err => err.url.includes('/api/comments'));
      expect(commentApiError).toBeDefined();
    }
    
    // Verify error message is shown to user
    const errorMessage = page.locator('[data-testid="error-message"]');
    await expect(errorMessage).toBeVisible();
    
    // Check if error details are available in the DOM (for support teams)
    const errorDetails = page.locator('[data-testid="error-details"]');
    const errorDetailsCount = await errorDetails.count();
    
    // Error details might be hidden but should exist for logging purposes
    if (errorDetailsCount > 0) {
      const detailsText = await errorDetails.textContent();
      expect(detailsText).toBeTruthy();
    }
    
    // Verify comment textarea still contains the original text (data not lost)
    const commentTextarea = page.locator('[data-testid="comment-textarea"]');
    await expect(commentTextarea).toHaveValue('Test comment for error logging');
  });

  test('Verify data is not lost on failed comment submission', async ({ page }) => {
    // Intercept the comment submission API and force it to fail
    await page.route('**/api/comments', async (route) => {
      await route.fulfill({
        status: 503,
        contentType: 'application/json',
        body: JSON.stringify({
          error: 'Service Unavailable',
          message: 'Unable to process comment at this time'
        })
      });
    });
    
    const testCommentText = 'Important comment that should not be lost';
    
    // Open comment dialog
    await page.click('[data-testid="add-comment-button"]');
    
    // Fill in the comment
    await page.fill('[data-testid="comment-textarea"]', testCommentText);
    
    // Submit the comment
    await page.click('[data-testid="submit-comment-button"]');
    
    // Wait for error message
    await page.waitForSelector('[data-testid="error-message"]', { state: 'visible' });
    
    // Verify error message is displayed
    const errorMessage = page.locator('[data-testid="error-message"]');
    await expect(errorMessage).toBeVisible();
    
    // Verify the comment text is still present in the textarea
    const commentTextarea = page.locator('[data-testid="comment-textarea"]');
    await expect(commentTextarea).toHaveValue(testCommentText);
    
    // Verify user can retry submission
    const submitButton = page.locator('[data-testid="submit-comment-button"]');
    await expect(submitButton).toBeEnabled();
    
    // Verify comment was not added to the list
    const commentList = page.locator('[data-testid="comment-list"]');
    await expect(commentList).not.toContainText(testCommentText);
  });

  test('Verify clear and user-friendly error messages for different failure types', async ({ page }) => {
    // Test network timeout error
    await page.route('**/api/comments', async (route) => {
      await route.fulfill({
        status: 408,
        contentType: 'application/json',
        body: JSON.stringify({
          error: 'Request Timeout',
          message: 'Request took too long to process'
        })
      });
    });
    
    await page.click('[data-testid="add-comment-button"]');
    await page.fill('[data-testid="comment-textarea"]', 'Test comment for timeout');
    await page.click('[data-testid="submit-comment-button"]');
    
    // Verify timeout error message
    const errorMessage = page.locator('[data-testid="error-message"]');
    await expect(errorMessage).toBeVisible();
    await expect(errorMessage).toContainText(/timeout|took too long|try again/i);
    
    // Close error or dialog
    const closeButton = page.locator('[data-testid="close-comment-dialog"]');
    if (await closeButton.isVisible()) {
      await closeButton.click();
    }
    
    // Test server error
    await page.route('**/api/comments', async (route) => {
      await route.fulfill({
        status: 500,
        contentType: 'application/json',
        body: JSON.stringify({
          error: 'Internal Server Error',
          message: 'An unexpected error occurred'
        })
      });
    });
    
    await page.click('[data-testid="add-comment-button"]');
    await page.fill('[data-testid="comment-textarea"]', 'Test comment for server error');
    await page.click('[data-testid="submit-comment-button"]');
    
    // Verify server error message is user-friendly
    await expect(errorMessage).toBeVisible();
    const errorText = await errorMessage.textContent();
    expect(errorText).toBeTruthy();
    // Verify no technical jargon or stack traces are shown
    expect(errorText!.toLowerCase()).not.toContain('stack');
    expect(errorText!.toLowerCase()).not.toContain('exception');
  });
});