import { test, expect } from '@playwright/test';

test.describe('Edit Pending Schedule Change Requests', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to login page
    await page.goto('/login');
    
    // Login with valid employee credentials
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'ValidPassword123');
    await page.click('[data-testid="login-button"]');
    
    // Wait for successful login and dashboard load
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Edit pending schedule change request successfully', async ({ page }) => {
    // Navigate to the 'My Requests' section
    await page.click('[data-testid="my-requests-menu"]');
    await expect(page).toHaveURL(/.*my-requests/);
    
    // Identify and click on a pending schedule change request from the list
    await page.click('[data-testid="request-item"][data-status="pending"]:first-child');
    
    // Verify request details and edit option are available
    await expect(page.locator('[data-testid="request-details"]')).toBeVisible();
    await expect(page.locator('[data-testid="edit-request-button"]')).toBeVisible();
    await expect(page.locator('[data-testid="edit-request-button"]')).toBeEnabled();
    
    // Click the 'Edit' button to enable editing mode
    await page.click('[data-testid="edit-request-button"]');
    
    // Wait for edit form to be visible
    await expect(page.locator('[data-testid="edit-request-form"]')).toBeVisible();
    
    // Update the 'Date' field with a new valid future date
    const futureDate = new Date();
    futureDate.setDate(futureDate.getDate() + 15);
    const formattedDate = futureDate.toISOString().split('T')[0];
    await page.fill('[data-testid="date-input"]', formattedDate);
    
    // Update the 'Reason' field with modified or additional explanation
    await page.fill('[data-testid="reason-input"]', 'Updated reason: Need to attend important family event on this date');
    
    // Optionally update or add a new attachment within the 10MB size limit
    const fileInput = page.locator('[data-testid="attachment-input"]');
    if (await fileInput.isVisible()) {
      await fileInput.setInputFiles({
        name: 'updated-document.pdf',
        mimeType: 'application/pdf',
        buffer: Buffer.from('Mock PDF content for testing')
      });
    }
    
    // Click the 'Submit' or 'Save Changes' button to save the updated request
    await page.click('[data-testid="submit-changes-button"]');
    
    // System validates and saves updates successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Request updated successfully');
    
    // Wait for update to be processed (within 2 seconds as per technical requirements)
    await page.waitForTimeout(500);
    
    // Verify that approvers receive notification of updated request
    // Check notification log or indicator
    await expect(page.locator('[data-testid="notification-sent-indicator"]')).toBeVisible();
    
    // Navigate back to 'My Requests' and verify the updated request shows the new information
    await page.click('[data-testid="my-requests-menu"]');
    await expect(page).toHaveURL(/.*my-requests/);
    
    // Verify the updated request shows the new information
    const updatedRequest = page.locator('[data-testid="request-item"][data-status="pending"]:first-child');
    await expect(updatedRequest).toBeVisible();
    await updatedRequest.click();
    
    // Verify updated fields are displayed
    await expect(page.locator('[data-testid="request-date"]')).toContainText(formattedDate);
    await expect(page.locator('[data-testid="request-reason"]')).toContainText('Updated reason: Need to attend important family event');
  });

  test('Prevent editing of approved requests', async ({ page }) => {
    // Navigate to the 'My Requests' section after successful login
    await page.click('[data-testid="my-requests-menu"]');
    await expect(page).toHaveURL(/.*my-requests/);
    
    // Identify a schedule change request with status 'Approved' from the list
    const approvedRequest = page.locator('[data-testid="request-item"][data-status="approved"]:first-child');
    await expect(approvedRequest).toBeVisible();
    
    // Click on the approved schedule change request to view details
    await approvedRequest.click();
    
    // Verify request details are displayed
    await expect(page.locator('[data-testid="request-details"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Approved');
    
    // Verify that the 'Edit' button is either disabled, hidden, or not present
    const editButton = page.locator('[data-testid="edit-request-button"]');
    const isEditButtonVisible = await editButton.isVisible();
    
    if (isEditButtonVisible) {
      // If visible, verify it is disabled
      await expect(editButton).toBeDisabled();
      
      // Attempt to click on the disabled button
      await editButton.click({ force: true }).catch(() => {});
      
      // Verify edit form is not displayed
      await expect(page.locator('[data-testid="edit-request-form"]')).not.toBeVisible();
    } else {
      // Verify button is not present
      await expect(editButton).not.toBeVisible();
    }
    
    // System denies edit and displays appropriate message
    const errorMessage = page.locator('[data-testid="error-message"]');
    if (await errorMessage.isVisible()) {
      await expect(errorMessage).toContainText(/cannot edit approved request|editing not allowed/i);
    }
    
    // Attempt to directly access the edit functionality via URL manipulation
    const currentUrl = page.url();
    const requestId = currentUrl.match(/\/requests\/(\d+)/)?.[1];
    
    if (requestId) {
      await page.goto(`/my-requests/${requestId}/edit`);
      
      // Verify that the request details remain unchanged and no edit form is displayed
      const editForm = page.locator('[data-testid="edit-request-form"]');
      const accessDeniedMessage = page.locator('[data-testid="access-denied-message"]');
      
      // Either redirected away or shown error message
      const isEditFormVisible = await editForm.isVisible().catch(() => false);
      
      if (isEditFormVisible) {
        // If form is somehow visible, verify it's disabled or read-only
        await expect(page.locator('[data-testid="submit-changes-button"]')).toBeDisabled();
      } else {
        // Verify access denied or redirected to view-only page
        const isAccessDenied = await accessDeniedMessage.isVisible().catch(() => false);
        const isRedirected = !page.url().includes('/edit');
        
        expect(isAccessDenied || isRedirected).toBeTruthy();
      }
      
      // Verify appropriate error message is displayed
      const denialMessage = page.locator('[data-testid="error-message"], [data-testid="access-denied-message"]');
      if (await denialMessage.isVisible()) {
        await expect(denialMessage).toContainText(/cannot edit|not allowed|approved request/i);
      }
    }
    
    // Verify request status remains 'Approved' and unchanged
    await page.click('[data-testid="my-requests-menu"]');
    await approvedRequest.click();
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Approved');
  });
});