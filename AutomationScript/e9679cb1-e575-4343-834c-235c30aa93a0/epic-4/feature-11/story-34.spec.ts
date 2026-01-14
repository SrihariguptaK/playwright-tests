import { test, expect } from '@playwright/test';

test('As Employee, I want to securely log in to the schedule system to protect my personal schedule data', async ({ page }) => {
  // TODO: Implement test steps for: As Employee, I want to securely log in to the schedule system to protect my personal schedule data
  // Response parsing failed - please review and implement manually
  await page.goto('/');
  await expect(page).toHaveTitle(/.*/)
});