import { test, expect } from '@playwright/test';

test('As Employee, I want to view my daily schedule to plan my workday effectively', async ({ page }) => {
  // TODO: Implement test steps for: As Employee, I want to view my daily schedule to plan my workday effectively
  // Response parsing failed - please review and implement manually
  await page.goto('/');
  await expect(page).toHaveTitle(/.*/)
});