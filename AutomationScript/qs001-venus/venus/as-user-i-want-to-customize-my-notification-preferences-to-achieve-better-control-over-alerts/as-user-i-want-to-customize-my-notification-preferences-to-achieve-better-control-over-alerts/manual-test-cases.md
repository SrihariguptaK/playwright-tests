# Manual Test Cases

## Story: As User, I want to customize my notification preferences to achieve better control over alerts
**Story ID:** story-7

### Test Case: Validate saving of notification preferences
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged into the system with valid credentials
- User has an active account with notification settings enabled
- User has permission to modify notification preferences
- System is accessible and responsive

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to notification settings page from user profile or settings menu | Notification settings page is displayed with all available options visible including notification channels (email, SMS, in-app), frequency settings, and conflict type options |
| 2 | Select preferred notification channels by checking email, SMS, and/or in-app notification options | Selected channels are highlighted/checked without any errors, UI responds immediately to selections, and no error messages are displayed |
| 3 | Select notification frequency from available options (immediate, daily digest, weekly summary) | Frequency option is selected and visually indicated as active |
| 4 | Choose conflict types to be notified about (scheduling conflicts, resource conflicts, priority conflicts) | Conflict types are selected and marked appropriately in the UI |
| 5 | Click the 'Save' or 'Save Preferences' button | System processes the request within 2 seconds, displays a success confirmation message (e.g., 'Preferences saved successfully'), and the save button may briefly show a loading state |
| 6 | Verify that the saved preferences are retained by refreshing the page or navigating away and returning to notification settings | All previously selected preferences are displayed correctly and remain saved |

**Postconditions:**
- User notification preferences are saved in the database
- User preferences are associated with the user profile
- System is ready to send notifications based on new preferences
- Confirmation message is displayed to the user

---

### Test Case: Ensure preferences are applied consistently
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged into the system with valid credentials
- User has previously saved notification preferences
- User has selected specific notification channels (e.g., email and in-app)
- System has the ability to generate scheduling conflicts for testing
- User has access to the selected notification channels

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to notification settings page | Notification settings page is displayed with current preferences shown |
| 2 | Change notification preferences by selecting different channels (e.g., change from email only to email + SMS) and/or modify frequency settings | New preferences are selected and visually indicated in the UI |
| 3 | Click 'Save' button to update preferences | System confirms preferences are updated successfully with a confirmation message, update is processed within 2 seconds |
| 4 | Trigger a scheduling conflict by creating or simulating a double-booking scenario or resource conflict | Scheduling conflict is created successfully in the system and conflict detection mechanism identifies it |
| 5 | Wait for notification to be sent and check the selected notification channel(s) for incoming notification | Notification is sent via the newly selected channel(s) only (e.g., email and SMS if both were selected), notification arrives within expected timeframe |
| 6 | Verify notification content includes conflict details such as conflict type, affected resources, time/date, and recommended actions | Notification content accurately matches user preferences, includes all relevant conflict information, is formatted correctly, and matches the selected conflict types from preferences |
| 7 | Verify that notifications are NOT sent through channels that were deselected | No notifications appear in deselected channels, confirming preferences are applied consistently |
| 8 | Trigger another scheduling conflict of a different type to verify consistency | Notification is sent again via the same selected channels with appropriate content based on conflict type preferences |

**Postconditions:**
- Updated notification preferences are active and applied system-wide
- Notifications are sent only through selected channels
- Notification content matches user-defined preferences
- System maintains consistency across multiple notification events
- Test conflicts can be cleaned up or marked as resolved

---

