# Manual Test Cases

## Story: As Employee, I want to receive reminders for my upcoming shifts to achieve better preparedness.
**Story ID:** story-13

### Test Case: Validate reminder subscription functionality
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Employee account exists in the system with valid credentials
- Employee has at least one upcoming shift scheduled
- Reminder service is operational and accessible
- Employee has a valid email address and/or phone number registered in their profile
- Web interface is accessible and functional

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the login page of the web interface | Login page is displayed with username and password fields |
| 2 | Enter valid employee credentials (username and password) and click the login button | User is successfully authenticated and redirected to the dashboard or home page |
| 3 | Locate and click on the profile or settings menu option | Profile or settings menu expands showing available options |
| 4 | Navigate to the reminder settings or notification preferences section | Reminder settings page is displayed showing available reminder options and current preferences |
| 5 | Review the available reminder options including delivery method (email/SMS), timing preferences, and shift details inclusion | All reminder configuration options are visible and accessible |
| 6 | Select preferred reminder delivery method (email or SMS or both) | Selected delivery method is highlighted or checked |
| 7 | Set the reminder timing preference (e.g., 24 hours before shift, 2 hours before shift) | Timing preference is selected and displayed correctly |
| 8 | Enable the option to include shift details in reminders | Shift details inclusion option is checked or enabled |
| 9 | Click the Save or Subscribe button to confirm reminder preferences | System processes the request and displays a confirmation message indicating reminder settings have been saved successfully |
| 10 | Verify the confirmation message contains details of the saved preferences | Confirmation message displays the selected delivery method, timing, and other preferences accurately |
| 11 | Refresh the reminder settings page or navigate away and return to verify persistence | Previously saved reminder preferences are displayed correctly, confirming they were persisted in the system |

**Postconditions:**
- Employee reminder preferences are saved in the database
- Employee is subscribed to the reminder service
- System is configured to send reminders based on the saved preferences
- API endpoint POST /api/reminders/subscribe has been successfully called
- Employee will receive reminders for upcoming shifts according to their preferences

---

