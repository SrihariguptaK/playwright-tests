# Manual Test Cases

## Story: As Performance Manager, I want to set up review cycles to achieve timely evaluations of performance metrics
**Story ID:** story-32

### Test Case: Validate successful setup of review cycles
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- User is logged in as Performance Manager
- User has valid authentication credentials
- Review cycle management feature is enabled
- Database is accessible and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the review cycle management page | Review cycle management interface is displayed with options to configure review cycles including frequency selection dropdown, save button, and any existing review cycles listed |
| 2 | Select a frequency for review cycles from the dropdown (daily, weekly, or monthly) | Selected frequency is displayed in the frequency field and highlighted as the current selection |
| 3 | Click on the save button | Review cycle is saved successfully, confirmation message is displayed, and the new review cycle appears in the list of configured cycles |

**Postconditions:**
- Review cycle is stored in the database
- Review cycle appears in the user's configured cycles list
- System is ready to send reminders based on the configured frequency
- User remains on the review cycle management page

---

### Test Case: Ensure reminders are sent for upcoming review cycles
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in as Performance Manager
- User has valid authentication credentials
- Review cycle management feature is enabled
- Notification system is operational
- User has notification permissions enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Set up a review cycle with a defined frequency (e.g., daily or weekly) | Review cycle is saved successfully and confirmation message is displayed |
| 2 | Wait for the reminder time based on the configured frequency | Reminder notification is sent to the user at the appropriate time before the scheduled review cycle |
| 3 | Check notification for review cycle in the notification center or inbox | Notification contains correct review cycle details including frequency, scheduled date/time, and relevant performance metrics to be reviewed |

**Postconditions:**
- Reminder notification has been delivered successfully
- Notification is logged in the system
- Review cycle status remains active
- User is informed of the upcoming review

---

### Test Case: Verify error handling for incomplete review cycle setup
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in as Performance Manager
- User has valid authentication credentials
- Review cycle management feature is enabled
- Database is accessible and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the review cycle management page | Review cycle management interface is displayed with frequency selection dropdown and save button visible |
| 2 | Attempt to save a review cycle without selecting frequency by clicking the save button with frequency field empty | Error message is displayed for missing frequency, indicating that frequency selection is required. The review cycle is not saved and the frequency field is highlighted or marked as required |
| 3 | Select frequency from the dropdown (daily, weekly, or monthly) and click save button | Review cycle is saved successfully, confirmation message is displayed, error message is cleared, and the new review cycle appears in the configured cycles list |

**Postconditions:**
- Review cycle is stored in the database after correction
- No incomplete review cycles exist in the system
- User receives appropriate feedback for both error and success states
- System maintains data integrity

---

