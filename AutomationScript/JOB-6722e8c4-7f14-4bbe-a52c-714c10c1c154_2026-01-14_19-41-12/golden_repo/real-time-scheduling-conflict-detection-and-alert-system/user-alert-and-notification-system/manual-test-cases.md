# Manual Test Cases

## Story: As Scheduler, I want to receive email notifications for detected scheduling conflicts to ensure timely awareness
**Story ID:** story-13

### Test Case: Validate email notification sent upon conflict detection
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User account exists with valid email address registered
- User has email notifications enabled in preferences
- Email server is configured and operational
- System conflict detection service is running
- Test email inbox is accessible for verification

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into the scheduling system with scheduler credentials | User successfully logged in and dashboard is displayed |
| 2 | Create a new scheduling entry that conflicts with an existing schedule (e.g., same resource, overlapping time) | Scheduling conflict is detected by the system and conflict alert is displayed in UI |
| 3 | Note the exact timestamp when the conflict was triggered | Timestamp recorded for delivery time verification |
| 4 | Check the recipient's email inbox within 5 seconds of conflict detection | Email notification is received with subject line indicating scheduling conflict |
| 5 | Open the email and verify it contains conflict details including conflicting schedules, resources, time slots, and affected parties | Email displays complete conflict information with clear formatting |
| 6 | Verify the email includes resolution guidance or instructions on how to resolve the conflict | Email contains actionable resolution steps or links to conflict resolution interface |
| 7 | Access the system's email delivery logs via admin panel or API endpoint GET /notifications/email/logs | Email delivery log entry is created with status 'Sent' and timestamp |
| 8 | Verify the delivery timestamp is within 5 seconds of conflict detection timestamp | Email delivery time meets the 5-second performance requirement |
| 9 | Check the email read receipt status in the system logs (if email client supports read receipts) | Read status is logged correctly showing 'Read' or 'Pending' status |

**Postconditions:**
- Email notification successfully delivered to recipient
- Email delivery and read status logged in system
- Conflict remains active in system until resolved
- Email remains in recipient inbox for future reference

---

### Test Case: Verify user notification preference settings
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User account exists with valid credentials
- User has access to notification preference settings
- Email notifications are currently enabled by default
- System notification service is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into the scheduling system with scheduler credentials | User successfully authenticated and main dashboard displayed |
| 2 | Navigate to user settings or preferences section | Settings page loads displaying notification preferences options |
| 3 | Locate the email notification toggle or checkbox for conflict notifications | Email notification option is visible and currently enabled (checked) |
| 4 | Disable email notifications by unchecking the option or toggling it off | Toggle switches to disabled state and visual indicator shows notifications are off |
| 5 | Click 'Save' or 'Update Preferences' button | Success message displayed confirming 'Preferences saved successfully' |
| 6 | Verify the preference change is persisted by refreshing the page or logging out and back in | Email notification setting remains disabled after page refresh |
| 7 | Trigger a scheduling conflict by creating overlapping schedule entries | Conflict is detected and displayed in UI, but no email notification is generated |
| 8 | Check the user's email inbox for any conflict notification emails | No email notification received in inbox |
| 9 | Verify system logs to confirm no email was sent to the user | Email logs show no delivery attempt for this user's conflict notification |
| 10 | Return to notification preferences and re-enable email notifications | Email notification toggle switches to enabled state |
| 11 | Save the updated preferences | Success message confirms preferences saved |
| 12 | Trigger another scheduling conflict | Conflict detected by system |
| 13 | Check email inbox within 5 seconds | Email notification is received confirming notifications have resumed |

**Postconditions:**
- Email notifications are re-enabled for the user
- User preferences are correctly stored in database
- System respects user notification preferences for future conflicts

---

### Test Case: Test email format and content correctness
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 15 mins

**Preconditions:**
- User account with valid email address exists
- Email notifications are enabled
- Multiple test devices available (desktop, mobile, tablet)
- Email client applications are configured on test devices
- System has sample conflict data ready for testing

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into the scheduling system and trigger a scheduling conflict with known details (specific resources, times, and parties) | Conflict is detected and email notification is triggered |
| 2 | Open the conflict notification email in desktop email client | Email opens successfully and displays properly formatted content |
| 3 | Verify email subject line clearly indicates a scheduling conflict | Subject line contains keywords like 'Scheduling Conflict Alert' or similar clear identifier |
| 4 | Check email body for conflict details including date, time, resource name, and conflicting parties | All conflict details match the actual conflict data and are accurately displayed |
| 5 | Verify the email contains resolution instructions or guidance section | Clear, actionable resolution steps are provided with appropriate formatting |
| 6 | Check for contact information (support email, phone number, or help desk link) | Contact information is present and clearly visible |
| 7 | Verify email branding, logo, and professional formatting | Email follows company branding guidelines with proper logo and color scheme |
| 8 | Open the same email on a mobile device (smartphone) | Email renders correctly with responsive design, text is readable without zooming |
| 9 | Open the same email on a tablet device | Email displays properly with appropriate layout for tablet screen size |
| 10 | Test all hyperlinks in the email by clicking each link | All links are functional and navigate to correct destinations (conflict resolution page, help documentation, etc.) |
| 11 | Verify any 'View Conflict' or 'Resolve Now' buttons redirect to the correct system page with conflict details pre-loaded | Buttons work correctly and deep-link to specific conflict in the system |
| 12 | Check contact email addresses and phone numbers for accuracy | All contact information is correct and matches official company contact details |
| 13 | Verify email footer contains unsubscribe or preference management link | Footer includes proper unsubscribe/preference link as per email best practices |
| 14 | Test email in different email clients (Gmail, Outlook, Apple Mail) | Email displays consistently across different email platforms without formatting issues |

**Postconditions:**
- Email format validated across multiple devices and clients
- All links and contact information confirmed functional
- Email content accuracy verified against actual conflict data

---

## Story: As Scheduler, I want to receive SMS notifications for critical scheduling conflicts to ensure immediate awareness
**Story ID:** story-14

### Test Case: Validate SMS notification sent for critical conflicts
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User account exists with valid mobile phone number registered
- User has opted-in to SMS notifications
- SMS gateway service is configured and operational
- User has sufficient SMS quota or credits
- Test mobile device is available and powered on
- System can identify and classify critical conflicts

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into the scheduling system with scheduler credentials | User successfully authenticated and dashboard is displayed |
| 2 | Create or trigger a critical scheduling conflict (e.g., conflict involving high-priority resources or urgent time slots) | System detects and classifies the conflict as 'Critical' with appropriate severity level |
| 3 | Note the exact timestamp when the critical conflict was triggered | Timestamp recorded for SMS delivery time verification |
| 4 | Verify the conflict is marked as critical in the system UI | Conflict displays with 'Critical' label or high-priority indicator |
| 5 | Check the registered mobile device for incoming SMS within 10 seconds of conflict detection | SMS notification is received on the mobile device |
| 6 | Open and read the SMS message | SMS contains concise conflict summary including conflict type, affected resource, and time |
| 7 | Verify SMS includes contact information or action instructions | SMS displays support contact number or short URL for immediate action |
| 8 | Access the system's SMS delivery logs via admin panel or API endpoint GET /notifications/sms/logs | SMS delivery log entry exists with status 'Delivered' and timestamp |
| 9 | Calculate the time difference between conflict detection and SMS delivery | SMS delivery time is within 10 seconds of conflict detection timestamp |
| 10 | Verify the SMS delivery status shows successful delivery confirmation from SMS gateway | Delivery status is 'Delivered' with gateway confirmation code |

**Postconditions:**
- SMS notification successfully delivered to recipient
- SMS delivery status logged in system with timestamp
- Critical conflict remains active until resolved
- SMS delivery metrics updated for reporting

---

### Test Case: Verify SMS opt-in and opt-out functionality
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- User account exists with valid phone number
- User currently has SMS notifications enabled (opted-in)
- SMS notification settings are accessible in user preferences
- System supports opt-in/opt-out functionality

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into the scheduling system with scheduler credentials | User successfully logged in and main interface displayed |
| 2 | Navigate to user settings or notification preferences section | Settings page loads showing SMS notification options |
| 3 | Locate the SMS notification opt-in/opt-out toggle or checkbox | SMS notification control is visible and currently shows opted-in status |
| 4 | Disable SMS notifications by toggling off or unchecking the SMS notification option | Toggle switches to disabled/opted-out state with visual confirmation |
| 5 | Click 'Save' or 'Update Preferences' button | Success message displayed: 'SMS notification preferences saved successfully' |
| 6 | Verify the opt-out preference persists by refreshing the page | SMS notification setting remains disabled after page refresh |
| 7 | Check database or API to confirm opt-out status is stored correctly | User's SMS opt-in status shows 'false' or 'opted-out' in system records |
| 8 | Trigger a critical scheduling conflict | Critical conflict is detected and displayed in system UI |
| 9 | Wait 15 seconds and check mobile device for any SMS notifications | No SMS notification is received on the mobile device |
| 10 | Verify SMS delivery logs to confirm no SMS was sent | SMS logs show no delivery attempt for this user due to opt-out status |
| 11 | Return to notification preferences and re-enable SMS notifications by toggling on | SMS notification toggle switches to enabled/opted-in state |
| 12 | Save the updated preferences | Success message confirms 'SMS notifications enabled successfully' |
| 13 | Verify opt-in status is updated in system records | User's SMS opt-in status shows 'true' or 'opted-in' in database |
| 14 | Trigger another critical scheduling conflict | Critical conflict detected by system |
| 15 | Check mobile device within 10 seconds for SMS notification | SMS notification is received confirming SMS notifications have resumed |

**Postconditions:**
- SMS notifications are re-enabled for the user
- User opt-in status correctly stored and enforced
- System respects user SMS preferences for all future critical conflicts

---

### Test Case: Test SMS message content and formatting
- **ID:** tc-006
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 13 mins

**Preconditions:**
- User account with valid phone number and SMS opt-in status
- Multiple mobile devices available for testing (different carriers and models)
- SMS notifications are enabled
- Critical conflict scenario is prepared with known details

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into the scheduling system and trigger a critical conflict with specific known details | Critical conflict is detected and SMS notification process initiated |
| 2 | Receive and open the SMS notification on primary test device | SMS is received and displays in device's messaging app |
| 3 | Verify SMS sender ID or phone number is recognizable and legitimate | Sender shows company name or official SMS short code |
| 4 | Check SMS message length to ensure it fits within standard SMS character limits (160 characters for single SMS) | Message is concise and does not exceed character limit or is properly segmented if longer |
| 5 | Verify SMS contains accurate conflict summary including conflict type or severity | SMS clearly states 'CRITICAL CONFLICT' or similar urgent indicator |
| 6 | Check that SMS includes essential conflict details: resource name, date, and time | All critical conflict details are present and match actual conflict data |
| 7 | Verify SMS includes contact information (phone number or support contact) | Valid contact phone number or support identifier is included |
| 8 | Check for any shortened URLs or links in the SMS | If URL is present, it is properly formatted and uses secure short URL service |
| 9 | Click or tap any links included in the SMS | Links open correctly and direct to appropriate conflict resolution page or system login |
| 10 | Test SMS display on different mobile devices (iOS, Android, different carriers) | SMS displays correctly on all tested devices without character encoding issues |
| 11 | Verify special characters, dates, and times are formatted correctly across devices | No garbled text, proper date/time format, special characters display correctly |
| 12 | Check for any broken links or incorrect phone numbers by attempting to use them | All phone numbers are dialable and links are functional without errors |
| 13 | Verify SMS does not contain any formatting issues like extra spaces, line breaks, or truncated text | Message is cleanly formatted with proper spacing and complete text |
| 14 | Test SMS readability and clarity by having multiple users review the message | Message is clear, professional, and conveys urgency appropriately |

**Postconditions:**
- SMS content validated for accuracy and completeness
- SMS formatting confirmed across multiple devices and carriers
- All links and contact information verified as functional

---

