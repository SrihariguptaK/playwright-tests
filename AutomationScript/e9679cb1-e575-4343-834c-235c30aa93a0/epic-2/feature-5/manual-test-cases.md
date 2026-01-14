# Manual Test Cases

## Story: As Scheduler, I want to receive real-time UI notifications for scheduling conflicts to act promptly
**Story ID:** story-13

### Test Case: Verify UI notification displays within 5 seconds when scheduling conflict is detected
- **ID:** tc-13-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Scheduler is logged into the system
- Scheduler has valid permissions to create/update appointments
- At least one appointment exists in the system
- System time is synchronized

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the appointment scheduling page | Scheduling page loads successfully with calendar view |
| 2 | Note the current system time | Current time is recorded for notification timing verification |
| 3 | Create a new appointment that overlaps with an existing appointment (same resource, overlapping time slot) | Appointment creation form accepts the conflicting data |
| 4 | Click 'Save' or 'Submit' button to save the appointment | System processes the appointment and detects the conflict |
| 5 | Observe the UI and note the time when notification appears | A conflict notification appears in the UI within 5 seconds showing conflict details including affected appointments, resources, and time slots |
| 6 | Review the notification content | Notification displays detailed information: conflict type, affected appointment IDs, resource names, conflicting time ranges, and conflict description |

**Postconditions:**
- Conflict notification is visible in the UI
- Conflicting appointments are highlighted in the schedule
- Notification remains visible until acknowledged
- System logs the conflict detection and notification event

---

### Test Case: Verify multiple simultaneous conflict notifications display without UI degradation
- **ID:** tc-13-002
- **Type:** edge-case
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Scheduler is logged into the system
- Multiple appointments exist in the system
- System has capacity to detect multiple conflicts simultaneously

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the bulk appointment import or batch scheduling feature | Bulk scheduling interface loads successfully |
| 2 | Create or import 5-10 appointments simultaneously that each create different conflicts (resource conflicts, room conflicts, time conflicts) | System accepts the batch of appointments for processing |
| 3 | Submit all appointments at once | System processes all appointments and detects multiple conflicts |
| 4 | Observe the UI notification area | Multiple conflict notifications appear within 5 seconds, each displaying distinct conflict information |
| 5 | Verify UI responsiveness by scrolling through notifications and clicking on different UI elements | UI remains responsive with no lag, freezing, or performance degradation. All notifications are readable and accessible |
| 6 | Click on each notification to view detailed conflict information | Each notification opens its respective conflict details without interfering with other notifications |
| 7 | Check the appointment calendar view | All conflicting appointments are highlighted appropriately with visual indicators |

**Postconditions:**
- All conflict notifications are visible and stacked/organized properly
- UI performance is not degraded
- All conflicting appointments remain highlighted
- Notifications remain until individually acknowledged

---

### Test Case: Verify conflict notification remains visible and accessible until acknowledged by user
- **ID:** tc-13-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Scheduler is logged into the system
- At least one appointment exists that can create a conflict

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the appointment scheduling page | Scheduling page loads successfully |
| 2 | Create an appointment that conflicts with an existing appointment | Conflict is detected and notification appears within 5 seconds |
| 3 | Wait 30 seconds without interacting with the notification | Notification remains visible on screen without auto-dismissing |
| 4 | Navigate to a different page within the application (e.g., dashboard, reports) | Notification indicator remains visible (e.g., notification badge, alert icon) |
| 5 | Return to the scheduling page | Original conflict notification is still visible and accessible |
| 6 | Click the 'Acknowledge' or 'Dismiss' button on the notification | Notification is dismissed and removed from the UI |
| 7 | Refresh the page | Acknowledged notification does not reappear |

**Postconditions:**
- Notification is marked as acknowledged in the system
- Notification is removed from active notifications list
- Conflict data remains accessible in conflict history/logs

---

### Test Case: Verify notification provides quick access to detailed conflict information and affected appointments
- **ID:** tc-13-004
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 9 mins

**Preconditions:**
- Scheduler is logged into the system
- Two appointments exist with the same resource assignment at overlapping times

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Create a third appointment that conflicts with the existing appointments (resource conflict) | System detects the conflict and displays notification within 5 seconds |
| 2 | Review the notification summary information | Notification displays: conflict type, number of affected appointments, primary resource involved, and time range |
| 3 | Click on 'View Details' or the notification body to expand | Detailed conflict view opens showing complete information for all affected appointments including appointment IDs, patient/client names, resources, rooms, times, and specific conflict descriptions |
| 4 | Click on one of the affected appointment links within the notification | System navigates directly to the appointment details page or opens the appointment in edit mode |
| 5 | Return to the notification and verify all conflicting appointments are highlighted in the calendar view | All appointments involved in the conflict are visually highlighted with a distinct color or border in the calendar |
| 6 | Check if notification categorizes conflict type (resource, room, equipment, time) | Conflict type is clearly labeled and color-coded in the notification |

**Postconditions:**
- Conflict details are accessible
- Affected appointments remain highlighted
- Navigation to conflict resolution is seamless

---

### Test Case: Verify notification behavior when network connection is temporarily lost during conflict detection
- **ID:** tc-13-005
- **Type:** error-case
- **Priority:** Medium
- **Estimated Time:** 12 mins

**Preconditions:**
- Scheduler is logged into the system
- Browser developer tools are available to simulate network conditions
- At least one appointment exists in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open browser developer tools and navigate to Network tab | Network monitoring tools are active |
| 2 | Navigate to the appointment scheduling page | Scheduling page loads successfully |
| 3 | Begin creating a conflicting appointment but do not save yet | Appointment form is filled with conflicting data |
| 4 | Simulate network disconnection using browser tools (set to 'Offline' mode) | Network connection is blocked |
| 5 | Click 'Save' button to submit the appointment | System attempts to save but fails due to network issue. Error message appears indicating connection problem |
| 6 | Re-enable network connection (set to 'Online' mode) | Network connection is restored |
| 7 | Click 'Save' button again or observe if system auto-retries | System successfully processes the appointment, detects conflict, and displays notification within 5 seconds of successful connection |
| 8 | Verify notification content is complete and accurate | Notification displays all required conflict information without data loss |

**Postconditions:**
- Conflict notification appears after connection restoration
- No data corruption or incomplete notifications
- System logs the connection issue and recovery

---

## Story: As Scheduler, I want to receive email alerts for scheduling conflicts to stay informed when away from the system
**Story ID:** story-14

### Test Case: Verify email alert is sent within 5 seconds when scheduling conflict is detected
- **ID:** tc-14-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Scheduler account has a valid email address configured
- Email alert preferences are enabled in scheduler profile
- SMTP service is operational
- At least one appointment exists in the system
- Test email inbox is accessible for verification

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into the scheduling system and verify scheduler email address in profile settings | Profile shows valid email address: scheduler@example.com |
| 2 | Note the current system time with seconds precision | Current time is recorded (e.g., 10:30:15 AM) |
| 3 | Create a new appointment that conflicts with an existing appointment (same resource, overlapping time) | Appointment is saved and conflict is detected by the system |
| 4 | Immediately check the test email inbox and note the email receipt timestamp | Email alert arrives within 5 seconds of conflict detection (by 10:30:20 AM) |
| 5 | Open the email and verify the subject line | Email subject clearly indicates scheduling conflict (e.g., 'Scheduling Conflict Alert - [Date/Time]') |
| 6 | Review email body content for required information | Email contains: appointment times, resource names, patient/client information, conflict description, conflicting appointment IDs, and link to resolve conflict |
| 7 | Verify email formatting and readability | Email is properly formatted with clear sections, readable fonts, and no broken HTML elements |

**Postconditions:**
- Email alert is successfully delivered
- Email delivery is logged in the system
- Email contains accurate conflict information
- Scheduler can take action from email information

---

### Test Case: Verify email includes comprehensive conflict details with appointment times, resources, and descriptions
- **ID:** tc-14-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Scheduler account has valid email configured
- Email alerts are enabled
- Multiple appointments exist with detailed information (patients, resources, rooms, equipment)

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Create a complex scheduling conflict involving multiple resources (e.g., doctor, room, and equipment all conflicting) | System detects multi-resource conflict |
| 2 | Wait for and retrieve the email alert from inbox | Email arrives within 5 seconds |
| 3 | Verify email contains appointment times section | Email displays: Original appointment time (e.g., 2:00 PM - 3:00 PM), Conflicting appointment time (e.g., 2:30 PM - 3:30 PM), and overlap period highlighted |
| 4 | Verify email contains resource information section | Email lists all conflicting resources: Resource type (Doctor, Room, Equipment), Resource name/ID, and availability status |
| 5 | Verify email contains conflict description section | Email provides: Clear description of conflict type, Severity level if applicable, and recommended actions or resolution options |
| 6 | Verify email contains appointment details | Email shows: Appointment IDs, Patient/client names (if permitted by privacy settings), Service types, and duration of each appointment |
| 7 | Check for actionable links in the email | Email contains clickable links to: View full conflict details, Access scheduler system, and resolve conflict directly |

**Postconditions:**
- All required conflict information is present in email
- Email provides sufficient detail for scheduler to take action
- Links in email are functional

---

### Test Case: Verify scheduler can configure email alert preferences in profile settings
- **ID:** tc-14-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Scheduler is logged into the system
- Scheduler has access to profile/settings page
- Test email addresses are available for verification

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to profile settings or preferences page | Settings page loads showing Email Alert Preferences section |
| 2 | Locate email alert configuration options | Page displays options including: Enable/disable email alerts toggle, Email address field, Conflict types to alert for (checkboxes), and Alert frequency preferences |
| 3 | Update email address to a new test email address | Email field accepts valid email format and saves successfully |
| 4 | Configure conflict type preferences by selecting specific types (e.g., only resource conflicts, not room conflicts) | Checkboxes for conflict types can be selected/deselected and preferences are saved |
| 5 | Set alert frequency preference (e.g., immediate, batched hourly, daily summary) | Frequency option is saved successfully |
| 6 | Click 'Save' or 'Update Preferences' button | System displays success message: 'Email preferences updated successfully' |
| 7 | Create a conflict matching the selected preferences | Email is sent to the new email address according to configured preferences |
| 8 | Create a conflict NOT matching the selected preferences (e.g., room conflict when only resource conflicts are enabled) | No email is sent for the filtered conflict type |
| 9 | Disable email alerts completely using the toggle | Toggle switches to 'Off' and setting is saved |
| 10 | Create another conflict | No email alert is sent when alerts are disabled |

**Postconditions:**
- Email preferences are saved in scheduler profile
- System respects configured preferences for future conflicts
- Changes take effect immediately

---

### Test Case: Verify system logs email delivery status and errors for failed deliveries
- **ID:** tc-14-004
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- Scheduler has admin or appropriate access to view email delivery logs
- System has logging functionality enabled
- Test email address can be set to invalid format

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to system logs or email delivery status page | Logs page loads showing email delivery records |
| 2 | Update scheduler profile with an invalid email address (e.g., 'invalid.email@') | System either validates and rejects invalid format, or accepts it for testing error handling |
| 3 | Create a scheduling conflict to trigger email alert | System attempts to send email to invalid address |
| 4 | Navigate back to email delivery logs within 1 minute | Log entry appears showing the email attempt |
| 5 | Review log entry details | Log contains: Timestamp of send attempt, Recipient email address, Conflict ID or reference, Delivery status: 'Failed', Error code and description (e.g., 'Invalid email format' or 'Delivery bounced'), and Retry attempt count |
| 6 | Update scheduler profile with valid email address | Email address is updated successfully |
| 7 | Create another conflict to trigger successful email | Email is sent successfully |
| 8 | Check logs for successful delivery | Log entry shows: Timestamp, Recipient, Conflict ID, Delivery status: 'Delivered' or 'Success', and SMTP response code |
| 9 | Test with non-existent domain email (e.g., 'test@nonexistentdomain12345.com') | System logs delivery failure with appropriate error message about domain not found |
| 10 | Verify logs are searchable and filterable by status, date, and recipient | Log interface provides search and filter functionality showing only relevant results |

**Postconditions:**
- All email delivery attempts are logged
- Errors are captured with detailed information
- Logs are accessible for troubleshooting
- System maintains audit trail of email communications

---

### Test Case: Verify email delivery with 98% success rate under normal operating conditions
- **ID:** tc-14-005
- **Type:** boundary
- **Priority:** Medium
- **Estimated Time:** 20 mins

**Preconditions:**
- Test environment has 50+ scheduler accounts with valid email addresses
- SMTP service is operational
- System can generate multiple conflicts simultaneously
- Email delivery logs are accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Prepare 100 valid scheduler email addresses in the system | 100 scheduler profiles exist with verified email addresses |
| 2 | Create a script or process to generate 100 different scheduling conflicts, each assigned to a different scheduler | System triggers 100 conflict detection events simultaneously or in rapid succession |
| 3 | Wait 1 minute for all email delivery attempts to complete | All emails have been processed by the system |
| 4 | Check email delivery logs and count successful deliveries | Logs show delivery status for all 100 email attempts |
| 5 | Calculate success rate: (Successful deliveries / Total attempts) * 100 | Success rate is 98% or higher (98-100 out of 100 emails delivered) |
| 6 | Review any failed deliveries for root cause | Failed deliveries have legitimate reasons logged (temporary server issues, invalid addresses, etc.) |
| 7 | Verify all successful emails arrived within 5 seconds by checking timestamps | At least 95% of successfully delivered emails have timestamps within 5 seconds of conflict detection |
| 8 | Spot check 10 random received emails for content accuracy | All checked emails contain correct and complete conflict information |

**Postconditions:**
- Email delivery success rate meets or exceeds 98% threshold
- System performance is acceptable under high email volume
- All delivered emails meet quality standards
- Logs provide visibility into delivery metrics

---

