# Manual Test Cases

## Story: As Scheduler, I want to receive in-app alerts for scheduling conflicts to act promptly
**Story ID:** story-3

### Test Case: Receive in-app alert on conflict detection
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as a Scheduler
- User has active session in the application
- Conflict detection engine is operational
- User has appropriate permissions to view scheduling conflicts
- At least two overlapping schedule entries exist in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Create or modify a schedule entry that conflicts with an existing entry (e.g., assign same resource to two different tasks at overlapping times) | System detects the scheduling conflict automatically |
| 2 | Observe the in-app notification area within 1 second of conflict creation | In-app alert is generated and displayed prominently to the user with visual indicator (badge, popup, or notification banner) |
| 3 | Click on the alert notification to view details | Alert expands or opens to show detailed conflict information including: conflicting resources, time slots, affected schedules, and conflict type |
| 4 | Review all conflict details displayed in the alert | All relevant information is clearly visible and formatted, including resource names, dates, times, and conflict description |
| 5 | Click the 'Acknowledge' or 'Dismiss' button on the alert | Alert is marked as acknowledged in the system and removed from the active notifications list |
| 6 | Check the notification history or dismissed alerts section | Acknowledged alert appears in the history with timestamp and acknowledgment status |

**Postconditions:**
- Alert is removed from active notifications
- Alert acknowledgment is recorded in the system
- User can access alert history if needed
- Conflict remains in the system until resolved
- Alert status is updated to 'Acknowledged'

---

### Test Case: Alert delivery performance test
- **ID:** tc-002
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in as a Scheduler
- User has active session in the application
- Conflict detection engine is operational
- System performance monitoring tools are available
- Multiple schedule entries are available for conflict creation
- Network connection is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Prepare test data with 5-10 schedule entries that will create simultaneous conflicts | Test data is ready for conflict generation |
| 2 | Start performance monitoring timer or use browser developer tools to track network timing | Performance monitoring is active and recording timestamps |
| 3 | Trigger multiple conflicts simultaneously by batch updating or creating overlapping schedule entries at the same time | System processes all conflict detections concurrently |
| 4 | Observe and record the time taken for each alert to appear in the in-app notification area | All alerts are generated and displayed to the user |
| 5 | Verify the timestamp difference between conflict creation and alert display for each alert | Each alert delivery latency is under 1 second from the moment of conflict detection |
| 6 | Count the total number of alerts displayed and compare with the number of conflicts created | 100% of conflicts generated corresponding in-app alerts (all alerts accounted for) |
| 7 | Review system logs or monitoring dashboard for alert generation metrics | System logs confirm all alerts were generated within the 1-second performance threshold |

**Postconditions:**
- All generated alerts are visible in the notification area
- Performance metrics are recorded and meet the 1-second threshold
- System remains stable after simultaneous alert generation
- No alerts are lost or delayed beyond acceptable limits
- Test conflicts can be cleaned up or resolved

---

## Story: As Scheduler, I want to receive email notifications for scheduling conflicts to stay informed when away
**Story ID:** story-4

### Test Case: Receive email notification on conflict detection
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User account is configured with a valid email address
- Email notification preferences are enabled for the user
- SMTP or email service is properly configured and operational
- Conflict detection engine is operational
- User has appropriate permissions to receive conflict notifications
- Test email inbox is accessible for verification

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Create or modify a schedule entry that creates a scheduling conflict (e.g., double-booking a resource or overlapping time slots) | System detects the scheduling conflict automatically through the conflict detection engine |
| 2 | Wait and monitor for email notification generation (should occur within 5 seconds) | Email notification is generated by the system and sent to the configured email address |
| 3 | Check the user's email inbox for the conflict notification email | User receives the email notification in their inbox within 5 seconds of conflict detection |
| 4 | Open and review the email content | Email contains detailed conflict information including: subject line indicating conflict, conflicting resource names, date and time of conflict, affected schedules, conflict type, and clear description of the issue |
| 5 | Review suggested actions or links provided in the email | Email includes suggested actions such as links to resolve conflict, view schedule details, or contact relevant parties |
| 6 | Click on any action links provided in the email (e.g., 'View Conflict' or 'Resolve Now') | Links direct user to the appropriate section of the application where they can take action to resolve the conflict |
| 7 | Verify email formatting and readability across different email clients if possible | Email is properly formatted, professional, and readable with all information clearly presented |

**Postconditions:**
- Email notification is successfully delivered to user's inbox
- Email delivery status is tracked in the system
- User is informed about the conflict and can take appropriate action
- Email remains in inbox for future reference
- System logs record successful email delivery

---

### Test Case: Email delivery performance test
- **ID:** tc-004
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User account is configured with a valid email address
- Email notification preferences are enabled
- SMTP or email service is properly configured and operational
- Conflict detection engine is operational
- Email delivery tracking system is enabled
- System performance monitoring tools are available
- Network connection is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Prepare test environment and note the current timestamp | Test environment is ready and baseline timestamp is recorded |
| 2 | Start performance monitoring to track email delivery timing | Performance monitoring is active and ready to capture metrics |
| 3 | Trigger a scheduling conflict by creating or modifying a schedule entry that conflicts with an existing entry | System detects the conflict and initiates email notification process |
| 4 | Record the exact timestamp when the conflict was created/detected | Conflict detection timestamp is captured for performance calculation |
| 5 | Monitor the email service logs or system logs for email send confirmation | System logs show email was queued and sent to the email service provider |
| 6 | Check the email inbox and record the timestamp when the email is received | Email appears in the inbox and receipt timestamp is captured |
| 7 | Calculate the time difference between conflict detection and email receipt | Email delivery time is within 5 seconds of conflict detection as per performance requirement |
| 8 | Review system logs and email delivery tracking dashboard for delivery status | System confirms successful delivery with status 'Delivered' and timestamp within 5-second threshold |
| 9 | Verify no email bounces or delivery failures occurred | Email delivery status shows successful delivery with no bounce or error messages |

**Postconditions:**
- Email is successfully delivered within 5 seconds
- Email delivery metrics are recorded in the system
- Performance requirement is validated and met
- Email delivery status is tracked and shows 'Delivered'
- No bounces or delivery failures are recorded
- System remains stable after email delivery

---

## Story: As Scheduler, I want to view detailed conflict information to understand and resolve scheduling issues
**Story ID:** story-5

### Test Case: View detailed conflict information
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as a Scheduler with valid credentials
- At least one scheduling conflict exists in the system
- User has appropriate access permissions to view conflict data
- Conflict detection engine has identified and flagged conflicts
- Network connection is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | User receives a conflict alert notification and clicks on it to open conflict details | Conflict details view opens and loads completely within 2 seconds, displaying a loading indicator during the fetch process |
| 2 | User reviews the displayed conflict information including event names, dates, times, and descriptions | All conflicting event details are displayed clearly with proper formatting, including event titles, scheduled times, and event descriptions |
| 3 | User reviews the resource allocation information shown in the conflict details | All conflicting resources are listed with their current assignments, availability status, and resource types clearly visible |
| 4 | User reviews the participant information for all conflicting events | Complete list of participants involved in the conflict is displayed with their names, roles, and availability status |
| 5 | User examines the suggested resolution options provided by the system | System displays multiple resolution suggestions such as time adjustments, resource alternatives, or participant reassignments with clear descriptions |
| 6 | User clicks on the navigation link to view the first conflicting event | User is redirected to the event scheduling page for the selected conflicting event, with all event details loaded and editable |
| 7 | User navigates back to conflict details and clicks on the second conflicting event link | User is taken to the event scheduling page for the second conflicting event, maintaining context of the conflict resolution workflow |

**Postconditions:**
- User has viewed complete conflict information
- User is positioned on the event scheduling page of the last viewed conflicting event
- Conflict remains in unresolved state until user takes action
- Navigation history includes conflict details view and visited event pages
- System logs the conflict view activity for audit purposes

---

