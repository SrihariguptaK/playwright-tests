# Manual Test Cases

## Story: As System Administrator, I want to perform management of user roles for approval workflows to achieve secure and appropriate access control
**Story ID:** story-9

### Test Case: Validate assignment of user roles
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- System Administrator is logged into the system with Admin role privileges
- User role management interface is accessible
- At least one user account exists in the system without 'Approver' role
- UserRoles table is accessible and operational
- Audit logging system is enabled and functioning

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | System Administrator navigates to and accesses the user role management interface | User role management interface loads successfully and displays current user roles in a table or list format with columns showing username, current roles, and last modified date |
| 2 | System Administrator selects a user from the list and assigns 'Approver' role to the selected user, then clicks Save or Submit button | System displays success message confirming role assignment, 'Approver' role appears in the user's role list, and changes are persisted to the UserRoles table |
| 3 | System Administrator navigates to the audit log section and searches for the recent role assignment action | Audit log displays an entry showing the administrator username, timestamp of the change, target user, action performed (role assignment), role assigned ('Approver'), and any relevant metadata |

**Postconditions:**
- User has 'Approver' role assigned in the system
- Role assignment is recorded in the audit log with complete details
- User can now access approval workflow features
- Role change is effective immediately in the system

---

### Test Case: Verify enforcement of role-based access control
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- Two test user accounts exist in the system
- First user does not have 'Approver' role assigned
- Second user has 'Approver' role assigned
- Approval dashboard is configured and accessible
- Role-based access control is enabled in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in as the user without 'Approver' role and attempt to navigate to the approval dashboard URL or click on approval dashboard menu item | System denies access and displays an 'Access Denied' or 'Unauthorized Access' message indicating insufficient permissions, user is redirected to home page or error page |
| 2 | Log out from the first user account, then log in as the user with 'Approver' role assigned and navigate to the approval dashboard | System grants access successfully, approval dashboard loads completely showing pending approval requests, approval actions are available, and all approval features are accessible |

**Postconditions:**
- Role-based access control is confirmed to be functioning correctly
- Users without appropriate roles cannot access restricted features
- Users with appropriate roles have full access to their authorized features
- No unauthorized access has occurred

---

### Test Case: Test revocation of user roles
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- System Administrator is logged into the system with Admin role privileges
- A user account exists with 'Approver' role currently assigned
- User with 'Approver' role has previously accessed approval features successfully
- User role management interface is accessible
- Audit logging system is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | System Administrator accesses user role management interface, selects the user with 'Approver' role, removes or revokes the 'Approver' role, and clicks Save or Submit button | System displays success message confirming role revocation, 'Approver' role is removed from the user's role list, changes are saved to the UserRoles table, and audit log records the revocation with timestamp and administrator details |
| 2 | Log in as the user whose 'Approver' role was revoked and attempt to access approval dashboard or any approval-related features | System denies access to approval features, displays 'Access Denied' message, user cannot view pending approvals, cannot perform approval actions, and is restricted from all approval workflow functionality |

**Postconditions:**
- User no longer has 'Approver' role in the system
- User cannot access any approval-related features
- Role revocation is recorded in the audit log
- Role change is effective immediately
- System maintains data integrity after role revocation

---

## Story: As Schedule Coordinator, I want to perform receiving notifications on schedule change request status updates to achieve timely awareness
**Story ID:** story-10

### Test Case: Validate notification sent on approval
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- Schedule Coordinator has submitted a schedule change request that is in pending status
- An Approver user is logged into the system
- NotificationService is running and operational
- Schedule Coordinator has valid notification settings configured
- System time is synchronized for accurate timestamp verification

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Approver logs in, navigates to approval dashboard, selects the pending schedule change request, adds approval comments, and clicks Approve button | Schedule change request status changes to 'Approved', system triggers notification process via POST /api/notifications endpoint, and notification is queued for delivery to Schedule Coordinator within 1 minute |
| 2 | Schedule Coordinator checks notification inbox or notification center within 1 minute of approval action and opens the received notification | Notification is received within 1 minute SLA, notification clearly displays 'Approved' status, shows the approver's name, includes all approver comments entered during approval, displays request details (date, time, reason), and shows timestamp of approval action |

**Postconditions:**
- Notification is successfully delivered to Schedule Coordinator
- Notification contains complete and accurate information
- Schedule change request status remains 'Approved'
- Notification is logged in notification history
- SLA for notification delivery (1 minute) is met

---

### Test Case: Test notification preference configuration
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 4 mins

**Preconditions:**
- Schedule Coordinator is logged into the system
- Notification preferences interface is accessible
- Default notification preferences are currently active
- At least one notification type is available for configuration

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Schedule Coordinator navigates to notification settings or preferences page, modifies notification preferences (such as enabling/disabling specific notification types, changing frequency, or adjusting delivery methods), and clicks Save or Update button | System displays success message confirming preferences have been saved, updated preferences are reflected in the UI immediately, changes are persisted to the database, and confirmation message shows what was changed |
| 2 | Trigger a notification event that matches the updated preferences (e.g., have an approver approve or reject a schedule change request submitted by this Schedule Coordinator) | Notification is sent according to the newly updated preferences, notification delivery method matches configured preference, notification timing aligns with configured frequency, and notification content follows the preference settings |

**Postconditions:**
- Notification preferences are successfully updated in the system
- Future notifications follow the new preference settings
- Preference changes are persisted across user sessions
- System respects user-configured notification settings

---

### Test Case: Verify notification history accessibility
- **ID:** tc-006
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 3 mins

**Preconditions:**
- Schedule Coordinator is logged into the system
- Schedule Coordinator has received at least 3-5 notifications previously
- Notification history feature is enabled
- Notifications include various types (approval, rejection, cancellation)

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Schedule Coordinator navigates to notification history page or section by clicking on notification history menu item or link | Notification history page loads successfully and displays all past notifications in chronological order (newest first), each notification entry shows notification type, status (read/unread), timestamp, subject/title, sender information, and a preview or full content of the notification message including any approver comments |

**Postconditions:**
- All historical notifications are accessible and viewable
- Notification history displays complete and accurate information
- Schedule Coordinator can review past notification details
- Notification history remains persistent and available for future access

---

## Story: As System Administrator, I want to perform monitoring of approval workflow performance to achieve operational efficiency
**Story ID:** story-12

### Test Case: Validate real-time metrics display
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- User has valid System Administrator credentials
- Monitoring dashboard is deployed and accessible
- Sample approval workflow data exists in ScheduleChangeRequests and ApprovalActions tables
- Dashboard refresh interval is configured to 5 minutes
- At least 10 active schedule change requests exist in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the monitoring dashboard URL | Login page is displayed |
| 2 | Enter valid Administrator credentials and click Login | Administrator is successfully authenticated and redirected to monitoring dashboard |
| 3 | Verify the monitoring dashboard loads completely | Dashboard displays with all metric widgets visible including average approval times, pending requests count, and SLA compliance percentage |
| 4 | Observe the real-time metrics section for current data | Real-time metrics are displayed showing current pending requests, active workflows, and today's approval statistics |
| 5 | Wait for 5 minutes and observe the dashboard | Dashboard automatically refreshes and metrics are updated with latest data |
| 6 | Record the displayed metric values (average approval time, pending requests count, SLA compliance rate) | All metric values are clearly visible and formatted correctly |
| 7 | Query the database directly for ScheduleChangeRequests and ApprovalActions to calculate expected metric values | Sample data values are retrieved successfully from database |
| 8 | Compare dashboard metrics with manually calculated values from database query | Dashboard metrics match the expected values calculated from database with less than 1% variance |
| 9 | Verify timestamp on dashboard shows last update time | Last updated timestamp is displayed and shows current time within 5-minute window |

**Postconditions:**
- Administrator remains logged into the dashboard
- Dashboard continues to refresh every 5 minutes
- No data corruption or system errors occurred
- Audit log records administrator access to monitoring dashboard

---

### Test Case: Test alert generation for SLA breaches
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User has valid System Administrator credentials and is logged into monitoring dashboard
- SLA threshold is configured (e.g., approval must complete within 24 hours)
- Alert notification system is enabled and configured
- Test environment allows simulation of time-based scenarios
- No existing SLA breach alerts are active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Create a new schedule change request in the system | Schedule change request is created successfully with timestamp recorded |
| 2 | Note the current time and the SLA deadline for the created request | SLA deadline is calculated correctly (e.g., 24 hours from creation time) |
| 3 | Simulate the passage of time to exceed the SLA threshold without approval action (or modify request timestamp in database to simulate SLA breach) | Request timestamp indicates SLA threshold has been exceeded |
| 4 | Wait for up to 5 minutes and monitor the dashboard alerts section | SLA breach alert is generated and displayed on the monitoring dashboard within 5 minutes |
| 5 | Verify the alert contains request ID, breach time, and severity level | Alert displays complete information including request ID, time exceeded, and marked as high severity |
| 6 | Check if alert notification was sent via configured channels (email, system notification) | Alert notification is sent to administrator through configured notification channels |
| 7 | Verify the alert timestamp matches the actual breach detection time | Alert timestamp is within 5 minutes of the actual SLA breach occurrence |
| 8 | Click on the alert to view detailed information | Detailed view opens showing full request details, approval history, and time elapsed |

**Postconditions:**
- SLA breach alert remains visible on dashboard until acknowledged or resolved
- Alert is logged in system audit trail
- Request remains in pending state awaiting approval
- SLA compliance metrics are updated to reflect the breach

---

### Test Case: Verify access control to monitoring dashboard
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- System has role-based access control configured
- Test user accounts exist: one with Admin role and one without Admin role (e.g., Employee or Manager role)
- Monitoring dashboard URL is accessible
- Authentication system is functioning correctly
- Security policies are enforced at application level

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the monitoring dashboard URL using a browser | Login page is displayed |
| 2 | Enter credentials for a non-admin user (Employee or Manager role) and click Login | User is authenticated successfully |
| 3 | Attempt to access the monitoring dashboard page | Access denied message is displayed with text similar to 'You do not have permission to access this resource' or 'Admin role required' |
| 4 | Verify the user is not redirected to the dashboard and remains on access denied page | User cannot view any monitoring metrics or dashboard components |
| 5 | Attempt to directly access the API endpoint GET /api/monitoring/metrics using non-admin credentials | API returns 403 Forbidden status code with appropriate error message |
| 6 | Log out the non-admin user | User is successfully logged out and redirected to login page |
| 7 | Enter credentials for a user with Admin role and click Login | Admin user is authenticated successfully |
| 8 | Navigate to the monitoring dashboard page | Full access is granted and monitoring dashboard loads completely with all metrics visible |
| 9 | Verify all dashboard features are accessible (real-time metrics, historical reports, drill-down capabilities) | Admin user can view and interact with all dashboard features without restrictions |
| 10 | Access the API endpoint GET /api/monitoring/metrics using admin credentials | API returns 200 OK status code with monitoring metrics data in response |

**Postconditions:**
- Non-admin user access attempt is logged in security audit trail
- Admin user access is logged in system audit trail
- No unauthorized data exposure occurred
- Role-based access control remains enforced
- Admin user session remains active on dashboard

---

