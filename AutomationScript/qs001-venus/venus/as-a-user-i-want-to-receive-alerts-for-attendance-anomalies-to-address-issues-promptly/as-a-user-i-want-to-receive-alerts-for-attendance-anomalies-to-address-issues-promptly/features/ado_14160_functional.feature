Feature: Attendance Anomaly Alert System
  As a User
  I want to receive alerts for attendance anomalies
  So that I can address issues promptly and maintain attendance compliance

  Background:
    Given user is logged into the system with valid credentials
    And attendance monitoring system is running and operational

  @functional @regression @priority-high @smoke
  Scenario: Alert is triggered and sent within 5 minutes when late arrival anomaly is detected
    Given user has an active attendance record in the database
    And user's expected arrival time is set to "9:00 AM" in the system
    And current system time is "9:16 AM"
    When system automatically analyzes attendance data and detects late arrival anomaly
    Then system should identify the late arrival as an attendance anomaly based on the 15-minute threshold rule
    And alert should be created with anomaly type "Late Arrival"
    And alert should include detected time "9:16 AM"
    And alert should include delay duration "16 minutes"
    And alert should include suggested action "Contact employee to verify reason"
    When system dispatches the alert notification to the affected user
    Then user should receive email notification with subject "Attendance Alert: Late Arrival Detected"
    And in-app notification should appear in the notification bell icon with red badge
    When system dispatches the alert to the user's manager
    Then manager should receive email notification with subject "Team Attendance Alert: [User Name] - Late Arrival"
    And in-app notification should appear in manager's notification center
    And alert delivery timestamp should show alerts were sent within 5 minutes of detection
    And alert record should be saved in the attendance alerts database with status "Sent"
    And alert should appear in the historical attendance alerts log with complete details

  @functional @regression @priority-high
  Scenario: User can acknowledge receipt of attendance anomaly alert and acknowledgment is recorded
    Given user has received an attendance anomaly alert for early departure
    And alert is visible in the user's notification center with "Unacknowledged" status
    And alert details show "Early Departure - Left at 4:30 PM (Expected: 5:00 PM)"
    And user is on "Notifications" page
    When user clicks on the notification bell icon in the top-right corner
    Then notification dropdown panel should open showing list of alerts
    And attendance anomaly alert with red "Unacknowledged" badge should be visible
    When user clicks on the alert titled "Attendance Alert: Early Departure Detected"
    Then alert detail modal should open displaying full information
    And modal should show anomaly type
    And modal should show detection time
    And modal should show description "You left at 4:30 PM, 30 minutes before expected departure time"
    And modal should show suggested action "Submit explanation or time-off request"
    When user clicks "Acknowledge" button at the bottom of the alert detail modal
    Then success message "Alert acknowledged successfully" should be displayed in green banner
    When user closes the modal and returns to the notifications list
    Then acknowledged alert should show green "Acknowledged" badge with timestamp
    And red notification badge count should decrease by 1
    When user navigates to "Attendance History" page
    And user locates the alert in the historical records
    Then alert record should show status "Acknowledged"
    And alert record should show acknowledgment timestamp
    And alert record should show acknowledging user name
    And manager should be able to see the acknowledgment status when viewing team alerts

  @functional @regression @priority-high
  Scenario: Alert includes complete anomaly details and suggested actions for multiple absence anomaly
    Given user is logged into the system as a manager with team view permissions
    And a team member has been absent for 3 consecutive days without prior notification
    And system has detected this as a "Multiple Absence" anomaly
    And user is on "Team Attendance Dashboard" page
    And alert has been generated and sent to both the absent employee and their manager
    When user opens the notification center by clicking the notification bell icon
    Then notification panel should display the alert with title "Critical Attendance Alert: Multiple Absence - [Employee Name]"
    When user clicks on the alert to view full details
    Then alert detail view should show anomaly type "Multiple Absence"
    And alert should show employee name
    And alert should show employee ID
    And alert should show detection date
    And alert should show absence duration "3 consecutive days (Jan 15-17, 2024)"
    And alert should show last known attendance "Jan 14, 2024 5:15 PM"
    When user scrolls down to view the "Suggested Actions" section
    Then suggested actions section should display "1. Contact employee immediately via phone and email"
    And suggested actions section should display "2. Verify employee wellbeing and safety"
    And suggested actions section should display "3. Request medical documentation if applicable"
    And suggested actions section should display "4. Initiate absence investigation per company policy"
    And suggested actions section should display "5. Document all communication attempts"
    When user reviews the "Alert Priority" and "Escalation Status" fields
    Then alert priority should show "Critical" in red text
    And escalation status should show "Escalated to HR Department" with timestamp
    When user clicks on "View Employee Contact Info" button within the alert
    Then employee contact information modal should open
    And modal should display phone number
    And modal should display email address
    And modal should display emergency contact details
    And modal should display last known location
    And alert should remain active until manager acknowledges and provides resolution notes
    And HR department should have visibility to the escalated alert in their dashboard

  @functional @regression @priority-high
  Scenario: Alerts are sent to both user and manager simultaneously for overtime anomaly detection
    Given user is currently working
    And user's shift end time is configured as "5:00 PM" in the system
    And current system time is "8:05 PM"
    And user has not logged out or marked departure in the attendance system
    And overtime threshold is set to 3 hours in system configuration
    When system automatically detects overtime anomaly at "8:05 PM" when threshold is exceeded
    Then system should identify "Excessive Overtime" anomaly
    And alert record should be created with user name
    And alert should include shift end time "5:00 PM"
    And alert should include current time "8:05 PM"
    And alert should include overtime duration "3 hours 5 minutes"
    When system simultaneously sends alert notification to the user's email address
    Then user should receive email within 2 minutes with subject "Attendance Alert: Excessive Overtime Detected"
    And email should contain anomaly details
    And email should contain suggested action "Please log out if work is complete or request overtime approval"
    When system simultaneously sends alert notification to the manager's email address
    Then manager should receive email within 2 minutes with subject "Team Attendance Alert: Excessive Overtime - [User Name]"
    And email should contain same anomaly details
    And email should contain suggested action "Verify if overtime is authorized and ensure employee wellbeing"
    When user checks in-app notifications
    Then user should see the overtime alert in notification center
    And alert timestamp should match email delivery time within 5 minutes of detection
    When manager checks in-app notifications
    Then manager should see the same overtime alert in their notification center
    And alert should have identical timestamp confirming simultaneous delivery
    When delivery log is checked at "/api/attendance/alerts/delivery-log"
    Then delivery log should show two entries with same alert ID
    And one entry should be for user delivery
    And one entry should be for manager delivery
    And both entries should have timestamps within 5 minutes of detection time
    And alert should be recorded with status "Delivered to User and Manager"

  @functional @regression @priority-medium
  Scenario: Historical record of attendance alerts is maintained and accessible with complete audit trail
    Given user is logged into the system as a manager with historical data access permissions
    And multiple attendance alerts have been generated over the past 30 days for the team
    And alerts include various types including late arrivals, early departures, absences, and overtime
    And some alerts have been acknowledged and others remain unacknowledged
    And user is on "Attendance Alerts History" page
    When user navigates to the "Attendance Alerts History" section from the main navigation menu
    Then attendance alerts history page should load displaying a table
    And table should have column "Alert ID"
    And table should have column "Employee Name"
    And table should have column "Anomaly Type"
    And table should have column "Detection Date/Time"
    And table should have column "Alert Sent Date/Time"
    And table should have column "Status"
    And table should have column "Acknowledged By"
    And table should have column "Acknowledgment Date/Time"
    And table should have column "Actions"
    When user applies date range filter to show alerts from the last 30 days
    Then table should refresh to display all alerts within the selected date range
    And page should show count "Displaying 47 alerts from Jan 1, 2024 to Jan 30, 2024"
    When user clicks on the "Anomaly Type" column header to sort alerts
    Then alerts should be grouped and sorted by type
    And table should show "Absences (12)"
    And table should show "Early Departures (8)"
    And table should show "Late Arrivals (15)"
    And table should show "Overtime (12)"
    And visual grouping indicators should be displayed
    When user clicks on "View Details" button for alert "ALT-2024-001234"
    Then alert detail modal should open showing complete information
    And modal should show full anomaly description
    And modal should show detection timestamp with millisecond precision
    And modal should show alert generation timestamp
    And modal should show delivery timestamps for user and manager
    And modal should show acknowledgment details if acknowledged
    And modal should show suggested actions provided
    And modal should show resolution notes if any
    And modal should show complete audit trail of all status changes
    When user clicks on "Export" button in the top-right corner
    Then export options modal should appear with formats CSV, Excel, PDF
    When user selects "CSV" format
    Then file should download with name "Attendance_Alerts_History_2024-01-01_to_2024-01-30.csv"
    And file should contain all displayed records
    When user applies filter to show only "Unacknowledged" alerts
    Then table should update to show only alerts with status "Unacknowledged"
    And page should display count "8 unacknowledged alerts requiring attention" with red highlight
    And all historical alert records should remain intact and accessible in the database
    And exported data should match the displayed records exactly

  @functional @regression @priority-medium
  Scenario: System correctly identifies and alerts for pattern-based anomaly of frequent tardiness
    Given user has been late to work 4 times in the past 7 days
    And each late arrival was between 10-20 minutes past expected arrival time
    And system pattern detection algorithm is configured to flag 4 or more late arrivals in 7 days as anomaly
    And current date is the 8th day
    When user checks in at "9:15 AM" which is 15 minutes late
    Then system should record the check-in
    And system should analyze attendance pattern for the past 7 days
    When system pattern detection algorithm identifies 5 late arrivals in 8 days
    Then system should generate a "Frequent Tardiness Pattern" anomaly alert with severity level "High"
    And alert should include pattern analysis "Employee has been late 5 times in the past 8 days (Jan 15, 17, 19, 21, 22) with average delay of 14 minutes"
    When system sends alert notification to user with pattern details
    Then user should receive notification titled "Attendance Pattern Alert: Frequent Tardiness Detected"
    And notification should include details of all late arrivals
    And notification should include pattern visualization
    And notification should include suggested action "Please review your schedule and discuss any challenges with your manager"
    When system sends alert notification to manager with pattern analysis
    Then manager should receive notification titled "Team Attendance Pattern Alert: Frequent Tardiness - [User Name]"
    And notification should include pattern details
    And notification should include trend graph
    And notification should include suggested actions "Schedule one-on-one meeting to discuss attendance concerns and identify support needs"
    When manager logs in and views the alert details including the pattern visualization
    Then alert detail view should show a timeline graph of late arrivals over the past 8 days
    And graph should highlight the pattern
    And each incident should be marked with delay duration displayed
    And pattern-based anomaly should be recorded with type "Frequent Tardiness Pattern"
    And alert should include references to all 5 individual late arrival incidents
    And system should continue monitoring the pattern for follow-up alerts if pattern persists
    And alert should be flagged for HR review if not resolved within 14 days