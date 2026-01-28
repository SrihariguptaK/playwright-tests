# Manual Test Cases

## Story: As Manager, I want to analyze attendance trends to achieve better workforce management
**Story ID:** story-18

### Test Case: Validate successful attendance trend visualization
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Manager user account exists with valid credentials and manager role permissions
- Manager is logged into the system
- Attendance database contains historical attendance data for at least one time period
- Analytics dashboard is accessible and functional
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Manager navigates to analytics dashboard by clicking on 'Analytics' or 'Dashboard' menu option | Analytics interface is displayed with available metrics options, time period selectors, and visualization area. Page loads within 3 seconds |
| 2 | Manager selects desired metrics to analyze (e.g., daily attendance, weekly trends, monthly patterns) from the metrics dropdown or selection panel | Selected metrics are highlighted and applied to the dashboard. System confirms metric selection with visual feedback (e.g., checkmark, highlight) |
| 3 | Manager selects a time period (e.g., last 30 days, last quarter, custom date range) for trend analysis | Time period is applied and system begins processing the data. Loading indicator appears if necessary |
| 4 | Manager views the attendance trends displayed in visual format (charts, graphs, tables) | Attendance trends are displayed accurately with correct data points, proper labeling, legends, and axis information. Visualization renders within 3 seconds. Data matches the selected time period and metrics with 100% accuracy |
| 5 | Manager hovers over or clicks on specific data points in the visualization | Detailed information tooltip appears showing exact values, dates, and relevant attendance statistics for the selected data point |

**Postconditions:**
- Attendance trends remain displayed on the analytics dashboard
- Selected metrics and time period settings are retained for the session
- No data corruption or system errors occur
- Manager can export or further analyze the displayed data

---

### Test Case: Verify insights into absenteeism rates
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Manager user account exists with valid credentials and manager role permissions
- Manager is logged into the system
- Attendance database contains absenteeism records for analysis
- Analytics dashboard is accessible and functional
- Absenteeism metrics are configured in the system
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Manager navigates to analytics dashboard by clicking on 'Analytics' or 'Dashboard' menu option | Analytics interface is displayed with available metrics options including absenteeism metrics. Dashboard loads successfully within 3 seconds |
| 2 | Manager selects absenteeism metrics from the available metrics list (e.g., absenteeism rate, absence frequency, absence patterns) | Absenteeism metrics are highlighted and applied to the dashboard. System displays confirmation that absenteeism analysis mode is active |
| 3 | Manager selects the time period for absenteeism analysis (e.g., last month, last quarter, year-to-date) | Time period is applied successfully. System begins calculating absenteeism rates for the selected period |
| 4 | Manager views the absenteeism insights displayed on the dashboard | Absenteeism insights are displayed accurately including: absenteeism rate percentages, trends over time, highlighted peak absence periods, and visual indicators (charts/graphs). Data visualization appears within 3 seconds with 100% accuracy |
| 5 | Manager reviews detailed absenteeism breakdown by clicking on specific sections or data points | Detailed breakdown appears showing: individual absence counts, reasons for absence (if available), department-wise distribution, and comparison with previous periods |
| 6 | Manager examines punctuality insights if available in the same view or adjacent section | Punctuality metrics are displayed showing late arrivals, early departures, and on-time attendance percentages with clear visual representation |

**Postconditions:**
- Absenteeism insights remain displayed on the analytics dashboard
- Manager can access detailed reports or drill down into specific absence records
- Selected absenteeism metrics and time period are saved for the current session
- No system errors or data inconsistencies occur
- Manager has actionable insights to address absenteeism issues

---

