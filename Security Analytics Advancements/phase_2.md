# Phase 2 - Security Analytics Charts

## Goal

Build the primary analytics section of the **Security Analytics** dashboard.

This phase should introduce visual analytics that help customers understand the overall health and posture of their environment at a glance.

Do not modify any functionality implemented in Phase 1.

Do not modify the existing **Findings** page.

The charts should be placed directly below the Executive Summary cards.

---

# Layout

Create a responsive row containing five widgets.

Layout:

---

Security Score Trend | Findings by Severity | Grade Distribution

Firmware Distribution | Most Common Findings

---

All widgets should have:

* Consistent height
* Rounded corners
* Card title
* Small information (ⓘ) icon
* Hover effects
* Loading skeleton
* Empty state
* Responsive layout

On smaller screens, cards should wrap naturally while maintaining equal spacing.

---

# Widget 1 - Security Score Trend

## Goal

Allow customers to quickly determine whether their security posture is improving or declining over time.

---

## Position

Top left.

This should be the largest chart in the row.

---

## Chart Type

Line Chart

---

## Data

Display the average security score over time.

Example:

60

63

67

72

74

78

81

84

---

## Time Selector

Place a dropdown in the top-right corner of the widget.

Supported options:

* Last 7 Days
* Last 30 Days
* Last 90 Days
* Last Year

Changing the period should immediately refresh the chart.

---

## Hover Tooltip

Display:

* Date
* Average Security Score
* Number of analyzed devices

Example:

June 10

Average Score: 81

Devices Analyzed: 126

---

## Empty State

Display

"No historical analysis data available."

---

## Loading State

Show an animated placeholder graph.

---

## Calculation

Use completed TSR analyses only.

Ignore:

* Failed analyses
* Devices without analysis history

---

## Interaction

Future phases will allow clicking chart points.

For this phase:

Chart is read-only.

---

# Widget 2 - Findings by Severity

## Goal

Provide a quick breakdown of current findings by severity.

---

## Position

Top center.

---

## Chart Type

Doughnut Chart

---

## Display

Critical

High

Medium

Low

---

## Center Text

Display:

Total Findings

Example

553

Total Findings

---

## Color Scheme

Critical

Red

High

Orange

Medium

Yellow

Low

Blue

Use the same severity colors already used throughout FirewallGuard AI.

---

## Legend

Display:

Severity

Count

Percentage

Example

Critical

23 (6%)

High

86 (20%)

Medium

154 (36%)

Low

290 (38%)

---

## Interaction

Clicking a severity should:

* Filter the device table
* Refresh all executive summary cards
* Refresh every chart

Multiple filters should continue working together.

---

# Widget 3 - Security Grade Distribution

## Goal

Visualize how devices are distributed across security grades.

---

## Position

Top right.

---

## Chart Type

Doughnut Chart

---

## Display

Grades

A

B

C

D

F

---

## Center Text

Display

Total Devices

Example

104 Devices

---

## Color Scheme

Grade A

Green

Grade B

Light Green

Grade C

Yellow

Grade D

Orange

Grade F

Red

---

## Legend

Display:

Grade

Device Count

Percentage

Example

A

12 (8%)

B

25 (18%)

C

42 (30%)

D

18 (13%)

F

7 (5%)

---

## Calculation

Only configured devices.

Ignore:

* Not Configured
* Decommissioned

---

## Interaction

Clicking Grade B

↓

Filter device table

↓

Refresh every dashboard component.

---

# Widget 4 - Firmware Distribution

## Goal

Help customers understand firmware adoption across their environment.

---

## Position

Bottom left.

---

## Chart Type

Horizontal Bar Chart

---

## Display

Firmware Version

Number of Devices

Percentage

Example

7.3.2

91 Devices

47%

---

## Sorting

Sort by:

Highest device count first.

---

## Bar Labels

Display values at the end of each bar.

Example

91 (47%)

---

## Footer

Display

Total Devices:

192

---

## Interaction

Clicking firmware version

↓

Filter device table

↓

Refresh dashboard

---

## Empty State

Display

"No firmware information available."

---

# Widget 5 - Most Common Findings

## Goal

Identify the security issues affecting the largest number of devices.

---

## Position

Bottom right.

---

## Display

Top five findings.

Columns

Ranking

Finding Name

Occurrence Count

---

Example

1

SSH Enabled

142

2

Weak TLS Configuration

118

3

SNMP Public Access

96

4

Expired Certificates

71

5

Management on WAN

60

---

## Footer

Display

Total Unique Findings

Example

245

---

## Sorting

Descending by occurrence count.

---

## Interaction

Clicking a finding

↓

Filter device table

↓

Refresh charts

↓

Refresh executive cards

---

## Empty State

Display

"No findings available."

---

# Widget Behavior

Every widget must respect:

* Customer Filter
* Search
* Configure Filter

Changing any filter must immediately update:

* Every chart
* Every legend
* Every total
* Every percentage

without reloading the page.

---

# Loading State

Every widget should display a loading skeleton independently.

One slow widget must not block the others.

---

# Performance

Avoid issuing separate API requests for every widget whenever possible.

Prefer a single dashboard analytics endpoint that returns:

* Score trend
* Severity distribution
* Grade distribution
* Firmware distribution
* Most common findings

The dashboard should remain responsive even for organizations managing thousands of devices.

---

# UI Requirements

All widgets must:

* Match the FirewallGuard AI design language.
* Have equal visual weight.
* Use consistent spacing.
* Use consistent typography.
* Use consistent icon sizes.
* Support dark mode.
* Animate smoothly when data changes.

Charts should never feel cluttered or overwhelming.

---

# Acceptance Criteria

This phase is complete when:

* Security Score Trend chart is implemented.
* Findings by Severity chart is implemented.
* Security Grade Distribution chart is implemented.
* Firmware Distribution chart is implemented.
* Most Common Findings widget is implemented.
* All widgets respect existing filters.
* Clicking interactive widgets filters the dashboard appropriately.
* Loading and empty states are implemented.
* Existing functionality from Phase 1 continues working without regression.
* The original Findings page remains unchanged.
