# Phase 1 - Executive Summary Dashboard

## Goal

Transform the top section of the **Security Analytics** page into an executive dashboard that immediately communicates the customer's overall security posture.

The dashboard should provide a high-level summary of the environment without requiring users to inspect individual devices.

This phase should only replace the existing summary cards on the **Security Analytics** page.

Do not modify the existing **Findings** page.

No other sections of the Security Analytics page should be changed during this phase.

---

# Existing Functionality

The current page already supports:

* Customer filter
* Search
* Configure Filter
* Device list
* Navigation to Device Findings

All of this functionality must continue working exactly as it does today.

---

# Layout

Create five summary cards in a single responsive row.

The cards should appear in the following order:

1. Overall Security Score
2. Critical Findings
3. High Findings
4. Devices
5. Protected Devices

Each card should have:

* Rounded corners matching the application theme
* Small icon in the upper left
* Title
* Large primary value
* Secondary information
* Small trend graph (sparkline)
* Hover tooltip
* Click interaction

Cards should resize gracefully on smaller displays.

---

# Card 1 - Overall Security Score

## Purpose

Provide a single health score representing the entire environment.

---

## Display

Icon:
Shield

Title:

Overall Security Score

Primary Value:

Average security score across all configured devices.

Example:

74 / 100

Secondary Value:

Overall security grade.

Example:

Grade C

Below the score display:

Example:

↑ 6 points vs last 30 days

Use:

Green when score improved.

Red when score declined.

Gray when unchanged.

---

## Sparkline

Display a small line graph showing the average security score trend.

Do not add axis labels.

Keep it simple and lightweight.

---

## Calculation

Use only configured devices.

Ignore:

* Not Configured devices
* Decommissioned devices

If no configured devices exist:

Display:

No Data

---

## Click Behavior

Clicking this card clears any grade filters currently applied.

---

# Card 2 - Critical Findings

## Purpose

Highlight the most urgent security issues.

---

## Display

Title:

Critical Findings

Primary Value:

Total number of open Critical findings.

Secondary Value:

Example:

↓ 12 vs last 30 days

Green

When Critical findings decreased.

Red

When Critical findings increased.

Gray

When unchanged.

---

## Sparkline

Display historical count of Critical findings.

---

## Click Behavior

Clicking the card should filter every dashboard component to devices containing Critical findings.

---

# Card 3 - High Findings

## Purpose

Show the current High severity workload.

---

## Display

Title

High Findings

Primary Value

Total High findings.

Secondary Value

Example

↓ 8 vs last 30 days

Same color rules as Critical.

---

## Sparkline

Display High findings trend.

---

## Click Behavior

Filter dashboard to devices containing High findings.

---

# Card 4 - Devices

## Purpose

Quick overview of managed assets.

---

## Display

Title

Devices

Primary Value

Total Devices

Example

142

Secondary Value

Configured Devices

Example

138 Configured

---

## Sparkline

Display growth of managed devices.

---

## Calculation

Include:

Configured

Not Configured

Exclude:

Decommissioned

---

## Click Behavior

Clear any device status filters.

---

# Card 5 - Protected Devices

## Purpose

Display overall licensing coverage.

---

## Display

Title

Protected Devices

Primary Value

Percentage of active protected devices.

Example

97%

Secondary Value

Example

137 / 142 devices

---

## Calculation

Protected Device

A device with:

* Active License
* Active Trial

Do NOT include:

Expired

Decommissioned

---

## Sparkline

Display protection percentage trend.

---

## Click Behavior

Filter dashboard to only protected devices.

---

# Time Range

The dashboard should respect the global time filter.

Initially support:

* Last 7 Days
* Last 30 Days
* Last 90 Days
* Last Year

Trend calculations should always compare against the selected period.

Example:

Last 30 Days

↓

Compare with previous 30 days.

---

# Hover Tooltips

Every card should include an information icon.

Hovering should explain:

Overall Security Score

"The average security posture score across all configured devices."

Critical Findings

"Total unresolved Critical findings."

High Findings

"Total unresolved High severity findings."

Devices

"Total managed devices currently visible after filters."

Protected Devices

"Devices with an active license or active trial."

---

# Filtering Rules

The summary cards must always respect:

* Customer filter
* Search
* Configure Filter

When any filter changes:

* All five cards refresh
* All sparklines refresh
* Trends recalculate
* Values update

No page reload should occur.

---

# Loading State

While data is loading:

Display animated skeleton cards.

Do not display zeroes.

---

# Empty State

If no devices exist:

Display

No Devices Found

and

Add your first device to begin monitoring.

---

# Performance

Do not issue separate API requests for each card.

Retrieve all required summary data in a single dashboard summary API whenever possible.

The page should feel instantaneous even for environments containing hundreds or thousands of devices.

---

# UI Requirements

Use existing FirewallGuard colors.

Critical

Red

High

Orange

Score

Green

Devices

Blue

Protected

Green

Spacing, typography, shadows, border radius, and icon sizing should remain consistent with the rest of FirewallGuard AI.

---

# Acceptance Criteria

This phase is complete when:

* Five executive summary cards replace the existing cards on the Security Analytics page.
* Every card updates dynamically based on dashboard filters.
* Every card contains a sparkline.
* Trend indicators display correctly.
* Clicking a card filters the dashboard appropriately.
* Loading and empty states are implemented.
* Existing Findings page remains completely unchanged.
* Existing navigation and device list continue working without regression.
