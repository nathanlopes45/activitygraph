# Screenshots

The README carries two images: the dashboard and the gateway diagram. The
rest live here, so the front page stays short enough to read.

Add one by dropping a PNG in `docs/images/` and adding a section below.
Keep the captions describing what the view answers rather than what it
contains, since a reader can already see what it contains.

Take them on a real network. A screenshot with invented device names is the
one thing in this repository that would be untrue, and it is also the first
thing anyone checks.

## Where the time went

<!-- ![Time by category](images/time-by-category.png) -->

The three-level breakdown: category, then subcategory, then service. Bytes
are deliberately not the headline, because a 4K stream and an evening of
reading produce wildly different byte counts for the same hour of someone's
life.

## Per person, across their devices

<!-- ![Group totals](images/groups.png) -->

The question the project exists to answer. A phone and a laptop both on
YouTube for the same hour is one hour, not two: intervals are unioned rather
than summed.

## Daily limits and blocked sites

<!-- ![Limits panel](images/limits.png) -->

What a group has chosen to block outright, and what it has given itself an
allowance for. The admin view shows every group's lists.

## Devices

<!-- ![Device list](images/devices.png) -->

Named from what each device announces about itself, or from what its owner
called it when they claimed it. Worth showing the two together, since the
difference between "iPhone" and "Nathan's iPhone 13" is most of the work.

## Trends over time

<!-- ![History](images/history.png) -->

Day over day, from `--history-db`. Useful for showing the project does
something a single snapshot cannot.

## Stats for nerds

<!-- ![Sessions and flows](images/sessions.png) -->

Sessions and raw flows, collapsed by default. Worth including precisely
because it is collapsed: it shows the detail exists without putting it in
front of someone who does not want it.
