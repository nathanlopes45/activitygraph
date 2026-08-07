# Screenshots

Four views of a live dashboard, taken on a real network. The first is the
one on the [README](../README.md); the rest are here so the front page stays
short enough to read.

Captions say what each view answers rather than what it contains, on the
grounds that a reader can already see what it contains.

## The signed-in view

![Filter and This Device panels above the group's daily limits and blocked
sites, the group's devices, and where the time went per
person](images/dashboard.png)

What a person sees when they sign in: the device they are holding, the group
it belongs to, what that group has blocked or limited, and where its time
went. The filter sits collapsed at the top because it is a convenience, not
the point of the page.

This is the one image in the README, because it carries the whole idea in a
single frame: time, attributed to people, with the controls to act on it.

## Time, per person, and the activity graph

![Where your time went and time per person, above the activity
graph](images/time-and-activity-graph.png)

The totals with the graph underneath, which is where sessions become legible
as an evening rather than as four hundred connections.

Time is measured by interval union, never by sum. A phone and a laptop both
on YouTube for the same hour is one hour of that group's day, not two.

## The detail, for anyone who wants it

![Category breakdown and devices, with the Stats for Nerds section
expanded](images/stats-for-nerds.png)

The category breakdown and the device list, with **Stats for Nerds**
expanded to show sessions and raw flows.

It is collapsed by default, and that is the design rather than an oversight:
the people this runs for are not network engineers, and a dashboard that
opens on a flow table answers a question nobody asked. The detail is one
click away for anyone who wants it.

## Day over day

![Category breakdown and devices with Stats for Nerds collapsed, above the
history panel](images/history-and-breakdown.png)

The same page with the detail folded away, and the history panel showing
trends across runs. This is what `--history-db` buys: a single snapshot
cannot tell you whether today was unusual.
