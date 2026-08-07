# Screenshots

Four views of a live dashboard on a real home network. The first two are
also on the [README](../README.md); the rest are here so the front page
stays short enough to read.

Captions say what each view answers rather than what it contains, on the
grounds that a reader can already see what it contains.

## Signed in as the admin

![A collapsed filter, the This Device panel, and every group's daily limits
and blocked sites](images/dashboard.png)

The admin sees every group's lists and can edit them, which is what makes
the account useful without letting it claim anything: a device belongs to
one group at a time, so an admin claiming one would take it from the person
whose device it is.

Two groups show Instagram already blocked for the day, having spent an
allowance measured in minutes. The filter sits collapsed because it is a
convenience, not the point of the page.

## Where the time went, and the graph underneath

![Category, subcategory and service totals beside time per person, above the
activity graph joining devices to sessions to services](images/time-and-activity-graph.png)

The breakdown goes category, then subcategory, then service: Social Media,
then Feeds, then Instagram. Nobody thinks in port numbers.

The pair of numbers under **time by person** is the whole argument for
measuring time the way this does. Five devices produced **17m of device
time** across **10m** of wall clock, because people use more than one thing
at once. Intervals are unioned rather than summed, so a phone and a laptop
both on Instagram for the same minute cost that minute once.

Below, the activity graph joins each device to its sessions and on to the
services they reached, which is what turns four hundred connections into an
evening somebody would recognise.

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
