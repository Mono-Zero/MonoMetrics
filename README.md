MonoMetrics

Privacy-focused visitor counter. Self-hosted, open source, no tracking.

What it does differently

Standard analytics stores your IP and device info, often tied to a cookie, so the site owner can recognize you across visits. This doesn't.

Your IP gets hashed with a salt that changes every day, then discarded. The hash is one-way — can't be reversed back to your IP. Because the salt rotates daily, the same visitor hashes to a different value tomorrow, so there's no way to link visits across days.

Instead of storing per-visitor records, hits get fed into a HyperLogLog counter — a data structure that estimates unique counts without storing individual entries. There's no visitor list to query, no lookup table, nothing to breach or subpoena that would reveal who visited.

What it collects

Page URL and device type (mobile/desktop). Nothing else. No fingerprinting.

What you get

Daily unique visitor estimate via JSON endpoint. Build your own dashboard on top if you want one.

Tradeoff

Counts are estimates (~1-2% margin of error), not exact. That's the cost of the counting method not retaining individual records to recount from.

Self-hosted only

No central server. You run it, you own the data (or lack thereof). Code's public — verify the claims yourself instead of trusting a privacy policy.

Setup
Deploy the server (single file, minimal deps)
Add the one-line script tag to your site
Query the JSON endpoint for counts
