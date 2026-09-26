# MonoMetrics

Visitor counter that can't tell who visited

## the difference

Normal trackers keep your IP + device often with a cookie so they recognize you next time This doesn't keep anything

IP gets mixed with a daily changing random value hashed into garbage thrown out Can't reverse it Tomorrow's garbage text won't match today's for the same person so there's nothing to link across visits

Instead of a visitor list hits go into a HyperLogLog counter just estimates how many uniques without storing who they were No list means no list to leak

## collects

Page URL mobile/desktop Nothing else

## returns

A daily unique count via JSON No dashboard, wire it up yourself

## catch

Estimate off by ~1-2% Price of not keeping records

## hosting

Yours not mine No central server collecting everyone's stuff Code's open check it instead of trusting me

## setup

1. run the server
2. paste the script tag
3. hit the endpoint for counts
