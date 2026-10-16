# AWS build checklist: cost guardrails and cleanup (V2 plan C9)

Read before each build step. Prices change: check the current AWS pricing page before creating anything that bills by the hour or the month. Nothing here has been created yet.

## Before any step
1. Confirm the project Region (AWS Settings > View all projects > Overview > Additional Info > Region). Every Regional resource goes there. Only WAF and CloudWatch Logs may sit in us-east-1, and only for a global dependency.
2. Check the spend limit in AWS Settings > Billing. A reached limit pauses the project, and the symptom is sudden Access Denied on things that worked.
3. Set a budget alert in Billing and Cost Management before creating anything that bills continuously.
4. Tag every resource `app=zoneproof` and `step=<plan id>` so one filter finds what a step created.

## Per step: what bills, and how to undo it
| Plan | Creates | Bills while it exists | Cleanup |
|---|---|---|---|
| C2 | One Secrets Manager secret | Per secret per month | Delete the secret (it has a recovery window; schedule deletion) |
| C3 | Managed Postgres | Instance hours + storage + backups, even when idle | Take a final snapshot, then delete the instance; delete old snapshots |
| C3 | One-off migration task | Task run time only | Nothing left behind; check the task definition is not scheduled |
| C4 | Inbound mail path | Depends on the chosen design | Decide with C4; list resources here when chosen |
| C5 | Static bucket + CloudFront | Storage and requests (small); CloudFront data out | Empty the bucket, then delete the distribution (disable first, wait), then the bucket |
| C6 | Model access | Per token | Remove the runtime's model permission; set a token budget first |
| C7 | Shared cache/rate-limit store | Node hours | Delete the cache cluster |
| C8 | Log groups, alarms | Log ingestion and storage; alarms per month | Set retention on every log group (default is never expire); delete alarms |
| C10 | The stacks above as code | Everything above | `destroy` the stack in reverse order; confirm nothing is retained |

## After each step
- List what was created and ask: keep it or remove it?
- If keeping, write down the monthly cost next to the row above.
- Leave nothing without a retention or deletion date: log groups, snapshots, buckets, secrets.

## Always-on items that surprise people
Managed database instance hours, NAT gateways, load balancers, idle cache nodes, unattached Elastic IPs, CloudWatch log groups with no retention.
