# Attack Path Graph — Research: Closing the Network Reachability and Node-Bridging Blockers

Research conducted 2026-09-28 via two parallel research agents, in response to the question:
"What's lacking from the ingredients of the attack simulation engine?" identified two blockers
in the current `app/services/graph_service.py` architecture:

1. **No network/resource reachability model** — findings carry real `security_groups`/`subnet_id`/
   `public_ip` data (captured this session), but nothing turns it into a queryable topology.
2. **No node bridging across categories** — edges exist only for IAM privilege-escalation
   (Cloudsplaining) and OAuth grants. Every Prowler/Lynis misconfiguration finding is a
   disconnected island node, by explicit design (see `graph_service.py`'s own docstring).

Both agents independently converged on the same infrastructure verdict (stay on Postgres, don't
adopt Neo4j) despite researching different questions — see "Unified recommendation" at the bottom.

---

## Report 1: Network Reachability

### 1. Most credible OSS tools/approaches

**Cartography** (CNCF, originally Lyft) — https://github.com/cartography-cncf/cartography —
Apache-2.0, actively maintained. Computes `exposed_internet` via Cypher pattern matching over
ENI → SG → rule → CIDR chains, and models VPC peering for cross-account reachability. **Its own
docs explicitly state route tables and NACLs are NOT modeled** — "configured reachability, not
observed traffic." Even the best-maintained OSS graph tool in this space stops short of full
east-west path computation. Fit: data model/relationship design is directly reusable inspiration;
no NACL/route-table logic exists to port because it doesn't exist here. Adopting Cartography
wholesale means adopting Neo4j.

**CloudMapper** (Duo Labs/Cisco) — https://github.com/duo-labs/cloudmapper — BSD-3-Clause,
largely dormant. `shared/public.py` walks SG `IpPermissions` for `0.0.0.0/0` rules, resolves the
attached resource and public IP, consolidates matched ports. The code itself carries
`# TODO: look at NACLs` — never reads NACLs or route tables, one-hop only, no graph. Fit: the
logic is small, readable, and portable as a template for the north-south check Sentinel needs;
not a reachability engine.

**PMapper** (NCC Group) — https://github.com/nccgroup/PMapper — **AGPL-3.0** (copyleft — read for
algorithm ideas, don't vendor code). Identity-graph only (IAM privilege escalation via local
policy simulation); does not model network topology at all.

**CloudFox** (Bishop Fox) — https://github.com/BishopFox/cloudfox — MIT, actively maintained.
Read-only boto3 enumeration for pentesters. Its "internet-reachable-endpoints" check is SG/public-IP
based, same shallow level as CloudMapper. MIT license makes it the safest to borrow snippets from.

### 2. Dead ends / oversold

- **VPC Reachability Analyzer**: real algorithm (routes + SGs + NACLs + gateways), wrong shape —
  priced per analysis ($0.10), requires an explicit source/destination pair per call, default quota
  1,000 paths/10,000 analyses/100 concurrent. No bulk "give me the whole graph" API. Cross-account
  mode requires AWS Organizations trusted access + CloudFormation StackSets — assumes Sentinel is
  the customer's org management account, which doesn't match Sentinel's single-assumable-role trust
  model. **Not viable for bulk graph-building.** Good only as an optional, user-triggered "verify
  this one path is real" confirmation feature later.
- **Network Access Analyzer**: same problem — requires authoring Network Access Scopes up front per
  question; not bulk-exportable.
- **Steampipe/Powerpipe `aws-compliance` mod**: no dedicated reachability benchmark exists.

### 3. Concrete recommendation

**Build it in-house, in Python against boto3 data, modeled directly in Postgres. Do not adopt
Neo4j. Do not depend on Reachability/Network Access Analyzer for graph construction.**

- No OSS tool has solved the hard part (NACL + route-table-aware east-west reachability) —
  "adopt a library" isn't on the table for the core algorithm.
- Sentinel is a single-team Python/FastAPI/Postgres shop; a per-tenant graph (one customer's VPC
  topology) is small and shallow — not the cross-account-portfolio scale that justified Cartography's
  Neo4j at Lyft.
- Postgres recursive CTEs (`WITH RECURSIVE`) are adequate for this graph's actual shape (a handful
  of hops), run per-scan/per-report, not as a hot interactive multi-hop query path.
- Apache AGE (Cypher-on-Postgres) is a middle option worth a spike later — stores graph data in
  regular Postgres tables with B-tree lookups per hop (not index-free adjacency), so for this
  shallow-graph case it buys Cypher syntax, not real graph-DB performance. Start with adjacency-list
  tables + recursive CTEs; only reach for AGE if hand-rolled CTEs become unmaintainable.
- Use VPC Reachability Analyzer selectively as a **confirmation layer**: once the graph flags a
  candidate path, optionally let a customer trigger one real Reachability Analyzer call to verify it
  — bounded cost, bounded scope, user-initiated. Never use it to build the base graph.

**Build plan:**
1. Ingest new boto3 data into new Postgres tables: `network_interfaces`, `security_groups`,
   `security_group_rules`, `subnets`, `route_tables`, `route_table_associations`, `network_acls`,
   `network_acl_entries`, `vpc_peering_connections`, `transit_gateway_attachments` (route tables and
   NACLs are new — not currently captured).
2. Compute internet-exposure (north-south) as a batch job per scan: single pass over each ENI's SG
   ingress rules for `0.0.0.0/0`/`::/0`, gated on public IP or IGW-routed subnet.
3. Compute east-west reachability as a recursive CTE over subnet→route-table→(peering|TGW|local)→subnet,
   gated at each hop by destination SG ingress + both subnets' NACLs (stateless, check both directions)
   + a route actually existing toward the destination CIDR.
4. Store computed edges as first-class rows (`attack_path_edges(source_finding_id, target_finding_id,
   edge_type, evidence_json)`) so `Finding.extra.resource_metadata` graduates from opaque JSONB to
   queryable topology.

### 4. Core algorithm (precise enough to implement)

**North-south** — single pass, no traversal: for each ENI, collect attached SG ids → for each SG,
fetch ingress rules → if any rule's CIDR is `0.0.0.0/0`/`::/0` (or references another SG that itself
allows it) AND the ENI has a public IP (or sits in an IGW-routed subnet) → mark reachable on that
port/protocol. Combine with `http_tokens != required` (IMDSv1) for an elevated-severity SSRF chain.

**East-west** — two layered graphs, intersected:
- *Connectivity graph*: nodes = subnets; edges = local VPC routing + route-table entries pointing at
  peering/TGW/VPN, restricted to the CIDR each route covers. BFS/recursive CTE from source subnet,
  following only routes whose destination CIDR contains the target.
- *Policy graph*: for each connectivity hop, check source subnet's outbound NACL allows traffic to
  destination CIDR/port AND destination subnet's inbound NACL allows traffic from source (NACLs
  evaluated in numeric order, first match wins, implicit final deny) AND destination SG ingress
  permits the source (by CIDR or by SG-to-SG reference — model these as edges, not CIDR strings).
- A path is reachable only if both graphs agree. This is exactly the model AWS's Reachability
  Analyzer builds internally — Sentinel needs it as a bulk-computed, storable graph, not a
  $0.10-per-pair on-demand query.

### Sources
github.com/cartography-cncf/cartography · docs.cartography.dev/modules/aws/infrastructure-investigations.html
· github.com/duo-labs/cloudmapper · github.com/nccgroup/PMapper · github.com/BishopFox/cloudfox ·
docs.aws.amazon.com/vpc/latest/reachability/* (what-is, cross-account-access-roles,
reachability-analyzer-limits) · docs.aws.amazon.com/vpc/latest/network-access-analyzer/* ·
aws.amazon.com/vpc/pricing · hub.powerpipe.io/mods/turbot/steampipe-mod-aws-compliance

---

## Report 2: Node Bridging & Crown-Jewel Scoring

### 1. Cartography's AWS data model

Apache-2.0, CNCF Sandbox project (accepted Aug 2024), actively released. Node types relevant here:
compute/network (`AWSEC2Instance`, `AWSEC2SecurityGroup`, `AWSEC2Subnet`, `AWSVpc`,
`AWSNetworkInterface`), identity (`AWSPrincipal` abstract parent, `AWSUser`, `AWSRole`, `AWSGroup`,
`AWSInstanceProfile`), storage (`AWSS3Bucket`, `AWSRDSInstance`, `AWSDynamoDBTable`), policy
(`AWSManagedPolicy`, `AWSPolicyStatement`).

Relationship model — every resource type is a first-class node, edges typed by *capability*:
- `AWSEC2Instance -[STS_ASSUMEROLE_ALLOW]-> AWSRole` (instance profile → role)
- `AWSPrincipal -[STS_ASSUMEROLE_ALLOW]-> AWSRole` (computed from trust policy AND permissions,
  not raw trust-policy text)
- `AWSPrincipal -[CAN_READ|CAN_WRITE]-> AWSS3Bucket`
- `AWSEC2Instance -[MEMBER_OF_EC2_SECURITY_GROUP]-> AWSEC2SecurityGroup`
- `AWSEC2SecurityGroup -[ALLOWS_TRAFFIC_FROM]-> AWSEC2SecurityGroup`

Key insight: `STS_ASSUMEROLE_ALLOW` is a **computed** edge (cross-referencing trust policy + identity
policy + org SCPs), materialized as a graph traversal step — structurally identical to what
Cloudsplaining already gives Sentinel today, just expressed as static analysis instead of Cypher
pattern-matching. Confirms Sentinel's Cloudsplaining output is already "Cartography-shaped"; the
missing work is resource nodes + exposure/access edges, not redoing the identity side.

### 2. BloodHound — the algorithm, and the AWS-specific development that changes the picture

Core pattern: nodes + typed edges (each edge means "you can do X to reach the target," never an
administrative label) → mark a small curated set of nodes "high value" (Tier Zero, seeded by
defaults like Domain Admins/DCs, editable by admins) → run shortest-path from an attacker-controlled
node to every high-value node → surface **chokepoints** (nodes recurring across many shortest paths).

**SpecterOps shipped AWS attack-path support in BloodHound Enterprise in July 2026** ("AWS Attack
Path Management") modeling IAM/Organizations/STS/S3/KMS/Lambda/EC2/CloudFormation/EKS/SSM — 20+
resource types, 150+ relationship types. They **open-sourced the collector in August 2026: AWSHound**
(github.com/AWSHound/AWSHound), targeting BloodHound Community Edition's new **OpenGraph** format
(extensible schema for third-party node/edge kinds). Its model:
- Nodes: `AWS_User/Group/Role`, `AWS_S3Bucket/EC2Instance/LambdaFunction/KMSKey/SSMParameter/
  EKSCluster/CloudFormationStack`, `AWS_Account/Organization`
- Edges: 156 total, 36 traversable for pathfinding — e.g. `AWS_CanAssumeRole`, `AWS_RunsAs`
  (compute → its execution role), `AWS_CanUpdateLambdaCode`, `AWS_CanCreateAndAssumeAdminRole`
- Explicit design rule: **"an edge is something you can do, not an administrative relationship"**
  — the exact philosophy already stated in Sentinel's own `graph_service.py` docstring.
- `AWS_RunsAs` is the literal answer to the node-bridging blocker: the edge connecting a
  misconfiguration-bearing resource (exposed Lambda/EC2) to its IAM execution role — precisely the
  missing link.

This is strong, very recent (last ~2 months as of this research) validation that Sentinel's target
architecture is directionally correct, and specifies the exact edge taxonomy needed — a spec that
can be read and adapted into Postgres tables without adopting BloodHound or Neo4j at all.

### 3. CloudFox and PMapper — what they add

- **CloudFox**: point-in-time enumeration CLI, not a persistent graph store. No data model worth
  borrowing — value is in finding-type/severity heuristics only.
- **PMapper**: closest to what Cloudsplaining already does for Sentinel (IAM graph + local policy
  simulator, including indirect escalation via resource-creation permissions). Explicitly
  identity-only — no resource-level model. Doesn't solve the bridging blocker; confirms identity-graph
  tools uniformly stop at the IAM boundary, which AWSHound is the first public attempt to fully close.

### 4. Postgres vs. graph database

A documented benchmark: recursive CTE traversing a 335K-node tree took 47s vs. 227ms for in-memory
BFS (~200x slower) — Postgres's recursive executor has no visited-state tracking, so it can't prune
already-explored nodes mid-traversal. This matters at real-account scale (thousands of resources).

Recommendation: adjacency-list tables (`graph_nodes`, `graph_edges`, typed `node_type`/`edge_type`,
tenant-scoped) + recursive CTEs with an explicit depth cap (~6 hops) and a visited-array guard
(`WHERE NOT resource_id = ANY(path)`) is workable at per-tenant scale now. **Apache AGE** (Apache-2.0,
`apache/age`) — openCypher inside Postgres, same database/backups/connection pool, results joinable
with existing tables — is the realistic next step once recursive-CTE latency becomes a real
complaint, before ever considering Neo4j. A dedicated graph database is justified specifically for
cross-tenant/cross-account queries or high-concurrency interactive multi-hop exploration — neither
applies to Sentinel's per-tenant, per-scan-cycle graph build.

### 5. Edge taxonomy recommendation

Add these edge types beyond Sentinel's current IAM-role/OAuth-grant edges:
- `ATTACHED_TO` (instance profile → role; SG → instance)
- `EXPOSED_TO_INTERNET` (network node → 0.0.0.0/0, derived directly from existing Prowler SG findings)
- `CAN_ASSUME` / `CAN_ESCALATE_TO` (already exists, from Cloudsplaining)
- `CAN_ACCESS` (role → S3/RDS/DynamoDB, derived from resource + identity policy evaluation — new work)
- **`RUNS_AS`** (compute resource → its IAM role — highest leverage; connects Prowler nodes to the
  existing Cloudsplaining subgraph; instance-profile-to-role mapping is already available, zero new
  scanning required)

### 6. Crown-jewel / criticality scoring

Every source (BloodHound Tier Zero, Wiz, AWS's tagging whitepaper) converges: **fundamentally a
human-curated tag, not reliably inferred automatically**; automated signals only suggest candidates.

- **Build now**: a `criticality` field on resource nodes, seeded by defaults from resource type +
  naming/environment heuristics (`prod` in name/tag → elevated; RDS/Redshift/DynamoDB without
  `dev`/`test`/`sandbox` tags → elevated), mirroring how BloodHound seeds Tier Zero with editable
  defaults. Plus a manual "mark as crown jewel" toggle in the UI — Wiz does exactly this ("any path
  leading to them is automatically elevated regardless of intermediate scores"). Ship this before any
  automated classification.
- **Defer**: Amazon Macie (real, API-drivable, event-driven S3 PII scanning) — priced per-GB-scanned
  and per-bucket-job, a nontrivial recurring cost to run centrally across every tenant's S3 estate in
  a low-priced multi-tenant SaaS. Realistic path: offer as an opt-in Pro/MSP-tier feature invoked
  against the tenant's own AWS account/bill, not operated centrally by Sentinel.
- **Toxic-combination framing** (Wiz, public blog/academy pages): score a path by whether it combines
  (1) public exposure, (2) unpatched vuln/CVE, (3) excessive privilege, (4) sensitive/critical data at
  the endpoint — and prioritize by *shortest path to highest-value target* over raw CVSS of any single
  node. Directly implementable once nodes 1–3 exist (Prowler=exposure/vuln, Cloudsplaining=privilege,
  crown-jewel tag=data criticality); a manually-tagged "holds customer PII" flag satisfies signal (4)
  just as well as Macie for ranking purposes on day one.

### Dead ends / oversold

- **CloudFox**: no persistent graph or path-finding algorithm despite frequent BloodHound/Cartography
  comparisons — any "graph" association is via third-party export scripts, not a built-in capability.
- **PMapper**: IAM-only, no resource-level model — won't help bridge the node-category gap.
- Pre-2026 "BloodHound for AWS" community attempts never reached the maturity of SpecterOps's
  July/Aug 2026 release — treat those older proofs-of-concept as stalled, not current state of the art.
- Macie as the *primary/default* crown-jewel signal is likely oversold for a cost-sensitive SMB/MSP
  product — real and working, but the per-scan cost model doesn't fit a low-priced multi-tenant SaaS
  without passing cost/operation to the tenant's own account.

### Sources
docs.cartography.dev/modules/aws/schema.html · github.com/cartography-cncf/cartography (
aws-privilege-escalation-queries.md) · cncf.io/projects/cartography ·
specterops.io/blog/2026/07/28/attack-path-management-comes-to-aws ·
specterops.io/blog/2026/08/19/awshound-opensource-aws-opengraph-collector ·
bloodhound.specterops.io/get-started/security-boundaries/tier-zero-members ·
github.com/BishopFox/cloudfox · bishopfox.com/blog/privilege-escalation-in-aws ·
github.com/nccgroup/PMapper · wiz.io/blog/the-anatomy-of-a-toxic-combination-of-risk ·
wiz.io/academy/detection-and-response/attack-path-analysis · age.apache.org/overview ·
docs.aws.amazon.com/whitepapers/latest/tagging-best-practices · docs.aws.amazon.com/macie/latest/user/what-is-macie ·
dev.to/ineron/your-postgresql-already-has-a-graph-engine-you-just-have-to-build-it-2ng7

---

## Unified recommendation

Both agents, researching independently, landed on the same infrastructure call: **stay on Postgres.**
Adjacency-list tables (`graph_nodes`, `graph_edges`) + recursive CTEs now; Apache AGE as the realistic
middle step if hand-rolled CTEs stop scaling; a dedicated graph database (Neo4j) is not justified at
Sentinel's per-tenant, per-scan-cycle graph scale — that tradeoff only flips for cross-account/
cross-tenant portfolio queries or high-concurrency interactive exploration, neither of which applies.

**Suggested phase order**, ranked by leverage vs. new-scanning cost:

1. **`RUNS_AS` edge** (compute → IAM role) — bridges existing Prowler nodes into the existing
   Cloudsplaining subgraph. Zero new AWS API calls; instance-profile-to-role mapping already available.
2. **`EXPOSED_TO_INTERNET` edge** — from SG data already captured this session (Prowler OCSF
   `resource_metadata`). Single-pass, zero new AWS API calls.
3. **Crown-jewel tag** — manual toggle + heuristic defaults (prod/env naming, resource type). No new
   scanning; ships fast; unlocks toxic-combination-style path ranking immediately.
4. **NACL/route-table ingestion + east-west reachability CTE** — the deep lift (new boto3 calls, new
   tables, the two-layer connectivity/policy graph). Worth deferring until 1–3 prove the graph model
   and UI are worth the investment.

Steps 1–3 alone would connect the majority of currently-isolated Prowler findings into the existing
privilege-escalation subgraph and enable real path-ranking by "shortest path to a tagged crown jewel"
— the core of the original "attack simulation engine" pitch — without touching network topology at all.
