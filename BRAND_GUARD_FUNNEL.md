# Brand Guard funnel counters

Built 2026-10-10. Answers one question: where does the volume go, and why? Brand Guard is a cascade (cheap checks first, expensive ones last), and nobody can tune it, price it, or decide where an AI layer should sit without knowing how many items reach each step. This records that, per brand per day. Open it in the app at **Brand Guard, Insight, Funnel**, or `GET /brand-guard/funnel?days=30&profile_id=...`.

## What is stored
Counts only: for each brand, day and stage, how many items **entered**, how many **passed**, and a small `detail` of why the rest did not (or how they split). No domain names, nothing about any particular look-alike. Table `brand_funnel_counts` (migration `e5a9c3d7f1b2`), one row per brand per day per stage, incremented atomically. Recording never breaks the work it describes: a failed counter is logged and ignored.

## The stages, and what each number means
Each stage counts its own things (names, candidates, visits), so the funnel is a series of filters, not one pile that shrinks. A stage's bar is its own pass rate.

| Stage | Counts | Passed means | Reasons recorded |
|---|---|---|---|
| Find candidates | names found this scan | sent on to a DNS check | how many each source found (name variations, certificate logs, newly registered, reported emails); names cut by the plan's scan budget |
| Keep real, live names | names new to this brand | kept as a candidate | not registered; over the plan's candidate limit; your own domains |
| Score and explain | candidates scored (new and re-scored) | scored suspicious | the split by current status |
| Pick who to visit | live, undismissed look-alikes | queued for a visit | visited recently; not similar enough yet; daily limit reached |
| Light probe | visits completed | page was reachable | page not reachable; worker could not fetch it; **waited too long (worker down or behind)** |
| Pick pages to render | probed pages | queued for a render | nothing interesting on the page; rendered recently; daily limit reached |
| Render | renders completed | produced a screenshot | failed; no screenshot; waited too long |
| Compare with your brand | pages compared | resembled your brand | icon copied; wording copied; same layout and colours |

The probe and render stages show "Off" until the worker and renderer are switched on, and record nothing while off.

Not counted here because they are already in the database: the spread of candidates by status (shown at the bottom of the page), cases, and takedowns. The AI layer is not built, so it has no stage; the page lists what is missing next to the stage it belongs to (`NOT_BUILT` in `brand_funnel.py`, edited as pieces are built).

## What to look for
- **A stage that drops almost everything:** check whether it is doing real filtering or hiding a problem (for example "not similar enough yet" dropping most live look-alikes means the similarity threshold decides who is ever visited).
- **"Waited too long":** the worker is down, offline, or behind. Jobs expire after 15 minutes. If this is more than a handful, add a worker or look at it.
- **"Daily limit reached":** the per-customer caps are binding. Whether that matters depends on what the dropped ones turn out to be.
- **Where an AI layer would get its volume:** the Compare stage's "resembled your brand" count, plus cases, is roughly what a lazy, per-case AI explanation would have to cover.

## What this does not tell you
It says how many items each filter dropped, **not whether it dropped the right ones**. A filter can drop 95% and be perfect, or drop 5% and be discarding real phishing. Measuring that needs the audit sample (send a small random share of what each filter drops through the next stage anyway and see what it finds), which is the next step and is not built. Until then these are volumes, not accuracy.

Counting started with the first scan after this was added, so older scans have no numbers.

## Checked
43 mutation checks on the counting rules (the arithmetic, the reasons, tenant and brand scoping, the safe wrapper); 42 caught, and the one that survives is equivalent (a reference job has no candidate, so an extra check is redundant). A first run caught eight gaps in the tests, all closed. On the dev app, a real scan of the Acme brand produced: 317 names found by name variations, 313 new names examined and all 313 dropped as not registered, 5 known candidates re-scored.

## What is not built
A funnel-shaped visual (the screen is a list of stage rows), a compact strip on the Brand Guard Overview, an alert when many jobs expire unclaimed, a roll-up across clients for MSPs, and the audit sample described above.
