# Passive DNS sources: terms-of-service check (V2 plan G4)

Checked 2026-10-16 from each provider's published terms. This is a product-risk read, not legal advice. Terms change: re-read the source page before relying on a row. "Product" below means ZoneProof: a paid service that shows results to customers and MSPs.

## Verdict
**No free passive DNS feed is safe to add to a paid product.** Every free tier we could read forbids commercial use or use inside a service. Certificate Transparency (already used) is the safe public source. If passive DNS is wanted, it has to be a paid or contracted licence.

## What was read
| Source | Free tier allowed in our product? | What the terms say | Confidence |
|---|---|---|---|
| **VirusTotal** public API | **No** | Public API must not be used in commercial products or services, or in business workflows that do not contribute new files. 500 requests/day, 4/minute. Premium has no such limits and is licensed per tier | Read on the VirusTotal docs |
| **Censys** Free/Researcher | **No** | Non-paying users may not use the service or its data for any commercial purpose, internal business use included. Attribution required. One account only. Data cannot go into products distributed to third parties without an Enterprise account. No building a competing product | Read on the Censys terms |
| **AlienVault OTX** | **No** | Free to end users for non-commercial use only. Commercial exploitation, showing or passing OTX content to third parties, and making it available as a service are prohibited. The EULA grants no right to build OTX data into a product | Read on the LevelBlue EULA |
| **HackerTarget** | **Not without written permission** | Site terms bar competing paid services and distributing or commercially exploiting content without express written permission. They say nothing about the free API, so the API terms must be asked for | Read the site terms only |
| **CIRCL passive DNS** | **Not as a public feed** | Access is by request to trusted partners, with affiliation and intended use stated. The page gives no data terms or price, so a request to CIRCL would be needed | Read the service page only |
| **SecurityTrails** | **Unknown** | Their terms page refused automated access (HTTP 403) and search did not surface the terms | **Not verified** |
| **Shodan** | **Unknown** | The legal page was not found at the expected address; lookups also cost query credits | **Not verified** |
| RapidDNS, Anubis (jldc.me), BufferOver, DNSDumpster | **Unknown** | Community or hobby sites with no clear published terms; availability can vanish without notice | **Not checked** |

## What to do
1. **Do not add a free passive DNS source.** The A6 subdomain discovery stays on its own records, the wordlist and Certificate Transparency.
2. If passive DNS is worth paying for, get a written commercial licence first. Ask each candidate: may results be shown to our customers, may we store them, is there a per-query cost, is there a redistribution limit. Candidates worth a quote: VirusTotal Premium, SecurityTrails (commercial plan), Shodan or Censys (Enterprise), CIRCL (request access).
3. Whichever source is chosen, add it behind the same rule as the other sources: shown on the Data sources page with its status, off by default until a key is set, and never called with a customer's data that is not already public.
4. Record the licence (who, when, what it allows) next to the key, so a later audit can see why a feed was allowed.

## Open for you
- Whether passive DNS is worth a paid licence at all, given CT plus own records already cover most of the same names.
- Whether to send a licence enquiry to any of the candidates above.
