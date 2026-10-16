// Labels and small helpers shared by the Brand Guard pages and the candidate drawer.

export const CLASS_LABEL: Record<string, string> = {
  homoglyph: 'Look-alike characters', combosquat: 'Brand + keyword', tld_swap: 'Different TLD', typo: 'Typo-squat',
  cctld_mimic: 'Fake .co.za', word_order: 'Words reordered', soundsquat: 'Sounds alike', bitsquat: 'Bit-squat',
  subdomain_abuse: 'Brand in subdomain',
}

// How we found it. Only what we actually do; page content and the like are not sources yet.
export const FOUND_VIA: Record<string, string> = {
  ct_log: 'Certificate', ct_stream: 'Live certificate', new_registration: 'New registration', reported_email: 'Reported email', permutation: 'Name variation',
}

export const BADGE_HELP: Record<string, string> = {
  blocklist: 'Listed by a public abuse feed (phishunt.io or abuse.ch URLhaus).',
  reported: 'Appeared in an email your own people forwarded to your report address.',
  spoofer: 'Its server is on the same address or network as a sender that failed authentication pretending to be your domain (from your DMARC reports).',
  popular: 'This look-alike is itself a well-known site, so it is probably an unrelated business.',
  parked: 'Parked for sale or ads, or locked so nobody can send mail as it.',
  yours: 'Sits on your own nameservers or server, so it is probably yours.',
}

// Detection ladder (what we can observe from public records). Response steps are NOT part of it: they are a person's decision.
export const RUNGS = [
  { key: 'registered', label: 'Registered' },
  { key: 'resolving', label: 'Resolves' },
  { key: 'mail_enabled', label: 'Mail-ready' },
  { key: 'certified', label: 'Certificate' },
] as const

export function rungsFor(stage: string) {
  const at = RUNGS.findIndex(r => r.key === stage)
  return RUNGS.map((r, i) => ({ ...r, on: at >= i, current: at === i }))
}

export const TONE: Record<string, { fg: string; bg: string; bd: string; dashed: boolean; dot: string }> = {
  red: { fg: '#ff8da1', bg: 'rgba(255,77,109,.12)', bd: 'rgba(255,77,109,.4)', dashed: false, dot: 'var(--bad)' },
  amber: { fg: '#f7d27a', bg: 'rgba(245,197,66,.12)', bd: 'rgba(245,197,66,.4)', dashed: false, dot: 'var(--warn)' },
  slate: { fg: 'var(--muted)', bg: 'transparent', bd: 'var(--faint)', dashed: true, dot: 'var(--faint)' },
  green: { fg: 'var(--good)', bg: 'rgba(52,224,161,.1)', bd: 'rgba(52,224,161,.35)', dashed: false, dot: 'var(--good)' },
  indigo: { fg: '#b9c0ff', bg: 'rgba(91,92,240,.14)', bd: 'rgba(91,92,240,.45)', dashed: false, dot: 'var(--indigo)' },
}

// The abuse type as a short chip. Only a public feed or a confirmed report may state it plainly; everything else says "suspected".
export function typeChip(t: any): { text: string; tone: string } | null {
  if (!t || !t.type || t.type === 'unclassified') return null
  const base = String(t.label || t.type)
  if (t.basis === 'reported') return { text: `${base} (reported)`, tone: t.type === 'malware' || t.type === 'phishing' ? 'red' : 'amber' }
  if (t.type === 'benign') return { text: base, tone: 'green' }
  return { text: `Suspected: ${base.toLowerCase()}`, tone: t.type === 'trademark' ? 'slate' : 'amber' }
}

export const SLA_TONE: Record<string, string> = { on_track: 'ok', due_soon: 'warn', breached: 'bad', met: 'ok' }

/** One plain line for a case's response deadline. The hours behind it are an assumed target by urgency, not a measurement. */
export function slaText(sla: any): string {
  if (!sla || !SLA_TONE[sla.state]) return ''
  const h = sla.hours_left
  if (sla.state === 'met') return 'Closed within its target'
  if (sla.state === 'breached') return h == null ? 'Closed after its target' : `Overdue by ${Math.max(1, Math.round(Math.abs(h)))} h`
  const left = h == null ? '' : h < 1 ? 'under an hour left' : `${Math.round(h)} h left`
  return `${sla.state === 'due_soon' ? 'Due soon' : 'On track'}${left ? ': ' + left : ''}`
}

/** What a page probe saw, as plain lines. Facts only; the verdict's weighing of them is elsewhere. */
export function probeLines(p: any): { text: string; tone: 'bad' | 'ok' | 'warn' | 'plain' }[] {
  if (!p) return []
  if (!p.reachable) return [{ text: 'We tried to load its page and could not reach it.', tone: 'plain' }]
  const out: { text: string; tone: 'bad' | 'ok' | 'warn' | 'plain' }[] = []
  if (p.redirects) out.push({ text: `It redirects to ${p.final_host}${p.redirects_to_brand ? ', the brand\'s own site' : ''}.`, tone: p.redirects_to_brand ? 'ok' : 'warn' })
  if (p.title) out.push({ text: `Page title: "${p.title}".`, tone: 'plain' })
  if (p.password_form) out.push({ text: p.offsite_password_form ? 'It asks for a password and sends it to a different site.' : 'It asks for a password.', tone: 'bad' })
  else out.push({ text: 'No password form on the page we saw.', tone: 'plain' })
  if (p.form_after_scripts) out.push({ text: 'The password form only appears after the page\'s scripts run, which a plain page fetch does not show.', tone: 'warn' })
  if (p.favicon_matches_brand) out.push({ text: 'It uses the brand\'s own icon, byte for byte.', tone: 'bad' })
  else if (p.similarity?.icon?.similar) out.push({ text: 'Its icon is a near copy of the brand\'s (re-sized or re-encoded).', tone: 'bad' })
  const w = p.similarity?.wording
  if (w && w.shared >= 0.4) out.push({ text: `${Math.round(w.shared * 100)}% of the wording on its page also appears on the brand's own page.`, tone: 'bad' })
  else if (w) out.push({ text: `Little of its wording (${Math.round(w.shared * 100)}%) matches the brand's own page.`, tone: 'plain' })
  const v = p.similarity?.visual
  if (v?.similar) out.push({ text: 'Its page has the same layout and accent colours as the brand\'s own page. Not scored: a shared layout alone cannot tell a copy from a common template.', tone: 'warn' })
  const c = p.certificate
  if (c) out.push({ text: `Certificate from ${c.issuer ?? 'an unknown issuer'}, ${c.age_days} day(s) old${c.self_signed ? ', self-signed' : ''}${c.expired ? ', expired' : ''}${c.valid_for_host === false ? ', not issued for this name' : ''}.`, tone: c.self_signed || c.expired || c.valid_for_host === false ? 'warn' : 'plain' })
  if (p.challenge_page) out.push({ text: 'The host showed a block or challenge page, so real visitors may see something different.', tone: 'warn' })
  return out
}

const FUNNEL_REASON: Record<string, string> = {
  found_permutation: 'Found by name variations', found_ct_log: 'Found in certificate logs', found_new_registration: 'Found as newly registered',
  found_reported_email: 'Found in reported emails', trimmed_by_plan_budget: 'Cut by your plan\'s scan budget',
  unregistered: 'Not registered', plan_cap: 'Over your plan\'s candidate limit', customer_owned: 'Your own domains',
  probed_recently: 'Visited recently', not_similar_enough: 'Not similar enough yet', daily_cap: 'Daily limit reached',
  not_interesting: 'Nothing interesting on the page', rendered_recently: 'Rendered recently',
  unreachable: 'Page not reachable', worker_error: 'Worker could not fetch it', expired_unclaimed: 'Waited too long (worker down or behind)',
  failed: 'Failed', no_screenshot: 'No screenshot', blank: 'Page rendered blank',
  icon: 'Icon copied', wording: 'Wording copied', layout: 'Same layout and colours',
}

/** A plain-words label for a funnel detail key (`status_suspicious` reads "Now suspicious"; unknown keys are spelled out, not hidden). */
export function funnelReason(key: string): string {
  if (FUNNEL_REASON[key]) return FUNNEL_REASON[key]
  if (key.startsWith('status_')) return 'Now ' + key.slice(7).replace(/_/g, ' ')
  return key.replace(/_/g, ' ').replace(/^./, c => c.toUpperCase())
}

/** Pass rate as a whole percentage, or an en dash when nothing entered the stage (so "no data" is never shown as 0%). */
export function funnelPct(rate: number | null | undefined): string {
  return rate == null ? '–' : `${Math.round(rate * 100)}%`
}

export const STEP_STATUS: Record<string, { label: string; tone: string }> = {
  observed: { label: 'Seen', tone: 'red' }, suspected: { label: 'Suspected', tone: 'amber' },
  not_observed: { label: 'Not seen', tone: 'slate' }, not_checked: { label: 'Cannot check', tone: 'slate' },
}

export function fmtDate(iso: string | null | undefined) {
  return iso ? new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : 'Never'
}

export function fmtShort(iso: string | null | undefined) {
  return iso ? new Date(iso).toLocaleString(undefined, { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' }) : ''
}

export function timeAgo(iso: string | null | undefined) {
  if (!iso) return 'never'
  const mins = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 60000))
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins} min ago`
  const hrs = Math.round(mins / 60)
  return hrs < 48 ? `${hrs} h ago` : `${Math.round(hrs / 24)} days ago`
}

export function humanHours(h: number | null | undefined) {
  if (h === null || h === undefined) return '—'
  if (h < 1) return `${Math.round(h * 60)} min`
  if (h < 48) return `${h < 10 ? h.toFixed(1).replace(/\.0$/, '') : Math.round(h)} h`
  return `${Math.round(h / 24)} days`
}

/** What a decision button changes, in plain words, for the confirmation line. */
export const DECISION_TEXT: Record<string, string> = {
  monitoring: 'Watching', confirmed: 'Confirmed as impersonation', takedown: 'Marked takedown requested',
  customer_owned: 'Marked as yours', partner: 'Marked as a partner', false_positive: 'Marked as unrelated', ignored: 'Ignored',
}
