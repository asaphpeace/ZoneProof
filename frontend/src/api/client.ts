// Same-origin '/api' by default (nginx, Vite proxy, CloudFront behaviour). Set VITE_API_BASE at build time to point at a separate API origin.
export const API_BASE: string = ((import.meta as any).env?.VITE_API_BASE as string | undefined)?.replace(/\/+$/, '') || '/api'
const BASE = API_BASE

let _token: string | null = localStorage.getItem('sentinel_token')

export function setToken(t: string) {
  _token = t
  localStorage.setItem('sentinel_token', t)
}
export function clearToken() {
  _token = null
  localStorage.removeItem('sentinel_token')
}
export function getToken() { return _token }

// Emitted when the backend returns 403 upgrade_required — components listen
// for this to show an upgrade prompt without coupling to the API layer.
export const upgradeRequired = {
  _handlers: [] as Array<(detail: { code: string; message: string; current_plan: string }) => void>,
  on(fn: (detail: any) => void) { this._handlers.push(fn) },
  off(fn: (detail: any) => void) { this._handlers = this._handlers.filter(h => h !== fn) },
  emit(detail: any) { this._handlers.forEach(h => h(detail)) },
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' }
  if (_token) headers['Authorization'] = `Bearer ${_token}`
  const res = await fetch(`${BASE}${path}`, { ...init, headers: { ...headers, ...(init.headers as Record<string,string> || {}) } })
  if (res.status === 401) { clearToken(); window.location.href = '/login'; throw new Error('Unauthorized') }
  if (!res.ok) {
    const e = await res.json().catch(() => ({}))
    const detail = e.detail
    // Surface upgrade prompts globally so any component that hits a limit
    // gets a consistent upgrade CTA without each one handling 403 manually.
    if (res.status === 403 && detail && typeof detail === 'object' && detail.upgrade_required) {
      upgradeRequired.emit(detail)
    }
    throw new Error(typeof detail === 'string' ? detail : detail?.message || res.statusText)
  }
  if (res.status === 204 || res.headers.get('content-length') === '0') return undefined as T
  return res.json()
}

export const api = {
  // Auth
  login: (email: string, password: string) =>
    request<any>('/auth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ username: email, password }),
    }),

  register: (email: string, password: string, fullName?: string, workspaceName?: string, termsAccepted = false) =>
    request<any>('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email, password, full_name: fullName, workspace_name: workspaceName, terms_accepted: termsAccepted }),
    }),

  // Overview
  overview: () => request<any>('/overview'),
  threatSurface: (days = 30) => request<any>(`/overview/threat-surface?days=${days}`),
  readinessRollup: () => request<any>('/overview/readiness-rollup'),
  allCerts: () => request<any[]>('/overview/certs'),
  reportData: (periodDays = 30) => request<any>(`/overview/report-data?period_days=${periodDays}`),

  // Domains
  domains: () => request<any[]>('/domains'),
  domain: (id: string) => request<any>(`/domains/${id}`),
  deleteDomain: (id: string) => request<any>(`/domains/${id}`, { method: 'DELETE' }),
  syncDomainDns: (id: string) => request<any>(`/domains/${id}/sync-dns`, { method: 'POST' }),
  domainRecommendations: (id: string) => request<any[]>(`/domains/${id}/recommendations`),
  simulateDmarcPolicy: (id: string) => request<any>(`/domains/${id}/simulate-policy`),
  sourcesHealth: () => request<any>('/sources/health'),
  discoverSubdomains: (id: string) => request<{ subdomains: any[]; sources: Record<string, string>; coverage: any | null }>(`/domains/${id}/discover-subdomains`),
  setSubdomainDisposition: (id: string, hostname: string, disposition: string, reason?: string) =>
    request<any>(`/domains/${id}/subdomain-dispositions`, {
      method: 'POST',
      body: JSON.stringify({ hostname, disposition, reason: reason ?? null }),
    }),
  registrarInstructions: (id: string) => request<any>(`/domains/${id}/registrar-instructions`),
  checkDnsLive: (id: string, recordType: string) => request<{ exists: boolean }>(`/domains/${id}/check-dns-live?record_type=${recordType}`),
  emailInstructions: (id: string, toEmail: string, recordType: string) =>
    request<{ sent: boolean }>(`/domains/${id}/email-instructions`, {
      method: 'POST',
      body: JSON.stringify({ to_email: toEmail, record_type: recordType }),
    }),
  // Audit log (Enterprise only)
  auditLog: (limit = 50, offset = 0, days = 30) => request<any[]>(`/audit-log?limit=${limit}&offset=${offset}&days=${days}`),
  auditLogCount: (days = 30) => request<{ count: number }>(`/audit-log/count?days=${days}`),

  // Wizard — one domain per call, backend expects { names: [...] } and returns array
  wizardStart:   (domain: string) => request<any[]>('/domains/wizard/start',    { method: 'POST', body: JSON.stringify({ names: [domain] }) }).then(r => r[0]),
  wizardTlsInfo: (domain: string) => request<any[]>('/domains/wizard/tls-info', { method: 'POST', body: JSON.stringify({ names: [domain] }) }).then(r => r[0]),
  wizardConfirm: (domain: string) => request<any>('/domains/wizard/confirm',    { method: 'POST', body: JSON.stringify({ names: [domain] }) }),
  wizardAbort:   (names: string[]) => request<void>('/domains/wizard/abort',    { method: 'POST', body: JSON.stringify({ names }) }),
  wizardDetectPlatforms: (domain: string) => request<{ detected: string[]; mimecast_detected: boolean }>('/domains/wizard/detect-platforms', { method: 'POST', body: JSON.stringify({ domain }) }),

  // DMARC
  dmarcData: (domainId: string, opts: { fromDate?: string | null, toDate?: string | null, days?: number } = {}) => {
    const p = new URLSearchParams()
    if (opts.fromDate) p.set('from_date', opts.fromDate)
    if (opts.toDate)   p.set('to_date',   opts.toDate)
    if (!opts.fromDate && opts.days) p.set('days', String(opts.days))
    const qs = p.toString()
    return request<any>(`/domains/${domainId}/dmarc${qs ? '?' + qs : ''}`)
  },
  dmarcHistogram:     (domainId: string) => request<any>(`/domains/${domainId}/dmarc/histogram`),
  dmarcRecordDiff:    (domainId: string) => request<any>(`/domains/${domainId}/dmarc/record-diff`),
  dmarcMarkPublished: (domainId: string) => request<any>(`/domains/${domainId}/dmarc/mark-published`, { method: 'POST' }),

  // TLS
  tlsData:          (domainId: string, days = 30) => request<any>(`/domains/${domainId}/tls?days=${days}`),
  tlsRecordDiff:    (domainId: string) => request<any>(`/domains/${domainId}/tls/record-diff`),
  tlsMarkPublished: (domainId: string) => request<any>(`/domains/${domainId}/tls/mark-published`, { method: 'POST' }),
  tlsDomainSummary: () => request<any[]>('/overview/tls-summary'),
  setMtaStsHostingMode: (domainId: string, mode: 'self' | 'managed') =>
    request<any>(`/domains/${domainId}/mta-sts/hosting-mode`, { method: 'POST', body: JSON.stringify({ mode }) }),
  mtaStsHostingStatus: (domainId: string) => request<any>(`/domains/${domainId}/mta-sts/hosting-status`),

  // Certs
  certs:      (domainId: string) => request<any[]>(`/domains/${domainId}/certs`),
  probeCerts: (domainId: string) => request<any>(`/domains/${domainId}/certs/probe`, { method: 'POST' }),

  // DNS — days=null means all time (no cutoff)
  dnsTimeline:       (domainId: string, limit = 50, offset = 0, days: number | null = null) => {
    const p = new URLSearchParams({ limit: String(limit), offset: String(offset) })
    if (days !== null) p.set('days', String(days))
    return request<any[]>(`/domains/${domainId}/dns-timeline?${p}`)
  },
  dnsTimelineCount:  (domainId: string, days: number | null = null) => {
    const p = days !== null ? `?days=${days}` : ''
    return request<any>(`/domains/${domainId}/dns-timeline/count${p}`)
  },
  dnsTenantTimeline: (limit = 100, offset = 0, days: number | null = null) => {
    const p = new URLSearchParams({ limit: String(limit), offset: String(offset) })
    if (days !== null) p.set('days', String(days))
    return request<any[]>(`/tenant/dns-timeline?${p}`)
  },
  dnsTenantCount:    (days: number | null = null) => {
    const p = days !== null ? `?days=${days}` : ''
    return request<any>(`/tenant/dns-timeline/count${p}`)
  },

  // Concept Cards
  conceptRender: (id: string, context: Record<string, any> = {}) =>
    request<any>(`/concepts/${id}/render`, { method: 'POST', body: JSON.stringify({ context }) }),
  conceptMarkSeen: (id: string) => request<any>(`/concepts/${id}/seen`, { method: 'POST' }),
  conceptsAll: () => request<any[]>('/concepts'),

  // Alerts
  alerts: () => request<any[]>('/alerts'),
  markAlertRead: (id: string) => request<any>(`/alerts/${id}/read`, { method: 'POST' }),

  // Sending platforms
  platformCatalog: () => request<any[]>(`/platforms/catalog`),
  platformStatus: (domainId: string) => request<any[]>(`/domains/${domainId}/platforms/status`),
  declarePlatform: (domainId: string, platformKey: string, customName?: string) => {
    const q = customName ? `?custom_name=${encodeURIComponent(customName)}` : ''
    return request<any>(`/domains/${domainId}/platforms/${platformKey}/declare${q}`, { method: 'POST' })
  },
  removePlatform: (domainId: string, platformKey: string) =>
    request<any>(`/domains/${domainId}/platforms/${platformKey}`, { method: 'DELETE' }),
  platformSetupCard: (domainId: string, platformKey: string) =>
    request<any>(`/domains/${domainId}/platforms/${platformKey}/setup`),
  emailPlatformInstructions: (domainId: string, platformKey: string, toEmail: string) =>
    request<{ ok: boolean }>(`/domains/${domainId}/platforms/${platformKey}/email-instructions`, {
      method: 'POST',
      body: JSON.stringify({ to_email: toEmail }),
    }),

  // Public scan
  scanDomain: (domain: string) =>
    request<any>('/scan', { method: 'POST', body: JSON.stringify({ domain }) }),

  // Advisor
  // force=true bypasses the unchanged-data guard — pass it only from an
  // explicit "Regenerate" click, never from the passive auto-refresh that
  // fires after a cached page load (that one should skip the API call
  // when nothing changed, to preserve Claude usage).
  advisor: (screen: string, domainId?: string, cachedOnly?: boolean, force?: boolean) => {
    const q = new URLSearchParams({ screen })
    if (domainId) q.set('domain_id', domainId)
    if (cachedOnly) q.set('cached_only', 'true')
    if (force) q.set('force', 'true')
    return request<any>(`/advisor?${q}`)
  },
  advisorChat: (message: string, history: { role: string; content: string }[], screen: string, domainId?: string) =>
    request<{ reply: string; model: string; citations: string[] }>('/advisor/chat', {
      method: 'POST',
      body: JSON.stringify({ message, history, screen, domain_id: domainId ?? null }),
    }),
  advisorCertSummary: (domainId?: string, cachedOnly?: boolean, force?: boolean) => {
    const q = new URLSearchParams()
    if (domainId) q.set('domain_id', domainId)
    if (cachedOnly) q.set('cached_only', 'true')
    if (force) q.set('force', 'true')
    const qs = q.toString()
    return request<any>(`/advisor/cert-summary${qs ? '?' + qs : ''}`)
  },
  advisorDnsSummary: (domainId?: string, cachedOnly?: boolean, force?: boolean) => {
    const q = new URLSearchParams()
    if (domainId) q.set('domain_id', domainId)
    if (cachedOnly) q.set('cached_only', 'true')
    if (force) q.set('force', 'true')
    const qs = q.toString()
    return request<any>(`/advisor/dns-summary${qs ? '?' + qs : ''}`)
  },
  regenerateNarrative: () => request<any>('/overview/narrative/regenerate', { method: 'POST' }),

  // Billing
  billingPlans:    () => request<any[]>('/billing/plans'),
  billingStatus:   () => request<any>('/billing/status'),
  updateReportSchedule: (schedule: 'off' | 'weekly' | 'monthly') =>
    request<any>('/billing/report-schedule', { method: 'PATCH', body: JSON.stringify({ schedule }) }),
  changePlan:      (plan: string) => request<any>('/billing/plan', { method: 'POST', body: JSON.stringify({ plan }) }),
  billingCheckout: (plan: string, billing_cycle: string) => request<{ checkout_url: string; session_id: string }>('/billing/checkout', { method: 'POST', body: JSON.stringify({ plan, billing_cycle }) }),
  billingPortal:   () => request<{ portal_url: string }>('/billing/portal', { method: 'POST' }),

  // Team / invites
  team:          () => request<any[]>('/auth/team'),
  invites:       () => request<any[]>('/auth/invites'),
  createInvite:  (email: string, role: string) => request<any>('/auth/invite', { method: 'POST', body: JSON.stringify({ email, role }) }),
  revokeInvite:  (id: string) => request<any>(`/auth/invite/${id}`, { method: 'DELETE' }),
  getInvite:     (token: string) => request<any>(`/auth/invite/${token}`),
  acceptInvite:  (token: string, full_name: string, password: string, terms_accepted: boolean) =>
    request<any>('/auth/accept-invite', { method: 'POST', body: JSON.stringify({ token, full_name, password, terms_accepted }) }),
  updateMember:  (id: string, patch: any) => request<any>(`/auth/team/${id}`, { method: 'PATCH', body: JSON.stringify(patch) }),
  removeMember:  (id: string) => request<any>(`/auth/team/${id}`, { method: 'DELETE' }),
  verifyOwnership: (domainId: string) => request<any>(`/domains/${domainId}/verify-ownership`, { method: 'POST' }),

  twoFaChallenge: (pre_auth_token: string, code: string) =>
    request<any>('/auth/2fa/challenge', { method: 'POST', body: JSON.stringify({ pre_auth_token, code }) }),

  // Profile / account
  me:             () => request<any>('/auth/me'),
  updateMe:       (patch: any) => request<any>('/auth/me', { method: 'PATCH', body: JSON.stringify(patch) }),
  changePassword: (current_password: string, new_password: string) =>
    request<void>('/auth/change-password', { method: 'POST', body: JSON.stringify({ current_password, new_password }) }),
  forgotPassword: (email: string) =>
    request<{ message: string }>('/auth/forgot-password', { method: 'POST', body: JSON.stringify({ email }) }),
  resetPassword: (token: string, new_password: string) =>
    request<void>('/auth/reset-password', { method: 'POST', body: JSON.stringify({ token, new_password }) }),
  verifyEmail: (token: string) =>
    request<void>('/auth/verify-email', { method: 'POST', body: JSON.stringify({ token }) }),
  resendVerification: () =>
    request<void>('/auth/resend-verification', { method: 'POST' }),
  sendTestEmail: () =>
    request<void>('/auth/send-test-email', { method: 'POST' }),
  deleteAccount:  () => request<void>('/auth/account', { method: 'DELETE' }),
  enable2fa:      () => request<any>('/auth/2fa/enable', { method: 'POST' }),
  verify2fa:      (code: string) => request<void>('/auth/2fa/verify', { method: 'POST', body: JSON.stringify({ code }) }),
  disable2fa:     (code: string) => request<void>('/auth/2fa/disable', { method: 'POST', body: JSON.stringify({ code }) }),

  // MSP
  mspBrandRollup:  () => request<{ clients: any[]; totals: any }>('/msp/brand-guard'),
  mspClientBrandCases: (clientId: string) => request<any[]>(`/msp/clients/${clientId}/brand-guard/cases`),
  /** White-label evidence pack for a client's look-alike, downloaded as a file. */
  mspClientEvidencePack: async (clientId: string, candidateId: string, format: 'pdf' | 'json') => {
    const res = await fetch(`${BASE}/msp/clients/${clientId}/brand-guard/candidates/${candidateId}/evidence-pack?format=${format}`, { headers: _token ? { Authorization: `Bearer ${_token}` } : {} })
    if (res.status === 401) { clearToken(); window.location.href = '/login'; throw new Error('Unauthorized') }
    if (!res.ok) { const e = await res.json().catch(() => ({})); throw new Error(typeof e.detail === 'string' ? e.detail : e.detail?.message || 'Could not build the evidence pack') }
    const name = /filename="([^"]+)"/.exec(res.headers.get('content-disposition') || '')?.[1] ?? `evidence.${format}`
    const url = URL.createObjectURL(await res.blob())
    const a = document.createElement('a')
    a.href = url
    a.download = name
    a.click()
    URL.revokeObjectURL(url)
  },
  mspClients:      () => request<any[]>('/msp/clients'),
  mspCreateClient: (payload: any) => request<any>('/msp/clients', { method: 'POST', body: JSON.stringify(payload) }),
  mspGetClient:    (id: string) => request<any>(`/msp/clients/${id}`),
  mspUpdateClient: (id: string, patch: any) => request<any>(`/msp/clients/${id}`, { method: 'PATCH', body: JSON.stringify(patch) }),
  mspDeleteClient: (id: string) => request<void>(`/msp/clients/${id}`, { method: 'DELETE' }),
  mspInviteToClient: (clientId: string, payload: any) => request<any>(`/msp/clients/${clientId}/invite`, { method: 'POST', body: JSON.stringify(payload) }),

  // Brand Guard
  brandGuardSummary:   (profileId?: string) => request<any>(`/brand-guard/summary${profileId ? `?profile_id=${profileId}` : ''}`),
  brandProfiles:       () => request<any[]>('/brand-guard/profiles'),
  brandCreateProfile:  (payload: any) => request<any>('/brand-guard/profiles', { method: 'POST', body: JSON.stringify(payload) }),
  brandUpdateProfile:  (id: string, patch: any) => request<any>(`/brand-guard/profiles/${id}`, { method: 'PATCH', body: JSON.stringify(patch) }),
  brandDeleteProfile:  (id: string) => request<void>(`/brand-guard/profiles/${id}`, { method: 'DELETE' }),
  brandScan:           (id: string) => request<any>(`/brand-guard/profiles/${id}/scan`, { method: 'POST' }),
  brandFingerprint:    (id: string) => request<any>(`/brand-guard/profiles/${id}/fingerprint`, { method: 'POST' }),
  brandSources:        () => request<any[]>('/brand-guard/sources'),
  brandScanRun:        (runId: string) => request<any>(`/brand-guard/scan-runs/${runId}`),
  brandCandidates:     (params: { profile_id?: string; status?: string; assigned_to?: string; limit?: number } = {}) => {
    const q = new URLSearchParams(Object.entries(params).filter(([, v]) => v).map(([k, v]) => [k, String(v)] as [string, string])).toString()
    return request<any[]>(`/brand-guard/candidates${q ? `?${q}` : ''}`)
  },
  brandCampaigns:      (profileId?: string) => request<any[]>(`/brand-guard/campaigns${profileId ? `?profile_id=${profileId}` : ''}`),
  brandCampaign:       (id: string) => request<any>(`/brand-guard/campaigns/${id}`),
  brandCampaignRemove: (id: string, candidateId: string) => request<void>(`/brand-guard/campaigns/${id}/members/${candidateId}/remove`, { method: 'POST' }),
  brandCandidate:      (id: string) => request<any>(`/brand-guard/candidates/${id}`),
  brandAssign:         (id: string, userId: string | null) => request<any>(`/brand-guard/candidates/${id}/assignee`, { method: 'PATCH', body: JSON.stringify({ user_id: userId }) }),
  /** Downloads the hash-stamped evidence pack as a file (the API sends it as an attachment, so it cannot go through request()). */
  brandEvidencePack:   async (id: string, format: 'pdf' | 'json') => {
    const res = await fetch(`${BASE}/brand-guard/candidates/${id}/evidence-pack?format=${format}`, { headers: _token ? { Authorization: `Bearer ${_token}` } : {} })
    if (res.status === 401) { clearToken(); window.location.href = '/login'; throw new Error('Unauthorized') }
    if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || 'Could not build the evidence pack')
    const name = /filename="([^"]+)"/.exec(res.headers.get('content-disposition') || '')?.[1] ?? `evidence.${format}`
    const url = URL.createObjectURL(await res.blob())
    const a = document.createElement('a')
    a.href = url
    a.download = name
    a.click()
    URL.revokeObjectURL(url)
  },
  brandTakedownRoutes: (id: string) => request<{ routes: any[] }>(`/brand-guard/candidates/${id}/takedown-routes`),
  brandTakedowns:      (id: string) => request<any[]>(`/brand-guard/candidates/${id}/takedowns`),
  brandTakedownCreate: (id: string, route: any) => request<any>(`/brand-guard/candidates/${id}/takedowns`, { method: 'POST', body: JSON.stringify({ route }) }),
  brandTakedownEdit:   (id: string, subject: string, body: string) => request<any>(`/brand-guard/takedowns/${id}`, { method: 'PATCH', body: JSON.stringify({ subject, body }) }),
  brandTakedownMove:   (id: string, status: string, note?: string) => request<any>(`/brand-guard/takedowns/${id}/status`, { method: 'POST', body: JSON.stringify({ status, note }) }),
  /** The rule file as text (for preview or copy). Not audit-logged: nothing leaves the product until it is downloaded. */
  brandBlocklist: async (format: string, include: string, profileId?: string, _download = false) => {
    const q = new URLSearchParams({ format, include, ...(profileId ? { profile_id: profileId } : {}) })
    const res = await fetch(`${BASE}/brand-guard/blocklist?${q}`, { headers: _token ? { Authorization: `Bearer ${_token}` } : {} })
    if (res.status === 401) { clearToken(); window.location.href = '/login'; throw new Error('Unauthorized') }
    if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || 'Could not build the list')
    return { text: await res.text(), count: Number(res.headers.get('x-entry-count') || 0) }
  },
  brandBlocklistDownload: async (format: string, include: string, profileId?: string) => {
    const q = new URLSearchParams({ format, include, download: 'true', ...(profileId ? { profile_id: profileId } : {}) })
    const res = await fetch(`${BASE}/brand-guard/blocklist?${q}`, { headers: _token ? { Authorization: `Bearer ${_token}` } : {} })
    if (res.status === 401) { clearToken(); window.location.href = '/login'; throw new Error('Unauthorized') }
    if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || 'Could not build the list')
    const name = /filename="([^"]+)"/.exec(res.headers.get('content-disposition') || '')?.[1] ?? `blocklist.${format}`
    const url = URL.createObjectURL(await res.blob())
    const a = document.createElement('a')
    a.href = url
    a.download = name
    a.click()
    URL.revokeObjectURL(url)
  },
  brandDefensive:      (profileId: string) => request<any>(`/brand-guard/defensive-registrations?profile_id=${profileId}`),
  brandReportLinks:    (id: string) => request<any[]>(`/brand-guard/candidates/${id}/report-links`),
  brandSubmissionCreate: (id: string, service: string) => request<any>(`/brand-guard/candidates/${id}/submissions`, { method: 'POST', body: JSON.stringify({ service }) }),
  brandSubmissionMove: (id: string, status: string, note?: string) => request<any>(`/brand-guard/submissions/${id}/status`, { method: 'POST', body: JSON.stringify({ status, note }) }),
  brandChannels:       () => request<any[]>('/brand-guard/notification-channels'),
  brandChannelCreate:  (body: any) => request<any>('/brand-guard/notification-channels', { method: 'POST', body: JSON.stringify(body) }),
  brandChannelUpdate:  (id: string, body: any) => request<any>(`/brand-guard/notification-channels/${id}`, { method: 'PATCH', body: JSON.stringify(body) }),
  brandChannelDelete:  (id: string) => request<void>(`/brand-guard/notification-channels/${id}`, { method: 'DELETE' }),
  brandChannelTest:    (id: string) => request<{ ok: boolean; error: string | null }>(`/brand-guard/notification-channels/${id}/test`, { method: 'POST' }),
  brandNotificationLog: () => request<any[]>('/brand-guard/notification-log'),
  brandSiemExport: async (format: 'jsonl' | 'cef') => {
    const res = await fetch(`${BASE}/brand-guard/siem-export?format=${format}`, { headers: _token ? { Authorization: `Bearer ${_token}` } : {} })
    if (res.status === 401) { clearToken(); window.location.href = '/login'; throw new Error('Unauthorized') }
    if (!res.ok) { const e = await res.json().catch(() => ({})); throw new Error(typeof e.detail === 'string' ? e.detail : e.detail?.message || 'Could not export') }
    const url = URL.createObjectURL(await res.blob())
    const a = document.createElement('a')
    a.href = url
    a.download = `zoneproof-brand-guard-${new Date().toISOString().slice(0, 10)}.${format === 'cef' ? 'cef' : 'jsonl'}`
    a.click()
    URL.revokeObjectURL(url)
  },
  brandTimeline:       (id: string) => request<any>(`/brand-guard/candidates/${id}/timeline`),
  /** How many items entered and left each stage of Brand Guard (counts only), for one brand or all of them. */
  brandFunnel:         (days = 30, profileId?: string) => request<any>(`/brand-guard/funnel?days=${days}${profileId ? `&profile_id=${profileId}` : ''}`),
  /** What the sandboxed renderer saw on this look-alike's page (facts and a text excerpt), or { available: false }. */
  brandCapture:        (id: string) => request<any>(`/brand-guard/candidates/${id}/capture`),
  /** The captured screenshot as an object URL for an <img> (an <img> cannot send the login token itself). The caller revokes it. */
  brandCaptureImage:   async (id: string): Promise<string | null> => {
    const res = await fetch(`${BASE}/brand-guard/candidates/${id}/capture/screenshot`, { headers: _token ? { Authorization: `Bearer ${_token}` } : {} })
    if (res.status === 401) { clearToken(); window.location.href = '/login'; throw new Error('Unauthorized') }
    if (!res.ok) return null
    const blob = await res.blob()
    return blob.type.startsWith('image/') ? URL.createObjectURL(blob) : null
  },
  /** The customer's own page as the renderer saw it, for the side-by-side comparison. Same rules as brandCaptureImage. */
  brandReferenceImage: async (profileId: string): Promise<string | null> => {
    const res = await fetch(`${BASE}/brand-guard/profiles/${profileId}/reference/screenshot`, { headers: _token ? { Authorization: `Bearer ${_token}` } : {} })
    if (res.status === 401) { clearToken(); window.location.href = '/login'; throw new Error('Unauthorized') }
    if (!res.ok) return null
    const blob = await res.blob()
    return blob.type.startsWith('image/') ? URL.createObjectURL(blob) : null
  },
  brandSetStatus:      (id: string, status: string, note?: string) =>
    request<any>(`/brand-guard/candidates/${id}/status`, { method: 'PATCH', body: JSON.stringify({ status, note }) }),

  // Generic escape hatches for one-off requests
  get:  <T = any>(path: string) => request<T>(path),
  post: <T = any>(path: string, body: any) => request<T>(path, { method: 'POST', body: JSON.stringify(body) }),
}
