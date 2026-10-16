<script setup lang="ts">
import { ref } from 'vue'

const activeSection = ref('getting-started')

const sections = [
  { id: 'getting-started', label: 'Getting Started',   num: '01' },
  { id: 'dmarc-guide',     label: 'DMARC Guide',        num: '02' },
  { id: 'mta-sts-guide',   label: 'MTA-STS & TLS',      num: '03' },
  { id: 'certs-ref',       label: 'Certificates',        num: '04' },
  { id: 'dns-timeline',    label: 'DNS Timeline',         num: '05' },
  { id: 'msp-guide',       label: 'MSP Guide',            num: '06' },
  { id: 'api',             label: 'API Reference',        num: '07' },
  { id: 'score-ref',       label: 'ZoneProof Score',       num: '08' },
  { id: 'account-security', label: 'Account & Security',  num: '09' },
  { id: 'audit-log',       label: 'Audit Log',            num: '10' },
]
</script>

<template>
  <div class="docs-wrap">
    <div class="titlerow">
      <div class="crumb">12 / Documentation</div>
      <h1>Documentation</h1>
      <div class="sub">Guides, reference, and implementation walkthroughs for ZoneProof</div>
    </div>

    <div class="docs-layout">
      <nav class="docs-nav">
        <div class="nav-label">Sections</div>
        <div
          v-for="s in sections" :key="s.id"
          :class="['nav-item', activeSection === s.id ? 'active' : '']"
          @click="activeSection = s.id"
        >
          <span class="n">{{ s.num }}</span>{{ s.label }}
        </div>
      </nav>

      <div class="docs-content">

        <!-- ═══════════════════════════════════════════════════════════════════
             01 · Getting Started
             ════════════════════════════════════════════════════════════════ -->
        <template v-if="activeSection === 'getting-started'">
          <div class="section-header">
            <div class="sec-num">01</div>
            <div>
              <h2>Getting Started</h2>
              <p class="sec-sub">Add your first domain, understand what ZoneProof monitors, and read your first score.</p>
            </div>
          </div>

          <div class="doc-block">
            <h3>Creating your account</h3>
            <p>Registering requires agreeing to the Terms of Service and Privacy Policy — your account starts <strong>unverified</strong> until you confirm your email via the link sent at signup. You can use the app immediately either way; verification is a dismissible reminder, not a login gate. See <a href="#" @click.prevent="activeSection = 'account-security'">Account &amp; Security</a> for the full detail on verification, password recovery, and what changing your password does to your active session.</p>
          </div>

          <div class="doc-block">
            <h3>What ZoneProof protects</h3>
            <p>ZoneProof monitors two independent email security standards that address different attack vectors:</p>
            <div class="two-col">
              <div class="info-card">
                <div class="ic-head">DMARC</div>
                <p>Stops domain spoofing — attackers sending email that appears to come from your domain. DMARC tells receiving mail servers what to do with unauthenticated mail: monitor it (<code>p=none</code>), send it to spam (<code>p=quarantine</code>), or reject it outright (<code>p=reject</code>).</p>
              </div>
              <div class="info-card">
                <div class="ic-head">MTA-STS & TLS</div>
                <p>Stops downgrade attacks — interception of inbound email by stripping TLS encryption. MTA-STS tells sending mail servers that they must use TLS to deliver to your mail host and that the certificate must be valid.</p>
              </div>
            </div>
            <p>These two tracks are complementary. DMARC protects your outbound reputation; MTA-STS protects your inbound delivery channel. A fully hardened domain has both at enforcement.</p>
          </div>

          <div class="doc-block">
            <h3>Adding your first domain</h3>
            <p>Click <strong>Add domain</strong> in the sidebar. The wizard runs in three steps:</p>
            <div class="steps">
              <div class="step"><span class="step-num">1</span><div><strong>Enter your domain names.</strong> You can add multiple domains at once. ZoneProof checks whether a DMARC record already exists in DNS.</div></div>
              <div class="step"><span class="step-num">2</span><div><strong>Publish the DMARC record.</strong> ZoneProof generates the exact TXT record to add to your DNS at <code>_dmarc.yourdomain.com</code>. The record includes your unique reporting address so aggregate reports are routed to ZoneProof.</div></div>
              <div class="step"><span class="step-num">3</span><div><strong>Optionally set up MTA-STS.</strong> ZoneProof generates the TLS-RPT and MTA-STS DNS records and the policy file. You can skip this step and return later — DMARC setup is the priority.</div></div>
            </div>
          </div>

          <div class="doc-block">
            <h3>The reporting address</h3>
            <p>Each domain gets a unique address in the form <code>abc123@mailsentry.co.za</code>. This address must appear in the DMARC <code>rua=</code> tag and/or the TLS-RPT <code>rua=</code> tag of your published DNS records. When ZoneProof finds it in DNS, the domain is marked ownership-verified and aggregate reports will be attributed to your workspace.</p>
            <div class="callout info">
              <strong>Why a unique address per domain?</strong> It lets ZoneProof identify which workspace owns which domain without requiring you to log into a third-party report processor. It also enables ownership transfer — if you move a domain between workspaces, you update the address in DNS.
            </div>
            <p>If your DMARC record was published before adding the domain to ZoneProof, add the reporting address to your existing <code>rua=</code> tag as a second address:</p>
            <div class="code-block" tabindex="0" role="region" aria-label="Code example"><pre>v=DMARC1; p=none; rua=mailto:reports@yourdmarc.com,mailto:abc123@mailsentry.co.za;</pre></div>
          </div>

          <div class="doc-block">
            <h3>When data appears</h3>
            <p>DMARC aggregate reports are sent by receiving mail servers (Google, Microsoft, Yahoo, etc.) once every 24 hours covering the previous day's mail. After you publish your DMARC record:</p>
            <div class="timeline-list">
              <div class="tl-row"><span class="tl-time">24–48 hours</span><span>First aggregate reports arrive from major mail providers</span></div>
              <div class="tl-row"><span class="tl-time">3–7 days</span><span>Enough data to see your primary sending sources and their alignment status</span></div>
              <div class="tl-row"><span class="tl-time">30 days</span><span>Sufficient history to make a confident policy advancement decision</span></div>
            </div>
            <p>Until reports arrive, the Analytics page will show no data. This is normal — there is nothing wrong with your setup.</p>
          </div>

          <div class="doc-block">
            <h3>Understanding your first ZoneProof Score</h3>
            <p>The score (0–100) reflects the overall security posture of your domain portfolio across three pillars:</p>
            <div class="pillar-list">
              <div class="pillar"><span class="pl-max">60 pts</span><strong>DMARC enforcement</strong> — where you are on the none → quarantine → reject journey</div>
              <div class="pillar"><span class="pl-max">25 pts</span><strong>MTA-STS enforcement</strong> — whether inbound TLS is required and the quality of delivery</div>
              <div class="pillar"><span class="pl-max">15 pts</span><strong>Certificate health</strong> — whether MX host certificates are valid and not expiring</div>
            </div>
            <p>A new domain starting at <code>p=none</code> with no MTA-STS will score near zero. That's expected. The score exists to track progress, not to judge you on day one.</p>
            <p>See <a href="#" @click.prevent="activeSection = 'score-ref'">ZoneProof Score Reference</a> for the exact point breakdown.</p>
          </div>
        </template>

        <!-- ═══════════════════════════════════════════════════════════════════
             02 · DMARC Implementation Guide
             ════════════════════════════════════════════════════════════════ -->
        <template v-else-if="activeSection === 'dmarc-guide'">
          <div class="section-header">
            <div class="sec-num">02</div>
            <div>
              <h2>DMARC Implementation Guide</h2>
              <p class="sec-sub">Moving from monitoring to full enforcement — the four-stage journey and what to check before each advance.</p>
            </div>
          </div>

          <div class="doc-block">
            <h3>The four stages</h3>
            <div class="stage-cards">
              <div class="stage-card stage-none">
                <div class="sc-head"><span class="sc-badge badge-none">p=none</span> Monitor</div>
                <p>No action is taken on unauthenticated mail. Reports are collected. Anyone can still send email that appears to come from your domain. This is a data-collection phase only — do not stay here longer than necessary.</p>
              </div>
              <div class="stage-card stage-q">
                <div class="sc-head"><span class="sc-badge badge-q">p=quarantine</span> Partial enforcement</div>
                <p>Unauthenticated mail is delivered to the recipient's spam folder. Your legitimate mail is still delivered — senders that pass SPF or DKIM alignment are unaffected. This stage exposes any senders you missed during monitoring.</p>
              </div>
              <div class="stage-card stage-r">
                <div class="sc-head"><span class="sc-badge badge-r">p=reject</span> Full enforcement</div>
                <p>Unauthenticated mail is refused by the receiving server and never delivered. This is the only policy that fully protects your domain against impersonation. Everything before this is preparation.</p>
              </div>
              <div class="stage-card stage-bimi">
                <div class="sc-head"><span class="sc-badge badge-b">p=reject + BIMI</span> Brand indicator</div>
                <p>Once at reject, you can publish a BIMI (Brand Indicators for Message Identification) record. This displays your logo in the sender column of supporting email clients (Gmail, Yahoo). Not yet tracked by ZoneProof but enabled by a clean reject posture.</p>
              </div>
            </div>
          </div>

          <div class="doc-block">
            <h3>SPF alignment explained</h3>
            <p>DMARC checks alignment, not just whether SPF or DKIM passed. Alignment means the domain in the authentication result must match the domain in the message's <code>From:</code> header.</p>
            <div class="two-col">
              <div class="info-card">
                <div class="ic-head good-head">Aligned — passes DMARC</div>
                <p>Envelope-from: <code>noreply@example.com</code><br>Header From: <code>example.com</code><br>→ domains match, SPF alignment passes.</p>
              </div>
              <div class="info-card">
                <div class="ic-head bad-head">Unaligned — fails DMARC</div>
                <p>Envelope-from: <code>bounce@mailchimp.com</code><br>Header From: <code>example.com</code><br>→ domains differ, SPF alignment fails (even though SPF itself passed on mailchimp.com).</p>
              </div>
            </div>
            <p>This is why services like Mailchimp, HubSpot, and SendGrid require separate DKIM configuration — they use their own envelope domain, so DKIM is the only alignment path available.</p>
          </div>

          <div class="doc-block">
            <h3>DKIM setup per ESP</h3>
            <p>Every service that sends on your behalf needs to sign with DKIM using a key scoped to your domain. Where to find this in each platform:</p>
            <div class="esp-table">
              <table>
                <thead><tr><th>Service</th><th>Where to configure</th><th>DNS record type</th></tr></thead>
                <tbody>
                  <tr><td>Google Workspace</td><td>Admin console → Apps → Google Workspace → Gmail → Authenticate email</td><td>TXT at <code>google._domainkey</code></td></tr>
                  <tr><td>Microsoft 365</td><td>Defender portal → Email &amp; collaboration → Policies → DKIM</td><td>Two CNAME records (<code>selector1</code>, <code>selector2</code>)</td></tr>
                  <tr><td>Mailchimp</td><td>Account → Domains → Verify domain → Authenticate</td><td>Two CNAME records</td></tr>
                  <tr><td>HubSpot</td><td>Settings → Website → Domains &amp; URLs → Connect a domain → Email sending domain</td><td>Two CNAME records</td></tr>
                  <tr><td>SendGrid</td><td>Settings → Sender Authentication → Authenticate Your Domain</td><td>Three CNAME records</td></tr>
                  <tr><td>Salesforce / Pardot</td><td>Email Studio → Email → Admin → Sender Authentication Package</td><td>CNAME records provided by Salesforce</td></tr>
                  <tr><td>Mailgun</td><td>Sending → Domains → DNS records</td><td>Two TXT records</td></tr>
                  <tr><td>Postmark</td><td>Account → Sender Signatures → DKIM</td><td>TXT at <code>pm._domainkey</code></td></tr>
                  <tr><td>Klaviyo</td><td>Account → Settings → Domains</td><td>CNAME records</td></tr>
                  <tr><td>ActiveCampaign</td><td>Settings → Advanced → Email authentication</td><td>TXT record provided</td></tr>
                </tbody>
              </table>
            </div>
            <p>After publishing the DNS record, allow 24–48 hours for propagation before checking alignment in the ZoneProof DMARC Analytics view.</p>
          </div>

          <div class="doc-block">
            <h3>The SPF 10-lookup limit</h3>
            <p>SPF has a hard limit of 10 DNS lookups when evaluating a record. Each <code>include:</code> directive counts as one lookup, and some includes nest further includes. Exceeding 10 causes SPF to return <code>permerror</code>, which means SPF fails — regardless of whether the sender is authorised.</p>
            <p><strong>How to diagnose it:</strong> In the DMARC Analytics source table, look for a sender showing SPF alignment failures with an explanation mentioning "too many DNS lookups" or "PermError".</p>
            <p><strong>How to fix it:</strong> Use an SPF flattening tool to resolve all <code>include:</code> directives to their constituent IP ranges and publish them directly. Update the flat record whenever your ESPs change their IP ranges (subscribe to their change notifications).</p>
            <div class="callout warn">
              SPF flattening is a maintenance burden. If you have more than 5 sending services, consider whether all of them still send mail from your domain — decommissioning unused ESPs is simpler than flattening.
            </div>
          </div>

          <div class="doc-block">
            <h3>When to advance policy</h3>
            <p>The safe advancement gate is <strong>95% DMARC compliance for 30 consecutive days</strong>. This means 95 out of every 100 messages sent by your legitimate senders pass DMARC authentication.</p>
            <p>The DMARC record diff view (Roadmap → current domain) shows the gate status. All three gates must be green before advancing:</p>
            <div class="gate-list">
              <div class="gate"><span class="g-ok">✓</span> Primary senders aligned — no authorised sender is failing DMARC</div>
              <div class="gate"><span class="g-ok">✓</span> At least 30 days of report data collected</div>
              <div class="gate"><span class="g-ok">✓</span> Compliance rate ≥ 95% — safe to advance without disrupting legitimate mail</div>
            </div>
            <p>If a sender is still failing alignment, fix that sender first. Advancing policy while senders are misaligned will move their mail to spam (at quarantine) or reject it entirely (at reject).</p>
          </div>

          <div class="doc-block">
            <h3>Subdomain policy</h3>
            <p>The <code>p=</code> tag applies to the organisational domain. Subdomains inherit the parent policy unless you set a separate <code>sp=</code> (subdomain policy) tag.</p>
            <div class="code-block" tabindex="0" role="region" aria-label="Code example"><pre>v=DMARC1; p=reject; sp=quarantine; rua=mailto:abc123@mailsentry.co.za;</pre></div>
            <p>Common scenario: you want strict enforcement on your main domain but a softer policy on subdomains you use for internal tooling that isn't yet aligned. Set <code>sp=quarantine</code> while you fix the subdomain senders, then remove the <code>sp=</code> tag once they're aligned.</p>
            <p>ZoneProof currently tracks the organisational domain policy. Subdomain-specific overrides are visible in the raw DMARC record but are not separately scored.</p>
          </div>
        </template>

        <!-- ═══════════════════════════════════════════════════════════════════
             03 · MTA-STS & TLS Guide
             ════════════════════════════════════════════════════════════════ -->
        <template v-else-if="activeSection === 'mta-sts-guide'">
          <div class="section-header">
            <div class="sec-num">03</div>
            <div>
              <h2>MTA-STS &amp; TLS Guide</h2>
              <p class="sec-sub">Protecting inbound delivery from downgrade attacks and certificate forgery.</p>
            </div>
          </div>

          <div class="doc-block">
            <h3>What MTA-STS protects against</h3>
            <p>DMARC protects your domain's reputation as a sender. MTA-STS protects your domain as a receiver. Without MTA-STS, a network attacker between a sender's mail server and your MX host can:</p>
            <ul class="bullet-list">
              <li>Strip the STARTTLS negotiation (downgrade attack), forcing mail to be delivered in plaintext</li>
              <li>Present a forged certificate for your MX host, intercepting encrypted mail</li>
            </ul>
            <p>MTA-STS solves this by publishing a signed policy that tells senders: "you must use TLS to deliver to my domain, and you must verify the certificate." Senders that support MTA-STS enforce this policy before delivering mail.</p>
            <div class="callout info">
              MTA-STS only protects inbound mail from senders that implement the standard. Major providers (Google, Microsoft, Yahoo) all do. Smaller or legacy servers may not — that's what TLS-RPT reporting reveals.
            </div>
          </div>

          <div class="doc-block">
            <h3>The three components</h3>
            <div class="steps">
              <div class="step">
                <span class="step-num">1</span>
                <div>
                  <strong>MTA-STS DNS record</strong> — a TXT record at <code>_mta-sts.yourdomain.com</code> that signals the policy exists and provides a version/ID for cache busting.
                  <div class="code-block mt8"><pre>v=STSv1; id=20250101120000;</pre></div>
                </div>
              </div>
              <div class="step">
                <span class="step-num">2</span>
                <div>
                  <strong>MTA-STS policy file</strong> — served over HTTPS at <code>https://mta-sts.yourdomain.com/.well-known/mta-sts.txt</code>. Lists your MX hostnames and the enforcement mode.
                  <div class="code-block mt8"><pre>version: STSv1
mode: testing
mx: mail.yourdomain.com
mx: *.protection.outlook.com
max_age: 86400</pre></div>
                </div>
              </div>
              <div class="step">
                <span class="step-num">3</span>
                <div>
                  <strong>TLS-RPT record</strong> — a TXT record at <code>_smtp._tls.yourdomain.com</code> that tells senders where to send TLS delivery reports. These feed the TLS posture view.
                  <div class="code-block mt8"><pre>v=TLSRPTv1; rua=mailto:abc123@mailsentry.co.za;</pre></div>
                </div>
              </div>
            </div>
            <p>ZoneProof generates all three records for you in the Add Domain wizard and in the Roadmap view.</p>
          </div>

          <div class="doc-block">
            <h3>Testing mode vs enforce mode</h3>
            <div class="two-col">
              <div class="info-card">
                <div class="ic-head">mode: testing</div>
                <p>Senders attempt TLS and validate the certificate, but if they fail, they deliver the mail anyway. Violations are reported via TLS-RPT. This is a safe observational mode — no mail is blocked.</p>
                <p>Use this phase to confirm that all your MX hosts present valid, trusted certificates with matching hostnames before you enforce.</p>
              </div>
              <div class="info-card">
                <div class="ic-head">mode: enforce</div>
                <p>Senders that support MTA-STS must use TLS and verify the certificate. If they can't, they queue the mail and retry rather than deliver over an insecure channel. Mail from non-MTA-STS senders is unaffected.</p>
                <p><strong>Do not advance to enforce until your TLS pass rate is stable above 99% and all MX host certificates are valid.</strong></p>
              </div>
            </div>
          </div>

          <div class="doc-block">
            <h3>Reading the TLS posture view</h3>
            <p>The TLS view shows data from TLS-RPT aggregate reports. Key fields:</p>
            <div class="field-list">
              <div class="fl-row"><span class="fl-k">Pass rate</span><span>Percentage of TLS sessions that completed successfully. Below 99% at enforce mode risks delivery failures.</span></div>
              <div class="fl-row"><span class="fl-k">Fail groups</span><span>Failures grouped by MX host and reporting sender. Tells you which MX host is causing failures and which senders are reporting them.</span></div>
              <div class="fl-row"><span class="fl-k">Failure reason</span><span>IANA-standardised reason code (e.g. <code>certificate-expired</code>, <code>starttls-not-supported</code>). See Certificates Reference for meanings.</span></div>
              <div class="fl-row"><span class="fl-k">Severity</span><span><span class="sev-badge sev-critical">critical</span> for certificate-expired or starttls-not-supported; <span class="sev-badge sev-warn">warning</span> for other failures; <span class="sev-badge sev-ok">ok</span> when no failures.</span></div>
            </div>
          </div>

          <div class="doc-block">
            <h3>Common blockers before enforcement</h3>
            <div class="blocker-list">
              <div class="blocker">
                <div class="bl-head">STARTTLS not offered</div>
                <p>Your MX host doesn't advertise the STARTTLS capability. Contact your hosting provider — this is a server configuration change, not a DNS change.</p>
              </div>
              <div class="blocker">
                <div class="bl-head">Hostname mismatch</div>
                <p>The certificate presented by your MX host doesn't cover the hostname in your MTA-STS policy. Either the MX record points to a different host than the certificate covers, or the certificate's SAN list is incomplete. See Certificates Reference.</p>
              </div>
              <div class="blocker">
                <div class="bl-head">Shared hosting MX</div>
                <p>If your MX host is shared infrastructure (e.g. <code>mail.mywebhost.com</code>), you don't control the certificate and may not be able to get a valid cert for your specific hostname. In this case, enforce mode may not be achievable without moving to a dedicated mail service.</p>
              </div>
              <div class="blocker">
                <div class="bl-head">Untrusted certificate</div>
                <p>The certificate chain is not trusted by the public WebPKI root store. Usually means a self-signed cert or an intermediate CA that isn't included in the chain. Replace with a certificate from a public CA (Let's Encrypt is free).</p>
              </div>
            </div>
          </div>

          <div class="doc-block">
            <h3>Safe advancement checklist</h3>
            <p>Before changing <code>mode: testing</code> to <code>mode: enforce</code> in your MTA-STS policy file:</p>
            <div class="gate-list">
              <div class="gate"><span class="g-ok">✓</span> TLS pass rate has been above 99% for at least 14 days</div>
              <div class="gate"><span class="g-ok">✓</span> All MX hosts listed in the policy show certificate status <code>ok</code> in the Certificates view</div>
              <div class="gate"><span class="g-ok">✓</span> No <code>critical</code> severity failures in the last 14 days of TLS-RPT data</div>
              <div class="gate"><span class="g-ok">✓</span> Certificate expiry is more than 30 days away (renew before advancing if not)</div>
              <div class="gate"><span class="g-ok">✓</span> MTA-STS policy file is reachable via HTTPS (test: <code>curl https://mta-sts.yourdomain.com/.well-known/mta-sts.txt</code>)</div>
            </div>
            <p>After switching to enforce, increment the <code>id=</code> value in your MTA-STS DNS record so senders refresh their cached policy.</p>
          </div>
        </template>

        <!-- ═══════════════════════════════════════════════════════════════════
             04 · Certificates Reference
             ════════════════════════════════════════════════════════════════ -->
        <template v-else-if="activeSection === 'certs-ref'">
          <div class="section-header">
            <div class="sec-num">04</div>
            <div>
              <h2>Certificates Reference</h2>
              <p class="sec-sub">Understanding MX host certificate health and what each status means for email delivery.</p>
            </div>
          </div>

          <div class="doc-block">
            <h3>Why certificate health matters</h3>
            <p>A TLS certificate is the proof of identity that your MX host presents when a sender attempts to deliver mail over TLS. In MTA-STS testing mode, certificate failures are logged but mail is delivered anyway. In <strong>enforce mode, a certificate failure causes the sender to queue mail and retry</strong> — it will not deliver over an insecure or unverifiable connection.</p>
            <p>Certificate problems are therefore a delivery risk, not just a monitoring concern.</p>
          </div>

          <div class="doc-block">
            <h3>Certificate statuses</h3>
            <div class="status-list">
              <div class="status-row">
                <span class="status-badge st-ok">ok</span>
                <div>Certificate is valid, trusted, matches the hostname, and has more than 30 days remaining. No action required.</div>
              </div>
              <div class="status-row">
                <span class="status-badge st-soon">expiring_soon</span>
                <div>Certificate expires within 30 days. Renew now — don't wait. Automated renewal (Let's Encrypt / ACME) should have already triggered; check if it failed.</div>
              </div>
              <div class="status-row">
                <span class="status-badge st-crit">critical</span>
                <div>Certificate expires within 7 days. Immediate action required. If you're on MTA-STS enforce, expiry will cause delivery failures at this MX host.</div>
              </div>
              <div class="status-row">
                <span class="status-badge st-exp">expired</span>
                <div>Certificate has expired. If MTA-STS is at enforce, MTA-STS-compliant senders cannot deliver to this MX host until the certificate is replaced. Replace immediately.</div>
              </div>
              <div class="status-row">
                <span class="status-badge st-err">error</span>
                <div>The probe could not connect to the host, could not complete TLS negotiation, or encountered an unhandled error. The host may be down, firewalled, or on a non-standard port. Check connectivity manually.</div>
              </div>
            </div>
          </div>

          <div class="doc-block">
            <h3>Hostname mismatch</h3>
            <p>A hostname mismatch means the certificate presented by the MX host does not include the MX hostname in its Subject Alternative Names (SAN) list or Common Name (CN).</p>
            <p><strong>Example:</strong> Your MX record points to <code>mail.yourdomain.com</code>. The certificate covers <code>*.yourhostingprovider.com</code> but not <code>mail.yourdomain.com</code>. MTA-STS-enforcing senders will refuse to deliver because they cannot verify the identity of the host.</p>
            <p><strong>Resolution options:</strong></p>
            <ul class="bullet-list">
              <li>Add <code>mail.yourdomain.com</code> to the certificate's SAN list (requires control of the certificate)</li>
              <li>Ask your hosting provider to issue a certificate that covers your MX hostname</li>
              <li>Use a mail service that issues certificates matching the hostnames they present (e.g. Google Workspace, Microsoft 365, Fastmail)</li>
            </ul>
            <div class="callout warn">
              The Common Name (CN) field is deprecated for hostname matching in modern TLS. Only the SAN list is checked. A certificate with your hostname only in the CN and not in the SAN will show as a hostname mismatch.
            </div>
          </div>

          <div class="doc-block">
            <h3>Deprecated TLS versions</h3>
            <p>TLS 1.0 and TLS 1.1 are deprecated (RFC 8996). Using them is a security risk — they have known vulnerabilities and cannot be considered secure for mail delivery.</p>
            <p>ZoneProof surfaces the negotiated TLS version for each MX host. If you see <code>TLSv1.0</code> or <code>TLSv1.1</code>:</p>
            <ul class="bullet-list">
              <li>This is a server configuration issue, not a certificate issue</li>
              <li>Contact your mail host or hosting provider to disable TLS 1.0 and 1.1 and enable TLS 1.2 and 1.3</li>
              <li>If you control the server, update the <code>ssl_protocols</code> (Nginx) or <code>SSLProtocol</code> (Apache) directive</li>
            </ul>
          </div>

          <div class="doc-block">
            <h3>STARTTLS</h3>
            <p>STARTTLS is the mechanism by which an SMTP connection upgrades from plaintext to TLS. Your MX host must advertise STARTTLS in its EHLO response for senders to use TLS at all.</p>
            <p>ZoneProof's certificate probe checks whether STARTTLS is supported. If <code>starttls_supported: false</code>:</p>
            <ul class="bullet-list">
              <li>TLS is not available for inbound delivery to this MX host</li>
              <li>MTA-STS enforce mode cannot work — senders will queue and retry indefinitely</li>
              <li>This must be fixed at the mail server level before MTA-STS can be used</li>
            </ul>
          </div>

          <div class="doc-block">
            <h3>Renewal cadence</h3>
            <div class="timeline-list">
              <div class="tl-row"><span class="tl-time">90 days before expiry</span><span>If using Let's Encrypt with auto-renewal (certbot, ACME), renewal attempts should begin around this time</span></div>
              <div class="tl-row"><span class="tl-time">30 days before expiry</span><span>ZoneProof shows <code>expiring_soon</code>. Verify that auto-renewal has succeeded or initiate manual renewal</span></div>
              <div class="tl-row"><span class="tl-time">7 days before expiry</span><span>ZoneProof shows <code>critical</code>. If auto-renewal hasn't fired, renew manually immediately</span></div>
              <div class="tl-row"><span class="tl-time">0 days (expiry)</span><span>ZoneProof shows <code>expired</code>. MTA-STS enforce delivery fails for this host. Replace certificate immediately</span></div>
            </div>
            <p>Set up an out-of-band certificate expiry alert (most CAs and certificate monitoring services provide this) so you have a second warning path independent of ZoneProof.</p>
          </div>
        </template>

        <!-- ═══════════════════════════════════════════════════════════════════
             05 · DNS Timeline Guide
             ════════════════════════════════════════════════════════════════ -->
        <template v-else-if="activeSection === 'dns-timeline'">
          <div class="section-header">
            <div class="sec-num">05</div>
            <div>
              <h2>DNS Timeline Guide</h2>
              <p class="sec-sub">Tracking changes to your email-security DNS records and identifying regressions before they become incidents.</p>
            </div>
          </div>

          <div class="doc-block">
            <h3>What the DNS Timeline audits</h3>
            <p>ZoneProof periodically polls the DNS records that affect your email security posture and logs any changes. The timeline captures:</p>
            <div class="field-list">
              <div class="fl-row"><span class="fl-k">DMARC</span><span>The <code>_dmarc.</code> TXT record — policy changes, rua/ruf tag changes, record removal</span></div>
              <div class="fl-row"><span class="fl-k">SPF</span><span>The root TXT record with <code>v=spf1</code> — additions, removals, modifier changes like <code>+all</code></span></div>
              <div class="fl-row"><span class="fl-k">MX</span><span>Mail exchange records — host changes and priority changes</span></div>
              <div class="fl-row"><span class="fl-k">MTA-STS</span><span>The <code>_mta-sts.</code> TXT record — mode and policy ID changes</span></div>
              <div class="fl-row"><span class="fl-k">TLS-RPT</span><span>The <code>_smtp._tls.</code> TXT record — reporting address changes</span></div>
            </div>
            <p>Each entry records the previous value, the new value, when the change was detected, and an AI-generated risk assessment.</p>
          </div>

          <div class="doc-block">
            <h3>Severity levels</h3>
            <div class="status-list">
              <div class="status-row">
                <span class="status-badge sev-badge sev-critical">critical</span>
                <div>A change that represents a clear security regression. Requires immediate investigation. Examples: DMARC policy downgraded, DMARC record removed, SPF record modified to include <code>+all</code> (allows any sender), MX record removed.</div>
              </div>
              <div class="status-row">
                <span class="status-badge sev-badge sev-warn">warn</span>
                <div>A change that may be intentional but warrants review. Examples: MTA-STS policy ID updated (could be a legitimate version bump or an unauthorised change), SPF record includes added (expanding who can send on your behalf).</div>
              </div>
              <div class="status-row">
                <span class="status-badge sev-badge sev-ok">info</span>
                <div>A routine or low-risk change. Examples: TLS-RPT rua address updated, DMARC rua address updated, MTA-STS max_age changed.</div>
              </div>
            </div>
          </div>

          <div class="doc-block">
            <h3>Critical events and what they mean</h3>
            <div class="blocker-list">
              <div class="blocker">
                <div class="bl-head">DMARC record removed</div>
                <p>Your domain is now completely unprotected. Anyone can send email claiming to be from your domain with no authentication requirement. Either the DNS change was unauthorised (investigate immediately) or it was a mistake (republish the record immediately).</p>
              </div>
              <div class="blocker">
                <div class="bl-head">DMARC policy downgraded</div>
                <p>The policy was changed from a stricter value (e.g. <code>p=reject</code>) to a looser one (e.g. <code>p=none</code>). This restores the ability of unauthenticated senders to deliver mail. Verify this was intentional — a common scenario is a well-meaning administrator "fixing" a delivery issue by removing enforcement.</p>
              </div>
              <div class="blocker">
                <div class="bl-head">SPF record modified to +all</div>
                <p>The SPF record now authorises any IP address to send on your behalf (<code>+all</code> or just <code>all</code> without a qualifier defaults to pass). This completely negates the value of SPF. This is almost never intentional.</p>
              </div>
              <div class="blocker">
                <div class="bl-head">MX record removed</div>
                <p>Your domain no longer has a mail exchanger. Inbound email will bounce. This is either a DNS error or an intentional decision (e.g. migrating to a new mail provider) — in either case it should be tracked.</p>
              </div>
            </div>
          </div>

          <div class="doc-block">
            <h3>Investigating a critical change</h3>
            <p>When a critical change appears in the timeline:</p>
            <div class="steps">
              <div class="step"><span class="step-num">1</span><div><strong>Establish the window.</strong> The timeline shows when ZoneProof detected the change, not necessarily when it was made. DNS TTLs mean the change could have been made hours earlier. Note the detected_at timestamp and work backwards.</div></div>
              <div class="step"><span class="step-num">2</span><div><strong>Check your DNS provider's change log.</strong> Most DNS providers (Cloudflare, Route53, GoDaddy) have an audit log of record changes. Find which user account made the change and when.</div></div>
              <div class="step"><span class="step-num">3</span><div><strong>Cross-reference with your change management records.</strong> Was this change planned? Was it part of a migration or configuration update? If yes, close the investigation. If no, treat it as a potential security incident.</div></div>
              <div class="step"><span class="step-num">4</span><div><strong>Restore if unauthorised.</strong> If the change was not authorised, restore the previous record value immediately. Then investigate how the change was made (compromised credentials, misconfigured automation, social engineering of your DNS provider).</div></div>
            </div>
          </div>

          <div class="doc-block">
            <h3>Regular audit cadence</h3>
            <p>Recommended review schedule:</p>
            <div class="timeline-list">
              <div class="tl-row"><span class="tl-time">Weekly</span><span>Review any new <code>critical</code> or <code>warn</code> entries — takes under 2 minutes if nothing unexpected has changed</span></div>
              <div class="tl-row"><span class="tl-time">Monthly</span><span>Review all <code>info</code> changes and verify they match known infrastructure changes from that month</span></div>
              <div class="tl-row"><span class="tl-time">After any DNS migration</span><span>Review the timeline immediately after migrating DNS providers or changing nameservers to confirm all records transferred correctly</span></div>
            </div>
            <p>The AI advisor on the DNS Timeline view summarises recent changes and flags anything worth attention, so the weekly review can often be done by reading the advisor panel.</p>
          </div>
        </template>

        <!-- ═══════════════════════════════════════════════════════════════════
             06 · MSP Guide
             ════════════════════════════════════════════════════════════════ -->
        <template v-else-if="activeSection === 'msp-guide'">
          <div class="section-header">
            <div class="sec-num">06</div>
            <div>
              <h2>MSP Guide</h2>
              <p class="sec-sub">Managing multiple client workspaces, generating white-label reports, and working with the portfolio view.</p>
            </div>
          </div>

          <div class="doc-block">
            <h3>Plan requirements</h3>
            <p>The MSP features are available on the <strong>MSP</strong> and <strong>Enterprise</strong> plans. The MSP Clients item in the sidebar is only visible on these plans.</p>
            <div class="table-wrap">
              <table>
                <thead><tr><th>Feature</th><th>Free</th><th>Starter</th><th>Pro</th><th>MSP</th><th>Enterprise</th></tr></thead>
                <tbody>
                  <tr><td>Domains</td><td>1</td><td>5</td><td>20</td><td>150 (pooled)</td><td>Unlimited</td></tr>
                  <tr><td>Team members</td><td>1</td><td>3</td><td>Unlimited</td><td>Unlimited</td><td>Unlimited</td></tr>
                  <tr><td>Sub-tenants (clients)</td><td>—</td><td>—</td><td>—</td><td>Unlimited</td><td>Unlimited</td></tr>
                  <tr><td>History</td><td>30 days</td><td>90 days</td><td>180 days</td><td>365 days</td><td>365 days</td></tr>
                  <tr><td>PDF report</td><td>—</td><td>✓</td><td>✓</td><td>✓</td><td>✓</td></tr>
                  <tr><td>White-label report</td><td>—</td><td>—</td><td>—</td><td>✓</td><td>✓</td></tr>
                  <tr><td>API access</td><td>—</td><td>—</td><td>✓</td><td>✓</td><td>✓</td></tr>
                </tbody>
              </table>
            </div>
          </div>

          <div class="doc-block">
            <h3>Multi-tenant architecture</h3>
            <p>In ZoneProof, a <strong>tenant</strong> is a workspace — a billing entity with its own set of domains, users, and data. MSP accounts can create and manage <strong>client tenants</strong> as sub-accounts.</p>
            <p>Data is always strictly separated between tenants. A client tenant's domain data, DMARC reports, TLS data, and certificates are never visible to other tenants — not even to the MSP account unless it explicitly switches into the client's context.</p>
            <p>The MSP account itself is a tenant. Its own domains (if any) are tracked separately from its clients.</p>
          </div>

          <div class="doc-block">
            <h3>Managing client tenants</h3>
            <p>From the <strong>MSP Clients</strong> view you can:</p>
            <ul class="bullet-list">
              <li>Create a new client tenant (give it a name and optional billing email)</li>
              <li>View all clients in a portfolio table with ZoneProof Score, domain count, and cert alert count</li>
              <li>Click into a client to see its full domain detail</li>
              <li>Update a client's name, billing email, or brand settings</li>
              <li>Invite a user directly into a client tenant without that user needing to self-register</li>
              <li>Remove a client tenant (deletes all associated domains and data — irreversible)</li>
            </ul>
            <div class="callout warn">
              Deleting a client tenant deletes all domains, DMARC data, TLS data, certificates, and DNS history for that tenant. This cannot be undone. Export the PDF report before deleting if you need a record.
            </div>
          </div>

          <div class="doc-block">
            <h3>The white-label PDF report</h3>
            <p>The PDF report is the primary deliverable for MSP client communication. It contains:</p>
            <ul class="bullet-list">
              <li>ZoneProof Score with grade and week-over-week delta</li>
              <li>Executive narrative (AI-generated, 3 sentences, board-readable)</li>
              <li>Threat surface summary — impersonation attempts blocked vs exposed</li>
              <li>Per-domain grade table with DMARC stage, MTA-STS stage, compliance rate, and primary issue</li>
              <li>Sender inventory (authorised compliant, authorised non-compliant, unauthorised)</li>
              <li>Prioritised recommendation list with effort/impact ratings</li>
              <li>Score trend chart (last 8 weeks)</li>
            </ul>
            <p>On MSP and Enterprise plans, the report header can be branded with the MSP's name and logo by setting <code>brand_name</code> and <code>brand_logo_url</code> on the client tenant.</p>
            <p>The report is generated on demand from the Overview page (Report button) and from the <code>GET /overview/report-data</code> API endpoint. MSPs typically generate and send one report per client per month.</p>
          </div>

          <div class="doc-block">
            <h3>Portfolio view</h3>
            <p>The MSP Clients list is a portfolio view — a single screen showing the security posture of all client tenants. Each row shows:</p>
            <div class="field-list">
              <div class="fl-row"><span class="fl-k">ZoneProof Score</span><span>0–100 composite score for that client's domains</span></div>
              <div class="fl-row"><span class="fl-k">Grade</span><span>A–F letter grade</span></div>
              <div class="fl-row"><span class="fl-k">Domain count</span><span>Number of active domains in that workspace</span></div>
              <div class="fl-row"><span class="fl-k">DMARC reject count</span><span>How many domains have reached full enforcement</span></div>
              <div class="fl-row"><span class="fl-k">Cert alerts</span><span>Number of domains with certificate issues requiring attention</span></div>
            </div>
            <p>Sort by ZoneProof Score ascending to prioritise which clients need the most attention this month.</p>
          </div>

          <div class="doc-block">
            <h3>Domain pooling on the MSP plan</h3>
            <p>The MSP plan includes 150 domains pooled across all client tenants. A single client can use any number of those 150 domains. There is no per-client domain limit — the limit is on the MSP account's total.</p>
            <p>If you need more than 150 domains total, contact sales for an Enterprise plan or a custom domain add-on.</p>
          </div>

          <div class="doc-block">
            <h3>Client billing: pooled by default, independent if they outgrow you</h3>
            <p>A client tenant starts on the Free plan, billed entirely through your MSP plan's domain pool — most clients never need anything else. But a client tenant is a real, independent workspace, and its own admin can subscribe to their own Starter/Pro/MSP plan directly from their Billing settings, completely separate from your account. This matters for the case where a client outgrows the relationship — they keep their data and history, they just start paying for their own plan instead of drawing from your pool.</p>
            <div class="callout info">
              You're not charged for a client's independent subscription, and they're not charged for being part of your pool — the two billing relationships don't overlap. If you remove a client that has its own active subscription, that subscription is cancelled automatically as part of the removal, so it never keeps billing a card with no account left behind it.
            </div>
            <p>You can't currently see from the MSP Clients list whether a given client has self-upgraded — if this matters for how you manage a relationship, ask the client directly or check with them before assuming their usage is still drawing from your pool.</p>
          </div>

          <div class="doc-block">
            <h3>Onboarding many clients at once</h3>
            <p>Adding domains supports pasting a comma- or newline-separated list, or uploading a CSV/text file directly — see <a href="#" @click.prevent="activeSection = 'account-security'">Account &amp; Security</a> for the exact format. For an MSP bringing on a new client with an existing domain portfolio, this means one import instead of clicking through the wizard once per domain.</p>
          </div>
        </template>

        <!-- ═══════════════════════════════════════════════════════════════════
             07 · API Reference (same as before — preserved)
             ════════════════════════════════════════════════════════════════ -->
        <template v-else-if="activeSection === 'api'">
          <div class="section-header">
            <div class="sec-num">07</div>
            <div>
              <h2>API Reference</h2>
              <p class="sec-sub">REST API for the ZoneProof backend. Base URL: <code>http://localhost:8000</code> (production URL is environment-specific).</p>
            </div>
          </div>

          <div class="doc-block">
            <h3 id="auth">Authentication</h3>
            <p>All protected endpoints require a Bearer token in the <code>Authorization</code> header. Tokens are JWTs signed with HS256 and expire based on your <code>ACCESS_TOKEN_EXPIRE_MINUTES</code> setting (default: 60 minutes).</p>

            <div class="endpoint-card">
              <div class="ep-line"><span class="method post">POST</span><code class="ep-path">/auth/token</code><span class="ep-desc">Obtain an access token</span></div>
              <p class="ep-note">Form-encoded body.</p>
              <div class="code-block" tabindex="0" role="region" aria-label="Code example"><pre>Content-Type: application/x-www-form-urlencoded

username=admin@example.com&password=secret</pre></div>
              <div class="response-label">Response — 200 OK</div>
              <div class="code-block" tabindex="0" role="region" aria-label="Code example"><pre>{
  "access_token": "eyJ...",
  "token_type":   "bearer",
  "user_id":      "uuid",
  "tenant_id":    "uuid",
  "full_name":    "Jane Smith",
  "role":         "admin",
  "workspace_name": "Acme Corp",
  "plan":         "pro"
}</pre></div>
              <div class="ep-note warn">If 2FA is enabled, the response contains <code>pre_auth_token</code> instead. Pass it to <code>POST /auth/2fa/challenge</code> with the authenticator code to complete login.</div>
            </div>

            <div class="endpoint-card">
              <div class="ep-line"><span class="method post">POST</span><code class="ep-path">/auth/2fa/challenge</code><span class="ep-desc">Complete login when 2FA is enabled</span></div>
              <div class="code-block" tabindex="0" role="region" aria-label="Code example"><pre>{ "pre_auth_token": "eyJ...", "code": "123456" }</pre></div>
            </div>

            <div class="endpoint-card">
              <div class="ep-line"><span class="method post">POST</span><code class="ep-path">/auth/register</code><span class="ep-desc">Create a new workspace</span></div>
              <div class="code-block" tabindex="0" role="region" aria-label="Code example"><pre>{ "email": "admin@example.com", "password": "secret", "full_name": "Jane Smith", "workspace_name": "Acme Corp" }</pre></div>
            </div>

            <div class="usage-note"><strong>Using the token</strong><br>Add to every subsequent request:<div class="code-block mt8"><pre>Authorization: Bearer eyJ...</pre></div></div>
          </div>

          <div class="doc-block">
            <h3>Profile &amp; Team</h3>
            <div class="endpoint-card"><div class="ep-line"><span class="method get">GET</span><code class="ep-path">/auth/me</code><span class="ep-desc">Current user and workspace info, including email_verified</span></div></div>
            <div class="endpoint-card"><div class="ep-line"><span class="method patch">PATCH</span><code class="ep-path">/auth/me</code><span class="ep-desc">Update display name or workspace name (admin only for workspace)</span></div></div>
            <div class="endpoint-card"><div class="ep-line"><span class="method get">GET</span><code class="ep-path">/auth/me/export</code><span class="ep-desc">Download a JSON export of account, workspace, team, and domain summary data</span></div></div>
            <div class="endpoint-card"><div class="ep-line"><span class="method get">GET</span><code class="ep-path">/auth/team</code><span class="ep-desc">List all users in the workspace</span></div></div>
            <div class="endpoint-card"><div class="ep-line"><span class="method post">POST</span><code class="ep-path">/auth/invite</code><span class="ep-desc">Send a team invite — returns the invite URL (admin only)</span></div><div class="code-block" tabindex="0" role="region" aria-label="Code example"><pre>{ "email": "colleague@example.com", "role": "viewer" }</pre></div></div>
            <div class="endpoint-card"><div class="ep-line"><span class="method get">GET</span><code class="ep-path">/auth/invite/{'{'}token{'}'}</code><span class="ep-desc">Preview invite details before accepting (workspace name, role, expiry)</span></div></div>
            <div class="endpoint-card"><div class="ep-line"><span class="method post">POST</span><code class="ep-path">/auth/accept-invite</code><span class="ep-desc">Accept an invite and set a password — requires terms_accepted: true</span></div><div class="code-block" tabindex="0" role="region" aria-label="Code example"><pre>{ "token": "...", "full_name": "Jane Smith", "password": "...", "terms_accepted": true }</pre></div></div>
          </div>

          <div class="doc-block">
            <h3>Account recovery &amp; verification</h3>
            <div class="endpoint-card"><div class="ep-line"><span class="method post">POST</span><code class="ep-path">/auth/forgot-password</code><span class="ep-desc">Request a reset link — always returns the same generic message, no email enumeration</span></div><div class="code-block" tabindex="0" role="region" aria-label="Code example"><pre>{ "email": "you@example.com" }</pre></div></div>
            <div class="endpoint-card"><div class="ep-line"><span class="method post">POST</span><code class="ep-path">/auth/reset-password</code><span class="ep-desc">Complete a password reset — single-use token, 30 min expiry</span></div><div class="code-block" tabindex="0" role="region" aria-label="Code example"><pre>{ "token": "...", "new_password": "..." }</pre></div></div>
            <div class="endpoint-card"><div class="ep-line"><span class="method post">POST</span><code class="ep-path">/auth/verify-email</code><span class="ep-desc">Confirm an email address — single-use token, 24h expiry</span></div><div class="code-block" tabindex="0" role="region" aria-label="Code example"><pre>{ "token": "..." }</pre></div></div>
            <div class="endpoint-card"><div class="ep-line"><span class="method post">POST</span><code class="ep-path">/auth/resend-verification</code><span class="ep-desc">Re-issue a verification email (authenticated) — invalidates any prior unused token</span></div></div>
            <div class="ep-note">Both <code>/auth/token</code> and <code>/auth/forgot-password</code> are rate-limited (10/min and 5/min respectively) — repeated calls in quick succession return <code>429</code>.</div>
          </div>

          <div class="doc-block">
            <h3>Domains</h3>
            <div class="endpoint-card"><div class="ep-line"><span class="method get">GET</span><code class="ep-path">/domains</code><span class="ep-desc">List all active domains</span></div></div>
            <div class="endpoint-card"><div class="ep-line"><span class="method get">GET</span><code class="ep-path">/domains/{'{'}domain_id{'}'}</code><span class="ep-desc">Domain detail including policy and policy ID</span></div></div>
            <div class="endpoint-card"><div class="ep-line"><span class="method delete">DELETE</span><code class="ep-path">/domains/{'{'}domain_id{'}'}</code><span class="ep-desc">Deactivate a domain (soft delete)</span></div></div>
            <div class="endpoint-card"><div class="ep-line"><span class="method post">POST</span><code class="ep-path">/domains/{'{'}domain_id{'}'}/sync-dns</code><span class="ep-desc">Re-probe live DNS and update published flags</span></div></div>
            <div class="endpoint-card"><div class="ep-line"><span class="method post">POST</span><code class="ep-path">/domains/{'{'}domain_id{'}'}/verify-ownership</code><span class="ep-desc">Check DNS for the reporting address slug</span></div></div>
            <h4 class="sub-head">Wizard</h4>
            <div class="endpoint-card"><div class="ep-line"><span class="method post">POST</span><code class="ep-path">/domains/wizard/start</code><span class="ep-desc">Step 1 — check DNS, generate DMARC records</span></div><div class="code-block" tabindex="0" role="region" aria-label="Code example"><pre>{ "names": ["example.com"] }</pre></div></div>
            <div class="endpoint-card"><div class="ep-line"><span class="method post">POST</span><code class="ep-path">/domains/wizard/tls-info</code><span class="ep-desc">Step 2 — generate TLS-RPT and MTA-STS records</span></div></div>
            <div class="endpoint-card"><div class="ep-line"><span class="method post">POST</span><code class="ep-path">/domains/wizard/confirm</code><span class="ep-desc">Step 3 — activate domains</span></div><div class="code-block" tabindex="0" role="region" aria-label="Code example"><pre>{ "names": ["example.com"] }</pre></div></div>
            <div class="endpoint-card"><div class="ep-line"><span class="method get">GET</span><code class="ep-path">/domains/{'{'}domain_id{'}'}/recommendations</code><span class="ep-desc">Rule-based advance/hold/regression outcomes for this domain, including HOLD blocking reasons (the alert bell omits HOLD; this endpoint doesn't)</span></div></div>
          </div>

          <div class="doc-block">
            <h3>Overview &amp; ZoneProof Score</h3>
            <div class="endpoint-card"><div class="ep-line"><span class="method get">GET</span><code class="ep-path">/overview</code><span class="ep-desc">Full portfolio summary including ZoneProof Score, per-domain KPIs, cert alerts</span></div></div>
            <div class="endpoint-card"><div class="ep-line"><span class="method get">GET</span><code class="ep-path">/overview/threat-surface</code><span class="ep-desc">Portfolio-wide impersonation attempt summary</span></div><div class="code-block" tabindex="0" role="region" aria-label="Code example"><pre>GET /overview/threat-surface?days=30</pre></div></div>
            <div class="endpoint-card"><div class="ep-line"><span class="method get">GET</span><code class="ep-path">/overview/report-data</code><span class="ep-desc">All data required for the PDF report, as JSON</span></div><div class="code-block" tabindex="0" role="region" aria-label="Code example"><pre>GET /overview/report-data?period_days=30</pre></div></div>
            <div class="endpoint-card"><div class="ep-line"><span class="method get">GET</span><code class="ep-path">/overview/report-pdf</code><span class="ep-desc">The same report data, rendered to an actual PDF (headless Chromium) — what scheduled report emails attach</span></div><div class="code-block" tabindex="0" role="region" aria-label="Code example"><pre>GET /overview/report-pdf?period_days=30</pre></div></div>
            <div class="endpoint-card"><div class="ep-line"><span class="method get">GET</span><code class="ep-path">/overview/certs</code><span class="ep-desc">All SSL/TLS certificates across all domains, sorted by urgency</span></div></div>
            <div class="endpoint-card"><div class="ep-line"><span class="method get">GET</span><code class="ep-path">/overview/tls-summary</code><span class="ep-desc">Per-domain TLS session pass rates</span></div></div>
            <div class="endpoint-card"><div class="ep-line"><span class="method post">POST</span><code class="ep-path">/overview/narrative/regenerate</code><span class="ep-desc">Force-regenerate the AI narrative for the current week</span></div></div>
          </div>

          <div class="doc-block">
            <h3>DMARC Analytics</h3>
            <div class="endpoint-card"><div class="ep-line"><span class="method get">GET</span><code class="ep-path">/domains/{'{'}domain_id{'}'}/dmarc</code><span class="ep-desc">Full DMARC analytics — compliance, sources, IPs, auth details</span></div></div>
            <div class="endpoint-card"><div class="ep-line"><span class="method get">GET</span><code class="ep-path">/domains/{'{'}domain_id{'}'}/dmarc/record-diff</code><span class="ep-desc">Current vs proposed DMARC record with readiness gate checks</span></div></div>
            <div class="endpoint-card"><div class="ep-line"><span class="method get">GET</span><code class="ep-path">/domains/{'{'}domain_id{'}'}/dmarc/sender-recommendations</code><span class="ep-desc">AI-generated per-source fix recommendations</span></div></div>
            <div class="endpoint-card"><div class="ep-line"><span class="method post">POST</span><code class="ep-path">/domains/{'{'}domain_id{'}'}/dmarc/sender-recommendations/{'{'}rec_id{'}'}/dismiss</code><span class="ep-desc">Dismiss a recommendation</span></div></div>
            <div class="endpoint-card"><div class="ep-line"><span class="method post">POST</span><code class="ep-path">/domains/{'{'}domain_id{'}'}/dmarc/mark-published</code><span class="ep-desc">Manually mark DMARC record as published</span></div></div>
          </div>

          <div class="doc-block">
            <h3>TLS &amp; MTA-STS</h3>
            <div class="endpoint-card"><div class="ep-line"><span class="method get">GET</span><code class="ep-path">/domains/{'{'}domain_id{'}'}/tls</code><span class="ep-desc">TLS session overview — pass rate, failure breakdown by MX host and reason</span></div></div>
            <div class="endpoint-card"><div class="ep-line"><span class="method get">GET</span><code class="ep-path">/domains/{'{'}domain_id{'}'}/tls/record-diff</code><span class="ep-desc">Diff of current vs proposed MTA-STS DNS record</span></div></div>
          </div>

          <div class="doc-block">
            <h3>Certificates</h3>
            <div class="endpoint-card"><div class="ep-line"><span class="method get">GET</span><code class="ep-path">/domains/{'{'}domain_id{'}'}/certs</code><span class="ep-desc">List all probed SSL/TLS certificates for the domain's MX hosts</span></div></div>
            <div class="endpoint-card"><div class="ep-line"><span class="method post">POST</span><code class="ep-path">/domains/{'{'}domain_id{'}'}/certs/probe</code><span class="ep-desc">Re-probe all MX hosts and refresh certificate data</span></div></div>
          </div>

          <div class="doc-block">
            <h3>DNS Timeline</h3>
            <div class="endpoint-card"><div class="ep-line"><span class="method get">GET</span><code class="ep-path">/domains/{'{'}domain_id{'}'}/dns-timeline</code><span class="ep-desc">DNS change history for one domain</span></div><div class="code-block" tabindex="0" role="region" aria-label="Code example"><pre>GET /domains/{id}/dns-timeline?limit=50&offset=0</pre></div></div>
            <div class="endpoint-card"><div class="ep-line"><span class="method get">GET</span><code class="ep-path">/tenant/dns-timeline</code><span class="ep-desc">DNS change history across all tenant domains</span></div><div class="code-block" tabindex="0" role="region" aria-label="Code example"><pre>GET /tenant/dns-timeline?limit=100&record_type=DMARC</pre></div></div>
            <div class="endpoint-card"><div class="ep-line"><span class="method get">GET</span><code class="ep-path">/domains/{'{'}domain_id{'}'}/dns-timeline/count</code><span class="ep-desc">Total change count for a domain</span></div></div>
            <div class="endpoint-card"><div class="ep-line"><span class="method get">GET</span><code class="ep-path">/tenant/dns-timeline/count</code><span class="ep-desc">Total change count across all tenant domains</span></div></div>
          </div>

          <div class="doc-block">
            <h3>AI Advisor</h3>
            <div class="endpoint-card">
              <div class="ep-line"><span class="method get">GET</span><code class="ep-path">/advisor</code><span class="ep-desc">Contextual advisory message for a given screen</span></div>
              <div class="code-block" tabindex="0" role="region" aria-label="Code example"><pre>GET /advisor?screen=overview
GET /advisor?screen=dmarc&domain_id=uuid&cached_only=true</pre></div>
              <div class="ep-note"><strong>screen</strong> values: <code>overview</code> · <code>dmarc</code> · <code>tls</code> · <code>posture</code> · <code>posture_dmarc</code> · <code>posture_tls</code> · <code>roadmap</code> · <code>certs</code> · <code>dns_timeline</code></div>
            </div>
            <div class="endpoint-card"><div class="ep-line"><span class="method post">POST</span><code class="ep-path">/advisor/chat</code><span class="ep-desc">Conversational chat grounded in live workspace data</span></div><div class="code-block" tabindex="0" role="region" aria-label="Code example"><pre>{ "message": "Why is Mailchimp failing alignment?", "screen": "dmarc", "domain_id": "uuid", "history": [] }</pre></div></div>
            <div class="endpoint-card"><div class="ep-line"><span class="method get">GET</span><code class="ep-path">/advisor/cert-summary</code><span class="ep-desc">AI certificate posture summary — portfolio or per-domain</span></div></div>
            <div class="endpoint-card"><div class="ep-line"><span class="method get">GET</span><code class="ep-path">/advisor/dns-summary</code><span class="ep-desc">AI DNS timeline change summary</span></div></div>
          </div>

          <div class="doc-block">
            <h3>Billing</h3>
            <div class="endpoint-card"><div class="ep-line"><span class="method get">GET</span><code class="ep-path">/billing/status</code><span class="ep-desc">Current plan, usage against limits, and report_schedule state</span></div></div>
            <div class="endpoint-card"><div class="ep-line"><span class="method post">POST</span><code class="ep-path">/billing/checkout</code><span class="ep-desc">Create a Stripe Checkout session for a paid plan upgrade</span></div></div>
            <div class="endpoint-card"><div class="ep-line"><span class="method post">POST</span><code class="ep-path">/billing/portal</code><span class="ep-desc">Create a Stripe Customer Portal session (manage card, invoices, cancel)</span></div></div>
            <div class="endpoint-card"><div class="ep-line"><span class="method post">POST</span><code class="ep-path">/billing/plan</code><span class="ep-desc">Change plan directly — downgrades and free tier only; paid upgrades go through /billing/checkout</span></div></div>
            <div class="endpoint-card"><div class="ep-line"><span class="method patch">PATCH</span><code class="ep-path">/billing/report-schedule</code><span class="ep-desc">Set automated PDF report delivery — off | weekly | monthly. Requires the scheduled_reports plan feature</span></div><div class="code-block" tabindex="0" role="region" aria-label="Code example"><pre>{ "schedule": "weekly" }</pre></div></div>
            <div class="ep-note">A client tenant created via <code>/msp/clients</code> can call these same endpoints on its own behalf — billing is independent of the parent MSP's plan unless you choose to manage it for them.</div>
          </div>

          <div class="doc-block">
            <h3>MSP</h3>
            <p>Available on MSP and Enterprise plans only. Returns <code>403</code> on other plans.</p>
            <div class="endpoint-card"><div class="ep-line"><span class="method get">GET</span><code class="ep-path">/msp/clients</code><span class="ep-desc">List all client tenants with summary scores</span></div></div>
            <div class="endpoint-card"><div class="ep-line"><span class="method post">POST</span><code class="ep-path">/msp/clients</code><span class="ep-desc">Create a new client tenant</span></div><div class="code-block" tabindex="0" role="region" aria-label="Code example"><pre>{ "name": "Client Co", "billing_email": "billing@client.com", "brand_name": "Client Co IT" }</pre></div></div>
            <div class="endpoint-card"><div class="ep-line"><span class="method get">GET</span><code class="ep-path">/msp/clients/{'{'}id{'}'}</code><span class="ep-desc">Full detail for one client including domains</span></div></div>
            <div class="endpoint-card"><div class="ep-line"><span class="method patch">PATCH</span><code class="ep-path">/msp/clients/{'{'}id{'}'}</code><span class="ep-desc">Update client name, billing email, or brand settings</span></div></div>
            <div class="endpoint-card"><div class="ep-line"><span class="method delete">DELETE</span><code class="ep-path">/msp/clients/{'{'}id{'}'}</code><span class="ep-desc">Remove client tenant and all its data — irreversible. If the client has its own active Stripe subscription, it's cancelled first</span></div></div>
            <div class="endpoint-card"><div class="ep-line"><span class="method post">POST</span><code class="ep-path">/msp/clients/{'{'}id{'}'}/invite</code><span class="ep-desc">Invite a user directly into a client tenant</span></div></div>
          </div>

          <div class="doc-block">
            <h3>Audit Log</h3>
            <p>Available on the Enterprise plan only. Returns <code>403</code> on other plans, and to non-admin users.</p>
            <div class="endpoint-card"><div class="ep-line"><span class="method get">GET</span><code class="ep-path">/audit-log</code><span class="ep-desc">Paginated audit entries, newest first</span></div><div class="code-block" tabindex="0" role="region" aria-label="Code example"><pre>GET /audit-log?limit=50&offset=0&action=auth.password_changed</pre></div></div>
            <div class="endpoint-card"><div class="ep-line"><span class="method get">GET</span><code class="ep-path">/audit-log/count</code><span class="ep-desc">Total entry count for this tenant</span></div></div>
          </div>

          <div class="doc-block">
            <h3>Data Models</h3>
            <p>All models below are the exact Pydantic schemas returned by the API.</p>

            <h4 class="sub-head">DomainOut / DomainDetail</h4>
            <div class="model-table"><table>
              <thead><tr><th>Field</th><th>Type</th><th>Notes</th></tr></thead>
              <tbody>
                <tr><td>id</td><td><code>str</code></td><td>UUID</td></tr>
                <tr><td>domain</td><td><code>str</code></td><td></td></tr>
                <tr><td>dmarc_stage</td><td><code>str</code></td><td><code>none</code> · <code>monitor</code> · <code>quarantine</code> · <code>reject</code></td></tr>
                <tr><td>mta_sts_stage</td><td><code>str</code></td><td><code>none</code> · <code>testing</code> · <code>enforce</code></td></tr>
                <tr><td>dmarc_record_published</td><td><code>bool</code></td><td>Live DNS confirms record exists</td></tr>
                <tr><td>ownership_verified</td><td><code>bool</code></td><td>Reporting address found in DNS</td></tr>
                <tr><td>reporting_address</td><td><code>str</code></td><td>Unique <code>slug@mailsentry.co.za</code></td></tr>
                <tr><td>added_at</td><td><code>datetime</code></td><td></td></tr>
                <tr><td>dmarc_policy <em>(Detail only)</em></td><td><code>str | None</code></td><td>Current live policy from DNS</td></tr>
                <tr><td>dmarc_pct <em>(Detail only)</em></td><td><code>int | None</code></td><td>DMARC <code>pct=</code> tag value</td></tr>
                <tr><td>mta_sts_policy_id <em>(Detail only)</em></td><td><code>str | None</code></td><td></td></tr>
              </tbody>
            </table></div>

            <h4 class="sub-head">SentinelScoreOut</h4>
            <div class="model-table"><table>
              <thead><tr><th>Field</th><th>Type</th><th>Notes</th></tr></thead>
              <tbody>
                <tr><td>score</td><td><code>int</code></td><td>0–100</td></tr>
                <tr><td>grade</td><td><code>str</code></td><td><code>A</code> · <code>B</code> · <code>C</code> · <code>D</code> · <code>F</code></td></tr>
                <tr><td>grade_color</td><td><code>str</code></td><td>Hex colour</td></tr>
                <tr><td>grade_label</td><td><code>str</code></td><td>e.g. <code>"Fully protected"</code></td></tr>
                <tr><td>pillar_dmarc</td><td><code>float</code></td><td>Points from DMARC pillar (max 60)</td></tr>
                <tr><td>pillar_tls</td><td><code>float</code></td><td>Points from TLS pillar (max 25)</td></tr>
                <tr><td>pillar_certs</td><td><code>float</code></td><td>Points from cert health pillar (max 15)</td></tr>
                <tr><td>volume_weighted</td><td><code>bool</code></td><td>Whether score is weighted by mail volume</td></tr>
                <tr><td>delta</td><td><code>int | None</code></td><td>Change vs last week; <code>null</code> if no history</td></tr>
              </tbody>
            </table></div>

            <h4 class="sub-head">DmarcSourceOut (source classification)</h4>
            <div class="model-table"><table>
              <thead><tr><th>Field</th><th>Type</th><th>Notes</th></tr></thead>
              <tbody>
                <tr><td>source_org</td><td><code>str</code></td><td>Sending organisation name</td></tr>
                <tr><td>volume</td><td><code>int</code></td><td></td></tr>
                <tr><td>spf_alignment</td><td><code>str</code></td><td><code>ALIGNED</code> · <code>UNALIGNED</code> · <code>FAIL</code></td></tr>
                <tr><td>dkim_alignment</td><td><code>str</code></td><td><code>ALIGNED</code> · <code>UNALIGNED</code> · <code>NONE</code></td></tr>
                <tr><td>dmarc_result</td><td><code>str</code></td><td><code>PASS</code> · <code>FAIL</code></td></tr>
                <tr><td>classification</td><td><code>str</code></td><td><code>authorized</code> · <code>forwarded</code> · <code>unauth</code> · <code>spoof</code> · <code>unknown</code></td></tr>
                <tr><td>recommended_action</td><td><code>str</code></td><td>What to do about this source</td></tr>
                <tr><td>ips</td><td><code>DmarcIpOut[]</code></td><td>Per-IP breakdown</td></tr>
              </tbody>
            </table></div>

            <h4 class="sub-head">CertOut</h4>
            <div class="model-table"><table>
              <thead><tr><th>Field</th><th>Type</th><th>Notes</th></tr></thead>
              <tbody>
                <tr><td>host</td><td><code>str</code></td><td>Hostname probed</td></tr>
                <tr><td>host_type</td><td><code>str</code></td><td><code>mx</code> · <code>https</code></td></tr>
                <tr><td>days_remaining</td><td><code>int | None</code></td><td>Negative = already expired</td></tr>
                <tr><td>tls_version</td><td><code>str | None</code></td><td>e.g. <code>TLSv1.3</code></td></tr>
                <tr><td>starttls_supported</td><td><code>bool | None</code></td><td></td></tr>
                <tr><td>hostname_valid</td><td><code>bool | None</code></td><td>CN or SAN match</td></tr>
                <tr><td>status</td><td><code>str</code></td><td><code>ok</code> · <code>expiring_soon</code> · <code>critical</code> · <code>expired</code> · <code>error</code></td></tr>
                <tr><td>probe_error</td><td><code>str | None</code></td><td>Error message if probe failed</td></tr>
                <tr><td>probed_at</td><td><code>datetime</code></td><td></td></tr>
              </tbody>
            </table></div>

            <h4 class="sub-head">AdvisorOut</h4>
            <div class="model-table"><table>
              <thead><tr><th>Field</th><th>Type</th><th>Notes</th></tr></thead>
              <tbody>
                <tr><td>message</td><td><code>str</code></td><td>AI-generated advisory text</td></tr>
                <tr><td>commend</td><td><code>bool</code></td><td>True when posture is healthy</td></tr>
                <tr><td>is_ai</td><td><code>bool</code></td><td>False for rule-based fallback</td></tr>
                <tr><td>model</td><td><code>str</code></td><td>e.g. <code>claude-haiku-4-5-20251001</code></td></tr>
              </tbody>
            </table></div>

            <h4 class="sub-head">Enumeration Reference</h4>
            <div class="model-table"><table>
              <thead><tr><th>Field / context</th><th>Valid values</th></tr></thead>
              <tbody>
                <tr><td>User <code>role</code></td><td><code>admin</code> · <code>viewer</code></td></tr>
                <tr><td>Tenant <code>plan</code></td><td><code>free</code> · <code>starter</code> · <code>pro</code> · <code>msp</code> · <code>enterprise</code></td></tr>
                <tr><td><code>dmarc_stage</code></td><td><code>none</code> · <code>monitor</code> · <code>quarantine</code> · <code>reject</code></td></tr>
                <tr><td><code>mta_sts_stage</code></td><td><code>none</code> · <code>testing</code> · <code>enforce</code></td></tr>
                <tr><td>Source <code>classification</code></td><td><code>authorized</code> · <code>forwarded</code> · <code>unauth</code> · <code>spoof</code> · <code>unknown</code></td></tr>
                <tr><td>Auth <code>verdict</code></td><td><code>authorized</code> · <code>authorized_dkim</code> · <code>authorized_spf</code> · <code>esp_bounce</code> · <code>esp_unauth</code> · <code>auth_failure</code> · <code>likely_spoof</code> · <code>unauth</code></td></tr>
                <tr><td>Cert <code>status</code></td><td><code>ok</code> · <code>expiring_soon</code> · <code>critical</code> · <code>expired</code> · <code>error</code></td></tr>
                <tr><td>DNS change <code>risk_severity</code></td><td><code>info</code> · <code>warn</code> · <code>critical</code></td></tr>
                <tr><td>Recommendation <code>effort</code> / <code>impact</code></td><td><code>Low</code> · <code>Medium</code> · <code>High</code></td></tr>
              </tbody>
            </table></div>
          </div>

          <div class="doc-block">
            <h3>Error Codes</h3>
            <div class="table-wrap"><table>
              <thead><tr><th>Status</th><th>Meaning</th><th>Common cause</th></tr></thead>
              <tbody>
                <tr><td><code>400</code></td><td>Bad Request</td><td>Invalid field value, duplicate email</td></tr>
                <tr><td><code>401</code></td><td>Unauthorized</td><td>Missing or expired Bearer token</td></tr>
                <tr><td><code>403</code></td><td>Forbidden</td><td>Admin role required, or feature not on current plan</td></tr>
                <tr><td><code>404</code></td><td>Not Found</td><td>Domain or resource not found in this workspace</td></tr>
                <tr><td><code>409</code></td><td>Conflict</td><td>Domain already registered, duplicate invite</td></tr>
                <tr><td><code>410</code></td><td>Gone</td><td>Invite already used or expired</td></tr>
                <tr><td><code>422</code></td><td>Unprocessable Entity</td><td>Request body failed schema validation</td></tr>
                <tr><td><code>429</code></td><td>Too Many Requests</td><td>Rate limit reached on a limited endpoint such as sign-in; the limit is per client address, wait and retry</td></tr>
              </tbody>
            </table></div>
          </div>

          <div class="doc-block">
            <h3>Example: Pull the ZoneProof Score</h3>
            <div class="code-block" tabindex="0" role="region" aria-label="Code example"><pre>import httpx

BASE = "http://localhost:8000"

r = httpx.post(f"{BASE}/auth/token", data={
    "username": "admin@example.com",
    "password": "secret",
})
token = r.json()["access_token"]
headers = {"Authorization": f"Bearer {token}"}

overview = httpx.get(f"{BASE}/overview", headers=headers).json()
s = overview["sentinel"]
print(f"Score: {s['score']}/100  Grade: {s['grade']}  Delta: {s['delta']:+d}")</pre></div>
          </div>
        </template>

        <!-- ═══════════════════════════════════════════════════════════════════
             08 · ZoneProof Score Reference
             ════════════════════════════════════════════════════════════════ -->
        <template v-else-if="activeSection === 'score-ref'">
          <div class="section-header">
            <div class="sec-num">08</div>
            <div>
              <h2>ZoneProof Score Reference</h2>
              <p class="sec-sub">Exact calculation, grade bands, pillar weights, and what moves the score.</p>
            </div>
          </div>

          <div class="doc-block">
            <h3>How the score is calculated</h3>
            <p>The ZoneProof Score is a portfolio-level number (0–100) computed from three pillars. When domains have mail volume data, the score is <strong>volume-weighted</strong> — higher-traffic domains count more because a security gap on a high-volume domain is more consequential than the same gap on a low-traffic domain.</p>
            <div class="pillar-breakdown">
              <div class="pb-pillar">
                <div class="pb-head"><span class="pb-max">60 pts</span> DMARC Pillar</div>
                <div class="pb-rows">
                  <div class="pb-row"><span>p=reject</span><span class="pb-pts">60 pts</span></div>
                  <div class="pb-row"><span>p=quarantine</span><span class="pb-pts">40 pts</span></div>
                  <div class="pb-row"><span>p=none (monitoring)</span><span class="pb-pts">20 pts</span></div>
                  <div class="pb-row"><span>No DMARC record</span><span class="pb-pts">0 pts</span></div>
                </div>
              </div>
              <div class="pb-pillar">
                <div class="pb-head"><span class="pb-max">25 pts</span> MTA-STS Pillar</div>
                <div class="pb-rows">
                  <div class="pb-row"><span>enforce + TLS pass rate ≥ 99%</span><span class="pb-pts">25 pts</span></div>
                  <div class="pb-row"><span>enforce + TLS pass rate &lt; 99%</span><span class="pb-pts">18 pts</span></div>
                  <div class="pb-row"><span>testing mode</span><span class="pb-pts">10 pts</span></div>
                  <div class="pb-row"><span>No MTA-STS policy</span><span class="pb-pts">0 pts</span></div>
                </div>
              </div>
              <div class="pb-pillar">
                <div class="pb-head"><span class="pb-max">15 pts</span> Certificate Health Pillar</div>
                <div class="pb-rows">
                  <div class="pb-row"><span>All certs valid, &gt; 30 days remaining</span><span class="pb-pts">15 pts</span></div>
                  <div class="pb-row"><span>Expiring soon (≤ 30 days)</span><span class="pb-pts">8 pts</span></div>
                  <div class="pb-row"><span>Critical (≤ 7 days)</span><span class="pb-pts">2 pts</span></div>
                  <div class="pb-row"><span>Expired</span><span class="pb-pts">0 pts</span></div>
                  <div class="pb-row"><span>No cert data (no MTA-STS)</span><span class="pb-pts">0 pts</span></div>
                </div>
              </div>
            </div>
          </div>

          <div class="doc-block">
            <h3>Per-domain grade vs portfolio score</h3>
            <p>There are two related but distinct scoring systems in ZoneProof:</p>
            <div class="two-col">
              <div class="info-card">
                <div class="ic-head">Per-domain grade (A–F)</div>
                <p>Shown on the domain table and domain detail. Scored out of 100 using slightly different pillar weights (DMARC max 65, TLS max 25, Certs max 10). Gives a grade for each individual domain regardless of its mail volume.</p>
              </div>
              <div class="info-card">
                <div class="ic-head">Portfolio ZoneProof Score</div>
                <p>The headline number shown on the Overview. Scored out of 100 using pillar weights (DMARC 60, TLS 25, Certs 15), averaged across all domains, weighted by their mail volume. This is the number in the weekly report.</p>
              </div>
            </div>
          </div>

          <div class="doc-block">
            <h3>Grade bands</h3>
            <div class="grade-bands">
              <div class="gb-row"><span class="gb-grade" style="color:#34e0a1">A</span><span class="gb-range">90–100</span><span class="gb-label">Fully protected</span><p>All (or nearly all) domains at p=reject with MTA-STS enforce and healthy certificates. Threat surface is effectively zero for compliant senders.</p></div>
              <div class="gb-row"><span class="gb-grade" style="color:#5b5cf0">B</span><span class="gb-range">75–89</span><span class="gb-label">Strong posture</span><p>Most domains at enforcement. Typically one or two domains not yet at reject, or MTA-STS not yet at enforce on some domains. Minor gaps remain.</p></div>
              <div class="gb-row"><span class="gb-grade" style="color:#f5c542">C</span><span class="gb-range">55–74</span><span class="gb-label">Partial coverage</span><p>A mix of domains at different stages. Some protected, some still in monitoring. Significant impersonation risk remains on unprotected domains.</p></div>
              <div class="gb-row"><span class="gb-grade" style="color:#ff8c42">D</span><span class="gb-range">35–54</span><span class="gb-label">Significant gaps</span><p>Most domains unprotected or at p=none. High impersonation risk. Active remediation needed.</p></div>
              <div class="gb-row"><span class="gb-grade" style="color:#ff4d6d">F</span><span class="gb-range">0–34</span><span class="gb-label">At risk</span><p>No meaningful enforcement. Domains are fully open to impersonation. Immediate action required.</p></div>
            </div>
          </div>

          <div class="doc-block">
            <h3>What moves the score up</h3>
            <div class="gate-list">
              <div class="gate"><span class="g-ok">↑</span> Advancing any domain from <code>p=none</code> to <code>p=quarantine</code> <em>(+20 pts on that domain's DMARC pillar)</em></div>
              <div class="gate"><span class="g-ok">↑</span> Advancing any domain from <code>p=quarantine</code> to <code>p=reject</code> <em>(+20 pts on that domain's DMARC pillar)</em></div>
              <div class="gate"><span class="g-ok">↑</span> Enabling MTA-STS in testing mode on any domain <em>(+10 pts on that domain's TLS pillar)</em></div>
              <div class="gate"><span class="g-ok">↑</span> Advancing MTA-STS from testing to enforce <em>(+15 pts when pass rate ≥ 99%)</em></div>
              <div class="gate"><span class="g-ok">↑</span> Renewing an expiring certificate before it reaches critical <em>(+7 pts on cert pillar)</em></div>
              <div class="gate"><span class="g-ok">↑</span> Adding a new domain that starts at a higher stage than the portfolio average <em>(raises the weighted average)</em></div>
            </div>
          </div>

          <div class="doc-block">
            <h3>What moves the score down</h3>
            <div class="gate-list">
              <div class="gate"><span class="g-bad">↓</span> A certificate entering <code>expiring_soon</code> status (–7 pts on cert pillar)</div>
              <div class="gate"><span class="g-bad">↓</span> A certificate entering <code>critical</code> status (–13 pts on cert pillar)</div>
              <div class="gate"><span class="g-bad">↓</span> A certificate expiring (cert pillar drops to 0 for that domain)</div>
              <div class="gate"><span class="g-bad">↓</span> Adding a new domain that starts unprotected (lowers the weighted average)</div>
              <div class="gate"><span class="g-bad">↓</span> A DMARC policy downgrade (e.g. reject → quarantine caused by a DNS change)</div>
            </div>
          </div>

          <div class="doc-block">
            <h3>Using the score in client reports</h3>
            <p>The ZoneProof Score is designed to be the single number you put in front of a non-technical client. To explain it:</p>
            <ul class="bullet-list">
              <li><strong>Grade A / Score 90+:</strong> "Your email security is fully enforced. We are blocking impersonation attempts and inbound delivery is protected."</li>
              <li><strong>Grade B / Score 75–89:</strong> "Strong posture with minor gaps. We are working through the remaining domains to reach full enforcement."</li>
              <li><strong>Grade C or below:</strong> "Significant gaps remain. [Number] of your domains are not yet at full enforcement — this is the focus of the next period's work."</li>
            </ul>
            <p>The score trend (shown in the PDF report as a weekly sparkline) tells the story of progress over time. A rising score across a quarter is a clear demonstration of value from your MSP service.</p>
          </div>

          <div class="doc-block">
            <h3>How this connects to recommendations</h3>
            <p>The same gates described above — DMARC compliance ≥ 95% for 30 days, TLS pass rate ≥ 99% for 14 days, certificate runway ≥ 30 days — aren't just used to calculate the score. They're the exact rule set the <a href="#" @click.prevent="activeSection = 'account-security'">recommendation engine</a> uses to decide when it's safe to suggest advancing a domain's enforcement stage. The alert bell, the PDF report's recommendation list, and the Roadmap page's "why can't I advance yet" panel all read from this one rule set — there's no separate AI judgment call about whether advancing is safe. An AI advisor may explain a recommendation in plain language, but it never decides whether to make one.</p>
          </div>
        </template>

        <!-- ═══════════════════════════════════════════════════════════════════
             09 · Account & Security
             ════════════════════════════════════════════════════════════════ -->
        <template v-else-if="activeSection === 'account-security'">
          <div class="section-header">
            <div class="sec-num">09</div>
            <div>
              <h2>Account &amp; Security</h2>
              <p class="sec-sub">Signing up, recovering access, verifying your email, and what changing your credentials actually does to your session.</p>
            </div>
          </div>

          <div class="doc-block">
            <h3>Terms acceptance at signup</h3>
            <p>Creating an account — either by registering directly or by accepting a team invite — requires checking a box agreeing to the Terms of Service and Privacy Policy. This is recorded with a timestamp and the specific terms version you agreed to, not just a yes/no flag, so it can be reproduced later if the terms ever materially change.</p>
            <p>Being invited onto an existing workspace by an admin still requires you, personally, to accept terms when you set your password — an admin inviting you isn't treated as consent on your behalf.</p>
          </div>

          <div class="doc-block">
            <h3>Email verification</h3>
            <p>New accounts created via direct registration start <strong>unverified</strong>. This is soft-gated by design: you can use the app immediately, but you'll see a dismissible banner prompting you to confirm your email address, with a one-click resend.</p>
            <div class="callout info">
              Accounts created by accepting a team invite, or created directly by an MSP admin, start already verified — receiving and clicking the invite link is itself proof you control that email address, so there's nothing further to confirm.
            </div>
            <p>Verification links expire after 24 hours. Requesting a new one automatically invalidates any link sent before it, so only the most recent email is ever live.</p>
          </div>

          <div class="doc-block">
            <h3>Forgotten password</h3>
            <p>The sign-in page has a "Forgot password?" link. Submitting your email always returns the same response — "if an account with that email exists, a reset link has been sent" — regardless of whether the address is actually registered. This is deliberate: a different response for known vs. unknown emails would let someone enumerate which addresses have accounts.</p>
            <div class="steps">
              <div class="step"><span class="step-num">1</span><div>Request a reset link by email.</div></div>
              <div class="step"><span class="step-num">2</span><div>Click the link (valid for 30 minutes, single-use — requesting a new one invalidates the previous link).</div></div>
              <div class="step"><span class="step-num">3</span><div>Choose a new password. You'll be signed out of your current session and need to sign back in with it.</div></div>
            </div>
            <p>Single sign-on (SSO) accounts have no password to reset — this flow only applies to accounts created with a password.</p>
          </div>

          <div class="doc-block">
            <h3>What changing your password actually does to your session</h3>
            <p>ZoneProof's sign-in tokens are stateless — there's no server-side list of "currently valid" tokens to check on every request. Instead, each account carries an internal counter that's embedded in every token it issues. Changing your password, resetting it, or enabling/disabling two-factor authentication increments that counter, which makes <strong>every previously issued token for that account stop working immediately</strong> — including the one you're using right now.</p>
            <p>In practice: after changing your password from your account settings, you'll be signed out and asked to sign in again with the new one. This is correct behavior, not a bug — it's what makes "change your password" actually mean something if your account was compromised, rather than just changing the password while a stolen session token keeps working.</p>
          </div>

          <div class="doc-block">
            <h3>Exporting your data</h3>
            <p>From Settings, you can download a JSON export of your account, workspace, team members, and a summary of each monitored domain's DMARC/TLS/certificate status. This is scoped to summary-level data — compliance percentages, volume, certificate status — not a row-by-row dump of every raw report ever ingested, since that's rarely what a data export request is actually asking for and can run into tens of thousands of rows per domain.</p>
          </div>

          <div class="doc-block">
            <h3>Bulk domain import</h3>
            <p>When adding domains, you're not limited to typing them one at a time. Paste a comma- or newline-separated list directly into the domain field, or use <strong>Import from CSV or text file</strong> to upload a file — one domain per line, or a comma-separated row exported from a spreadsheet. A header row like "domain" or "name" is recognised and skipped automatically rather than queued as an (invalid) domain.</p>
            <p>Every domain in the list goes through the same DMARC check → TLS setup → confirm flow as a single domain, just looped — useful for an MSP onboarding a new client's entire domain portfolio in one pass rather than clicking through the wizard repeatedly.</p>
          </div>
        </template>

        <!-- ═══════════════════════════════════════════════════════════════════
             10 · Audit Log
             ════════════════════════════════════════════════════════════════ -->
        <template v-else-if="activeSection === 'audit-log'">
          <div class="section-header">
            <div class="sec-num">10</div>
            <div>
              <h2>Audit Log</h2>
              <p class="sec-sub">Who changed what, and when — every security and admin-relevant action in your workspace.</p>
            </div>
          </div>

          <div class="doc-block">
            <h3>Availability</h3>
            <p>Audit Log is an <strong>Enterprise plan</strong> feature. It's always visible in the sidebar regardless of plan — on a lower tier it shows a lock icon and links through to an upgrade prompt rather than disappearing entirely, so you know the feature exists before you need to ask.</p>
          </div>

          <div class="doc-block">
            <h3>What gets logged</h3>
            <p>The audit log is written by explicit calls at known, security-relevant action points — not a generic "log every request" capture. That's a deliberate tradeoff: a generic capture logs the HTTP layer ("PATCH /domains/abc123"), which isn't reconstructible into "what actually happened" without cross-referencing code. Explicit logging captures the actual event ("advanced example.com from quarantine to reject") in a form a non-engineer reviewing the log can read directly.</p>
            <div class="field-list">
              <div class="fl-row"><span class="fl-k">Account</span><span>Password changes/resets, 2FA enabled/disabled, email verified</span></div>
              <div class="fl-row"><span class="fl-k">Team</span><span>Invites created/accepted/revoked, role changes, member removal</span></div>
              <div class="fl-row"><span class="fl-k">Domains</span><span>Domain added/deleted, ownership verified</span></div>
              <div class="fl-row"><span class="fl-k">Billing</span><span>Plan changes — both admin-initiated and Stripe-webhook-driven (e.g. a failed payment downgrade)</span></div>
              <div class="fl-row"><span class="fl-k">MSP</span><span>Client tenant created/deleted, client user invited or created directly</span></div>
            </div>
          </div>

          <div class="doc-block">
            <h3>What you can see per entry</h3>
            <p>Each entry shows when it happened, who did it (by email — preserved even if that user is later removed from the workspace), the action, and what it was done to. Where relevant, the entry also records the before/after state of what changed (e.g. a role change shows the old and new role).</p>
            <div class="callout info">
              If a tenant is deleted entirely, its audit history is not preserved as a queryable log in the app — there would be no workspace left to view it from. The deletion event itself is recorded in the application's own system logs rather than the in-app audit log, for exactly this reason.
            </div>
          </div>

          <div class="doc-block">
            <h3>Filtering</h3>
            <p>The audit log can be filtered by action type if you're looking for a specific category of event (e.g. only billing changes, or only team membership changes) rather than scrolling the full history.</p>
          </div>
        </template>

      </div>
    </div>
  </div>
</template>

<style scoped>
.docs-wrap { max-width: 1100px; }
.titlerow { margin-bottom: 28px; }
.crumb { font-family: var(--mono); font-size: 10px; color: var(--faint); letter-spacing: 1.4px; text-transform: uppercase; }
h1 { font-family: var(--disp); font-weight: 800; font-size: 25px; letter-spacing: -.7px; margin-top: 5px; }
.sub { color: var(--muted); margin-top: 5px; font-size: 13px; }

.docs-layout { display: grid; grid-template-columns: 196px 1fr; gap: 28px; align-items: start; }

/* Nav */
.docs-nav { position: sticky; top: 20px; }
.nav-label { font-family: var(--mono); font-size: 9px; letter-spacing: 1.4px; color: var(--faint); text-transform: uppercase; padding: 0 10px 8px; }
.nav-item { display: flex; align-items: center; gap: 8px; padding: 7px 10px; border-radius: 10px; font-size: 12.5px; font-weight: 500; color: var(--muted); cursor: pointer; transition: all .14s ease; }
.nav-item:hover { background: rgba(255,255,255,.05); color: var(--txt); }
.nav-item.active { background: rgba(91,92,240,.15); color: var(--indigo); font-weight: 600; }
.n { font-family: var(--mono); font-size: 9px; opacity: .55; flex: none; }

/* Content */
.docs-content { min-width: 0; }
.section-header { display: flex; align-items: flex-start; gap: 18px; margin-bottom: 32px; padding-bottom: 24px; border-bottom: 1px solid var(--line); }
.sec-num { font-family: var(--mono); font-size: 28px; font-weight: 700; color: var(--indigo); opacity: .25; line-height: 1; flex: none; margin-top: 4px; }
h2 { font-family: var(--disp); font-weight: 800; font-size: 22px; letter-spacing: -.5px; margin: 0 0 4px; }
.sec-sub { color: var(--muted); font-size: 13px; margin: 0; }
.sec-sub code { background: rgba(255,255,255,.07); padding: 1px 5px; border-radius: 4px; font-family: var(--mono); font-size: 12px; }
.doc-block { margin-bottom: 40px; }
h3 { font-family: var(--disp); font-weight: 700; font-size: 16px; margin: 0 0 14px; letter-spacing: -.3px; }
h4.sub-head { font-family: var(--disp); font-weight: 700; font-size: 13.5px; margin: 22px 0 10px; color: var(--muted); letter-spacing: -.2px; }
p { color: var(--muted); font-size: 13px; line-height: 1.65; margin: 0 0 12px; }
a { color: var(--indigo); text-decoration: none; }
a:hover { text-decoration: underline; }

/* Two col */
.two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin: 14px 0; }
.info-card { background: var(--glass); border: 1px solid var(--line); border-radius: 14px; padding: 14px 16px; }
.ic-head { font-family: var(--disp); font-weight: 700; font-size: 13px; margin-bottom: 8px; color: var(--txt); }
.ic-head.good-head { color: var(--teal); }
.ic-head.bad-head { color: var(--bad); }

/* Steps */
.steps { display: flex; flex-direction: column; gap: 12px; margin: 14px 0; }
.step { display: flex; gap: 14px; align-items: flex-start; }
.step-num { flex: none; width: 26px; height: 26px; border-radius: 50%; background: rgba(91,92,240,.18); color: var(--indigo); font-family: var(--mono); font-size: 11px; font-weight: 700; display: grid; place-items: center; margin-top: 1px; }
.step > div { font-size: 13px; color: var(--muted); line-height: 1.6; flex: 1; }
.step > div strong { color: var(--txt); }

/* Callout */
.callout { padding: 12px 14px; border-radius: 10px; font-size: 12.5px; color: var(--muted); margin: 14px 0; line-height: 1.6; }
.callout.info { background: rgba(91,92,240,.08); border-left: 3px solid var(--indigo); }
.callout.warn { background: rgba(245,165,0,.08); border-left: 3px solid #f5a500; }
.callout strong { color: var(--txt); }

/* Gate list */
.gate-list { display: flex; flex-direction: column; gap: 8px; margin: 14px 0; }
.gate { display: flex; align-items: flex-start; gap: 10px; font-size: 13px; color: var(--muted); }
.g-ok { color: var(--teal); font-weight: 700; flex: none; }
.g-bad { color: var(--bad); font-weight: 700; flex: none; }
.gate em { color: var(--faint); font-style: normal; font-family: var(--mono); font-size: 11px; }

/* Timeline list */
.timeline-list { display: flex; flex-direction: column; gap: 8px; margin: 14px 0; }
.tl-row { display: flex; gap: 16px; font-size: 13px; color: var(--muted); }
.tl-time { font-family: var(--mono); font-size: 11px; color: var(--indigo); white-space: nowrap; padding-top: 1px; min-width: 120px; }

/* Pillar list */
.pillar-list { display: flex; flex-direction: column; gap: 8px; margin: 12px 0 16px; }
.pillar { display: flex; gap: 12px; align-items: flex-start; font-size: 13px; color: var(--muted); }
.pl-max { font-family: var(--mono); font-size: 11px; font-weight: 700; color: var(--indigo); white-space: nowrap; min-width: 50px; padding-top: 1px; }
.pillar strong { color: var(--txt); }

/* Stage cards */
.stage-cards { display: flex; flex-direction: column; gap: 10px; margin: 14px 0; }
.stage-card { border-radius: 14px; padding: 14px 16px; border: 1px solid var(--line); }
.stage-none { background: rgba(255,255,255,.03); }
.stage-q    { background: rgba(245,165,0,.05); border-color: rgba(245,165,0,.2); }
.stage-r    { background: rgba(46,230,197,.05); border-color: rgba(46,230,197,.2); }
.stage-bimi { background: rgba(91,92,240,.05); border-color: rgba(91,92,240,.2); }
.sc-head { display: flex; align-items: center; gap: 10px; font-family: var(--disp); font-weight: 700; font-size: 13.5px; margin-bottom: 8px; color: var(--txt); }
.sc-badge { font-family: var(--mono); font-size: 10px; font-weight: 700; padding: 2px 9px; border-radius: 8px; }
.badge-none { background: rgba(255,255,255,.08); color: var(--faint); }
.badge-q    { background: rgba(245,165,0,.18); color: #f5a500; }
.badge-r    { background: rgba(46,230,197,.18); color: var(--teal); }
.badge-b    { background: rgba(91,92,240,.18); color: var(--indigo); }

/* Blockers */
.blocker-list { display: flex; flex-direction: column; gap: 12px; margin: 14px 0; }
.blocker { background: var(--glass); border: 1px solid var(--line); border-radius: 12px; padding: 12px 16px; }
.bl-head { font-family: var(--disp); font-weight: 700; font-size: 13px; color: var(--txt); margin-bottom: 6px; }

/* Field list */
.field-list { display: flex; flex-direction: column; gap: 8px; margin: 12px 0; }
.fl-row { display: grid; grid-template-columns: 130px 1fr; gap: 12px; font-size: 13px; color: var(--muted); }
.fl-k { font-family: var(--mono); font-size: 11px; color: var(--txt); font-weight: 600; padding-top: 2px; }

/* Status list */
.status-list { display: flex; flex-direction: column; gap: 12px; margin: 14px 0; }
.status-row { display: flex; align-items: flex-start; gap: 12px; font-size: 13px; color: var(--muted); }
.status-badge { font-family: var(--mono); font-size: 10px; font-weight: 700; padding: 2px 9px; border-radius: 8px; white-space: nowrap; flex: none; }
.st-ok   { background: rgba(46,230,197,.14); color: var(--teal); }
.st-soon { background: rgba(245,197,66,.14); color: #f5c542; }
.st-crit { background: rgba(245,130,61,.18); color: #f5823d; }
.st-exp  { background: rgba(255,77,109,.14); color: var(--bad); }
.st-err  { background: rgba(255,255,255,.07); color: var(--faint); }

/* Sev badges */
.sev-badge { font-family: var(--mono); font-size: 10px; font-weight: 700; padding: 2px 9px; border-radius: 8px; }
.sev-critical { background: rgba(255,77,109,.14); color: var(--bad); }
.sev-warn     { background: rgba(245,165,0,.14); color: #f5a500; }
.sev-ok       { background: rgba(46,230,197,.14); color: var(--teal); }

/* Bullet list */
.bullet-list { margin: 8px 0 12px 0; padding-left: 18px; display: flex; flex-direction: column; gap: 6px; }
.bullet-list li { font-size: 13px; color: var(--muted); line-height: 1.6; }
.bullet-list strong { color: var(--txt); }

/* ESP table */
.esp-table { overflow-x: auto; margin: 12px 0; }

/* Tables */
.table-wrap { overflow-x: auto; margin: 12px 0; }
.model-table { overflow-x: auto; margin: 8px 0 16px; }
table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
thead th { text-align: left; font-family: var(--mono); font-size: 9.5px; font-weight: 700; letter-spacing: 1px; text-transform: uppercase; color: var(--faint); padding: 8px 12px; border-bottom: 1px solid var(--line); }
tbody td { padding: 9px 12px; border-bottom: 1px solid rgba(255,255,255,.04); color: var(--muted); vertical-align: top; }
tbody td:first-child { color: var(--txt); font-weight: 500; }
tbody td code { font-family: var(--mono); font-size: 11px; background: rgba(255,255,255,.07); padding: 1px 5px; border-radius: 3px; }
tbody tr:last-child td { border-bottom: none; }

/* Code */
.code-block { background: rgba(0,0,0,.35); border: 1px solid rgba(255,255,255,.08); border-radius: 10px; padding: 12px 14px; margin-top: 6px; overflow-x: auto; }
.code-block pre { font-family: var(--mono); font-size: 11.5px; color: rgba(255,255,255,.8); margin: 0; white-space: pre; line-height: 1.6; }
.mt8 { margin-top: 8px; }

/* Endpoint cards */
.endpoint-card { background: var(--glass); border: 1px solid var(--line); border-radius: 14px; padding: 14px 16px; margin-bottom: 12px; }
.ep-line { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.method { font-family: var(--mono); font-size: 10px; font-weight: 700; letter-spacing: .5px; padding: 2px 8px; border-radius: 6px; flex: none; }
.method.get    { background: rgba(46,230,197,.14); color: var(--teal); }
.method.post   { background: rgba(91,92,240,.16); color: var(--indigo); }
.method.patch  { background: rgba(245,165,0,.14);  color: #f5a500; }
.method.delete { background: rgba(255,77,109,.14); color: var(--bad); }
.ep-path { font-family: var(--mono); font-size: 12.5px; color: var(--txt); background: rgba(255,255,255,.05); padding: 2px 8px; border-radius: 6px; }
.ep-desc { font-size: 12.5px; color: var(--muted); }
.ep-note { font-size: 12px; color: var(--muted); margin-top: 8px; line-height: 1.6; }
.ep-note.warn { color: #f5a500; background: rgba(245,165,0,.07); padding: 8px 10px; border-radius: 8px; border-left: 2px solid #f5a500; margin-top: 8px; }
.ep-note code, .ep-note strong { font-family: var(--mono); font-size: 11px; }
.response-label { font-family: var(--mono); font-size: 9.5px; color: var(--faint); letter-spacing: 1px; text-transform: uppercase; margin-top: 10px; margin-bottom: 4px; }
.usage-note { background: rgba(91,92,240,.08); border: 1px solid rgba(91,92,240,.2); border-radius: 12px; padding: 14px 16px; font-size: 13px; color: var(--muted); margin-top: 14px; }
.usage-note strong { color: var(--txt); }

/* Pillar breakdown */
.pillar-breakdown { display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px; margin: 14px 0; }
.pb-pillar { background: var(--glass); border: 1px solid var(--line); border-radius: 14px; padding: 14px; }
.pb-head { font-family: var(--disp); font-weight: 700; font-size: 13px; color: var(--txt); margin-bottom: 12px; display: flex; flex-direction: column; gap: 4px; }
.pb-max { font-family: var(--mono); font-size: 18px; font-weight: 800; color: var(--indigo); }
.pb-rows { display: flex; flex-direction: column; gap: 6px; }
.pb-row { display: flex; justify-content: space-between; align-items: center; font-size: 12px; color: var(--muted); border-bottom: 1px solid rgba(255,255,255,.04); padding-bottom: 6px; }
.pb-row:last-child { border-bottom: none; padding-bottom: 0; }
.pb-pts { font-family: var(--mono); font-size: 11px; font-weight: 700; color: var(--indigo); }

/* Grade bands */
.grade-bands { display: flex; flex-direction: column; gap: 0; border: 1px solid var(--line); border-radius: 14px; overflow: hidden; }
.gb-row { display: grid; grid-template-columns: 44px 80px 160px 1fr; gap: 12px; align-items: start; padding: 14px 16px; border-bottom: 1px solid var(--line); }
.gb-row:last-child { border-bottom: none; }
.gb-grade { font-family: var(--disp); font-weight: 800; font-size: 22px; }
.gb-range { font-family: var(--mono); font-size: 11px; color: var(--faint); padding-top: 6px; }
.gb-label { font-weight: 600; font-size: 13px; color: var(--txt); padding-top: 5px; }
.gb-row p { font-size: 12.5px; color: var(--muted); margin: 0; line-height: 1.55; padding-top: 4px; }

@media (max-width: 900px) {
  .docs-layout { grid-template-columns: 1fr; }
  .docs-nav { position: static; display: flex; flex-wrap: wrap; gap: 6px; padding-bottom: 8px; border-bottom: 1px solid var(--line); margin-bottom: 4px; }
  .nav-label { display: none; }
  .nav-item { padding: 5px 10px; font-size: 12px; }
  .two-col { grid-template-columns: 1fr; }
  .pillar-breakdown { grid-template-columns: 1fr; }
  .gb-row { grid-template-columns: 36px 60px 1fr; }
  .gb-row p { grid-column: 1 / -1; }
}
</style>
