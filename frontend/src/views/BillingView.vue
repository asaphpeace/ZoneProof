<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api } from '@/api/client'
import { useAuthStore } from '@/stores/auth'
import { useUiStore } from '@/stores/ui'

const auth   = useAuthStore()
const ui     = useUiStore()
const route  = useRoute()
const router = useRouter()

const status   = ref<any>(null)
const plans    = ref<any[]>([])
const loading  = ref(true)
const changing = ref<string | null>(null)
const redirecting = ref<string | null>(null)

// Billing cycle toggle
const cycle = ref<'monthly' | 'annual'>('monthly')

onMounted(async () => {
  // Handle return from Stripe
  if (route.query.upgraded) {
    ui.toast('Plan activated — welcome to your new plan!')
    router.replace({ name: 'billing' })
  } else if (route.query.cancelled) {
    ui.toast('Checkout cancelled', 'error')
    router.replace({ name: 'billing' })
  }

  try {
    ;[status.value, plans.value] = await Promise.all([api.billingStatus(), api.billingPlans()])
  } finally {
    loading.value = false
  }
})

const PLAN_ORDER = ['free', 'starter', 'pro', 'msp', 'enterprise']

function isCurrentPlan(key: string) {
  return status.value?.current_plan?.key === key
}
function isUpgrade(key: string) {
  const cur = PLAN_ORDER.indexOf(status.value?.current_plan?.key ?? 'free')
  return PLAN_ORDER.indexOf(key) > cur
}
function usagePct(used: number, limit: number | null) {
  if (!limit) return 0
  return Math.min(100, Math.round(used / limit * 100))
}
function usageColor(pct: number) {
  if (pct >= 90) return '#ff4d6d'
  if (pct >= 70) return '#f5c542'
  return '#2ee6c5'
}

const schedSaving = ref(false)
async function setReportSchedule(schedule: 'off' | 'weekly' | 'monthly') {
  if (status.value?.report_schedule === schedule) return
  schedSaving.value = true
  try {
    status.value = await api.updateReportSchedule(schedule)
    ui.toast(schedule === 'off' ? 'Scheduled reports turned off' : `Reports will be sent ${schedule}`)
  } catch (e: any) {
    ui.toast(e.message ?? 'Failed to update report schedule', 'error')
  } finally {
    schedSaving.value = false
  }
}

const FEATURE_LABELS: Record<string, string> = {
  pdf_report:        'PDF reports',
  recommendations:   'Recommendations',
  api_access:        'API access',
  white_label:       'White-label reports',
  scheduled_reports: 'Scheduled reports',
}

function planPrice(plan: any) {
  if (cycle.value === 'annual' && plan.annual_price_zar) {
    return Math.round(plan.annual_price_zar / 12)
  }
  return plan.price_zar
}

async function selectPlan(key: string) {
  if (changing.value || redirecting.value) return

  if (isUpgrade(key) && key !== 'enterprise' && key !== 'free') {
    // Paid upgrade — go through Stripe Checkout
    redirecting.value = key
    try {
      const result = await api.billingCheckout(key, cycle.value)
      window.location.href = result.checkout_url
    } catch (e: any) {
      redirecting.value = null
      const detail = (() => { try { return JSON.parse(e.message) } catch { return null } })()
      ui.toast(detail?.message ?? e.message ?? 'Failed to start checkout', 'error')
    }
    return
  }

  // Downgrade or free plan — direct change
  changing.value = key
  try {
    const updated = await api.changePlan(key)
    status.value = updated
    auth.setPlan(updated.current_plan.key)
    ui.toast(`Plan changed to ${updated.current_plan.label}`)
  } catch (e: any) {
    const detail = (() => { try { return JSON.parse(e.message) } catch { return null } })()
    ui.toast(detail?.message ?? e.message ?? 'Failed to change plan', 'error')
  } finally {
    changing.value = null
  }
}

async function openPortal() {
  redirecting.value = '__portal__'
  try {
    const result = await api.billingPortal()
    window.location.href = result.portal_url
  } catch (e: any) {
    redirecting.value = null
    ui.toast((e.message) ?? 'Failed to open billing portal', 'error')
  }
}
</script>

<template>
  <div>
    <div class="crumb">08 / Billing</div>
    <h1>Plan &amp; Billing</h1>

    <div v-if="loading" class="r-loading">
      <div class="spinner"/><p>Loading billing info…</p>
    </div>

    <template v-else-if="status">

      <!-- ── Current usage ──────────────────────────────────────────── -->
      <section class="card usage-card">
        <div class="ct">
          <div style="display:flex;align-items:center;gap:12px">
            <h3 aria-level="2">Current plan</h3>
            <span class="plan-badge">{{ status.current_plan.label }}</span>
          </div>
          <div style="display:flex;gap:8px">
            <button
              v-if="status.has_active_subscription"
              class="portal-btn"
              :disabled="redirecting === '__portal__'"
              @click="openPortal"
            >
              <span v-if="redirecting === '__portal__'" class="btn-spinner"/>
              <template v-else>
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <rect x="1" y="4" width="22" height="16" rx="2"/>
                  <line x1="1" y1="10" x2="23" y2="10"/>
                </svg>
                Manage subscription
              </template>
            </button>
          </div>
        </div>

        <div class="usage-row">
          <div class="usage-item">
            <div class="usage-head">
              <span>Domains</span>
              <span class="usage-nums">
                {{ status.usage.domains_used }}
                <span class="usage-max">/ {{ status.usage.domains_limit ?? '∞' }}</span>
              </span>
            </div>
            <div class="usage-bar-track">
              <div class="usage-bar-fill"
                :style="`width:${usagePct(status.usage.domains_used, status.usage.domains_limit)}%;background:${usageColor(usagePct(status.usage.domains_used, status.usage.domains_limit))}`"/>
            </div>
          </div>

          <div class="usage-item">
            <div class="usage-head">
              <span>Team members</span>
              <span class="usage-nums">
                {{ status.usage.users_used }}
                <span class="usage-max">/ {{ status.usage.users_limit ?? '∞' }}</span>
              </span>
            </div>
            <div class="usage-bar-track">
              <div class="usage-bar-fill"
                :style="`width:${usagePct(status.usage.users_used, status.usage.users_limit)}%;background:${usageColor(usagePct(status.usage.users_used, status.usage.users_limit))}`"/>
            </div>
          </div>

          <div class="usage-item">
            <div class="usage-head">
              <span>Report history</span>
              <span class="usage-nums">{{ status.usage.history_days }} days</span>
            </div>
            <div class="usage-bar-track">
              <div class="usage-bar-fill" style="width:100%;background:var(--teal)"/>
            </div>
          </div>
        </div>

        <div v-if="status.billing_email" class="billing-meta">
          <span class="fl">Billing email</span>
          <span class="fv fmono">{{ status.billing_email }}</span>
        </div>
      </section>

      <!-- ── Scheduled report delivery ─────────────────────────────── -->
      <section class="card schedule-card">
        <div class="schedule-head">
          <div>
            <div class="schedule-title">Scheduled reports</div>
            <div class="schedule-sub">Automatically email the PDF security report to your billing address</div>
          </div>
          <span v-if="!status.current_plan.scheduled_reports" class="schedule-lock">Requires Pro plan or higher</span>
        </div>
        <div class="schedule-opts">
          <button
            v-for="opt in [['off','Off'],['weekly','Weekly'],['monthly','Monthly']]" :key="opt[0]"
            :class="['schedule-opt', status.report_schedule === opt[0] ? 'sched-active' : '']"
            :disabled="schedSaving || (!status.current_plan.scheduled_reports && opt[0] !== 'off')"
            @click="setReportSchedule(opt[0] as any)"
          >{{ opt[1] }}</button>
        </div>
        <div v-if="status.last_report_sent_at" class="schedule-last">
          Last sent {{ new Date(status.last_report_sent_at).toLocaleDateString() }}
        </div>
      </section>

      <!-- ── Billing cycle toggle ───────────────────────────────────── -->
      <div class="cycle-toggle">
        <button :class="['cycle-opt', cycle === 'monthly' ? 'cyc-active' : '']" @click="cycle = 'monthly'">Monthly</button>
        <button :class="['cycle-opt', cycle === 'annual'  ? 'cyc-active' : '']" @click="cycle = 'annual'">
          Annual
          <span class="save-chip">save 17%</span>
        </button>
      </div>

      <!-- ── Plan comparison ────────────────────────────────────────── -->
      <div class="plans-grid">
        <div
          v-for="plan in plans"
          :key="plan.key"
          class="plan-card"
          :class="{
            'plan-current':  isCurrentPlan(plan.key),
            'plan-featured': plan.key === 'msp',
          }"
        >
          <div v-if="plan.key === 'msp'" class="plan-featured-band">Most popular for MSPs</div>

          <div class="plan-header">
            <div class="plan-name">{{ plan.label }}</div>
            <div class="plan-price">
              <template v-if="planPrice(plan) === 0">Free</template>
              <template v-else-if="planPrice(plan) !== null">
                <span class="plan-amt">R{{ planPrice(plan)?.toLocaleString() }}</span>
                <span class="plan-per">/mo</span>
              </template>
              <template v-else>Custom</template>
            </div>
            <div v-if="cycle === 'annual' && plan.annual_price_zar" class="plan-annual">
              R{{ plan.annual_price_zar.toLocaleString() }}/yr · 2 months free
            </div>
          </div>

          <div class="plan-limits">
            <div class="plan-limit-row">
              <span>Domains</span>
              <span class="fmono">{{ plan.domains ?? 'Unlimited' }}</span>
            </div>
            <div class="plan-limit-row">
              <span>Team members</span>
              <span class="fmono">{{ plan.users ?? 'Unlimited' }}</span>
            </div>
            <div class="plan-limit-row">
              <span>History</span>
              <span class="fmono">{{ plan.history_days }} days</span>
            </div>
          </div>

          <div class="plan-features">
            <div
              v-for="(label, key) in FEATURE_LABELS"
              :key="key"
              class="plan-feature"
              :class="plan[key] ? 'feat-on' : 'feat-off'"
            >
              <span class="feat-icon">{{ plan[key] ? '✓' : '–' }}</span>
              {{ label }}
            </div>
          </div>

          <div class="plan-action">
            <button
              v-if="isCurrentPlan(plan.key)"
              class="plan-btn plan-btn-current"
              disabled
            >Current plan</button>

            <button
              v-else-if="plan.key === 'enterprise'"
              class="plan-btn plan-btn-contact"
              @click="ui.toast('Contact sales@mailsentry.co.za for Enterprise pricing')"
            >Contact sales</button>

            <button
              v-else-if="isUpgrade(plan.key)"
              class="plan-btn plan-btn-upgrade"
              :disabled="!!(changing || redirecting)"
              @click="selectPlan(plan.key)"
            >
              <span v-if="redirecting === plan.key" class="btn-spinner"/>
              <template v-else>
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="width:13px;height:13px">
                  <path d="M5 12h14M12 5l7 7-7 7"/>
                </svg>
                Upgrade
              </template>
            </button>

            <button
              v-else
              class="plan-btn plan-btn-downgrade"
              :disabled="!!(changing || redirecting)"
              @click="selectPlan(plan.key)"
            >
              <span v-if="changing === plan.key" class="btn-spinner"/>
              <span v-else>Downgrade</span>
            </button>
          </div>
        </div>
      </div>

      <p class="billing-note">
        All prices exclude VAT. Annual billing saves 17% (2 months free).
        Upgrades redirect to Stripe Checkout — payments are processed securely by Stripe.
        Downgrades take effect immediately after usage validation.
        For Enterprise pricing or white-label arrangements contact
        <a href="mailto:sales@mailsentry.co.za">sales@mailsentry.co.za</a>.
      </p>

    </template>
  </div>
</template>

<style scoped>
.r-loading { display:flex; flex-direction:column; align-items:center; gap:12px; padding:60px; color:var(--muted); }
.spinner { width:28px; height:28px; border:3px solid rgba(255,255,255,.1); border-top-color:var(--indigo); border-radius:50%; animation:spin .8s linear infinite; }
@keyframes spin { to { transform:rotate(360deg); } }

h1 { font-family:var(--disp); font-size:22px; font-weight:900; color:var(--txt); margin-bottom:24px; }
.crumb { font-family:var(--mono); font-size:10px; color:var(--faint); letter-spacing:.5px; margin-bottom:8px; }

/* Usage card */
.card { background:rgba(255,255,255,.03); border:1px solid rgba(255,255,255,.07); border-radius:16px; padding:22px 24px; }
.ct { display:flex; align-items:center; justify-content:space-between; margin-bottom:18px; }
.ct h3 { font-family:var(--disp); font-size:15px; font-weight:700; color:var(--txt); margin:0; }
.plan-badge { font-family:var(--mono); font-size:10px; font-weight:700; letter-spacing:.5px; text-transform:uppercase; background:rgba(91,92,240,.15); color:var(--indigo); padding:3px 10px; border-radius:20px; }

.usage-row { display:grid; grid-template-columns:repeat(3,1fr); gap:20px; }
.usage-head { display:flex; justify-content:space-between; font-size:11px; color:var(--muted); margin-bottom:6px; }
.usage-nums { font-family:var(--mono); font-weight:700; color:var(--txt); }
.usage-max  { color:var(--faint); font-weight:400; }
.usage-bar-track { height:4px; background:rgba(255,255,255,.07); border-radius:4px; overflow:hidden; }
.usage-bar-fill  { height:100%; border-radius:4px; transition:width .4s; }

.billing-meta { display:flex; gap:16px; margin-top:16px; padding-top:16px; border-top:1px solid rgba(255,255,255,.06); font-size:11px; }
.fl { color:var(--faint); width:120px; flex:none; }
.fv { color:var(--txt); }
.fmono { font-family:var(--mono); font-size:10px; }

/* Scheduled reports */
.schedule-card { margin-top:16px; }
.schedule-head { display:flex; align-items:flex-start; justify-content:space-between; gap:14px; margin-bottom:14px; }
.schedule-title { font-family:var(--disp); font-weight:700; font-size:14px; }
.schedule-sub { color:var(--muted); font-size:11.5px; margin-top:3px; line-height:1.5; }
.schedule-lock { font-family:var(--mono); font-size:9.5px; color:var(--faint); background:rgba(255,255,255,.05); padding:4px 9px; border-radius:8px; white-space:nowrap; flex:none; }
.schedule-opts { display:flex; gap:8px; }
.schedule-opt {
  flex:1; padding:9px 0; border-radius:10px; border:1px solid rgba(255,255,255,.1);
  background:rgba(255,255,255,.04); color:var(--muted); font-family:var(--disp); font-weight:600;
  font-size:12.5px; cursor:pointer; transition:.15s;
}
.schedule-opt:hover:not(:disabled) { background:rgba(255,255,255,.08); color:var(--txt); }
.schedule-opt:disabled { opacity:.4; cursor:not-allowed; }
.schedule-opt.sched-active { background:linear-gradient(90deg,#5b5cf0,#4b4ce0); color:#fff; border-color:transparent; }
.schedule-last { margin-top:10px; font-size:10.5px; color:var(--faint); font-family:var(--mono); }

.portal-btn {
  display:flex; align-items:center; gap:6px; padding:7px 13px; border-radius:10px;
  background:rgba(255,255,255,.06); border:1px solid rgba(255,255,255,.1);
  color:var(--muted); font-family:var(--disp); font-weight:600; font-size:11.5px; cursor:pointer;
  transition:.15s;
}
.portal-btn:hover:not(:disabled) { background:rgba(255,255,255,.1); color:var(--txt); }
.portal-btn:disabled { opacity:.5; cursor:default; }
.portal-btn svg { width:13px; height:13px; }

/* Cycle toggle */
.cycle-toggle { display:inline-flex; background:rgba(255,255,255,.05); border-radius:12px; padding:3px; gap:3px; margin:24px 0 16px; }
.cycle-opt { padding:7px 18px; border:none; background:none; color:var(--muted); font-family:var(--disp); font-weight:700; font-size:12px; border-radius:10px; cursor:pointer; transition:.15s; display:flex; align-items:center; gap:7px; }
.cycle-opt.cyc-active { background:rgba(91,92,240,.25); color:var(--txt); }
.save-chip { font-family:var(--mono); font-size:8px; font-weight:700; letter-spacing:.4px; text-transform:uppercase; background:rgba(52,224,161,.2); color:#34e0a1; padding:1px 6px; border-radius:20px; }

/* Plans grid */
.plans-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(200px,1fr)); gap:12px; }

.plan-card {
  display:flex; flex-direction:column;
  background:rgba(255,255,255,.03); border:1px solid rgba(255,255,255,.07);
  border-radius:16px; padding:20px; position:relative; overflow:hidden;
  transition:border-color .15s;
}
.plan-card:hover { border-color:rgba(255,255,255,.14); }
.plan-current  { border-color:rgba(46,230,197,.35) !important; background:rgba(46,230,197,.04); }
.plan-featured { border-color:rgba(91,92,240,.4) !important; background:rgba(91,92,240,.05); }

.plan-featured-band { position:absolute; top:0; left:0; right:0; text-align:center; font-family:var(--mono); font-size:8.5px; font-weight:700; letter-spacing:.5px; text-transform:uppercase; background:linear-gradient(90deg,#5b5cf0,#4b4ce0); color:#fff; padding:4px 0; }
.plan-featured .plan-header { margin-top:20px; }

.plan-header { margin-bottom:14px; }
.plan-name  { font-family:var(--disp); font-size:16px; font-weight:800; color:var(--txt); margin-bottom:6px; }
.plan-price { display:flex; align-items:baseline; gap:3px; }
.plan-amt   { font-family:var(--disp); font-size:22px; font-weight:900; color:var(--txt); }
.plan-per   { font-family:var(--mono); font-size:10px; color:var(--faint); }
.plan-annual { font-family:var(--mono); font-size:9px; color:var(--teal); margin-top:3px; }

.plan-limits { display:flex; flex-direction:column; gap:6px; padding:12px 0; border-top:1px solid rgba(255,255,255,.06); border-bottom:1px solid rgba(255,255,255,.06); margin-bottom:12px; }
.plan-limit-row { display:flex; justify-content:space-between; font-size:11px; color:var(--muted); }
.plan-limit-row .fmono { color:var(--txt); }

.plan-features { display:flex; flex-direction:column; gap:5px; flex:1; margin-bottom:16px; }
.plan-feature { display:flex; align-items:center; gap:7px; font-family:var(--mono); font-size:9.5px; }
.feat-on  { color:var(--muted); }
.feat-off { color:var(--faint); opacity:.55; }
.feat-icon { width:14px; text-align:center; font-size:11px; }
.feat-on .feat-icon  { color:#34e0a1; }
.feat-off .feat-icon { color:var(--faint); }

.plan-action { margin-top:auto; }
.plan-btn { width:100%; padding:9px; border-radius:10px; border:none; font-family:var(--disp); font-weight:700; font-size:12px; cursor:pointer; transition:opacity .15s; display:flex; align-items:center; justify-content:center; gap:7px; }
.plan-btn:disabled { opacity:.55; cursor:default; }
.plan-btn-upgrade  { background:linear-gradient(90deg,#5b5cf0,#4b4ce0); color:#fff; }
.plan-btn-upgrade:hover:not(:disabled) { opacity:.88; }
.plan-btn-downgrade { background:rgba(255,255,255,.06); color:var(--muted); border:1px solid rgba(255,255,255,.1); }
.plan-btn-current  { background:rgba(46,230,197,.12); color:#2ee6c5; border:1px solid rgba(46,230,197,.25); cursor:default; }
.plan-btn-contact  { background:rgba(91,92,240,.12); color:var(--indigo); border:1px solid rgba(91,92,240,.2); }
.btn-spinner { width:14px; height:14px; border:2px solid rgba(255,255,255,.3); border-top-color:#fff; border-radius:50%; animation:spin .7s linear infinite; }

.billing-note { font-family:var(--mono); font-size:9.5px; color:var(--faint); margin-top:20px; line-height:1.65; }
.billing-note a { color:var(--indigo); }
</style>
