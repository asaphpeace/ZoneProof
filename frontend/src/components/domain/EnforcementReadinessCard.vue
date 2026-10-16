<script setup lang="ts">
import { ref, computed } from 'vue'
import PlatformSetupModal from './PlatformSetupModal.vue'

// PAIN_POINT_RESOLUTION_PLAN.md Pain 4 — turns "should I enforce" from one
// aggregate number into a literal checklist: every significant source,
// one row each, with its specific fix linked inline.
const props = defineProps<{
  domainId: string
  sourceReadiness: {
    source_org: string
    classification: string
    total_count: number
    fail_count: number
    status: 'ready' | 'blocking' | 'will_be_blocked' | 'below_floor'
  }[]
}>()

const setupPlatformKey = ref<string | null>(null)

// Same best-effort name->key mapping as DmarcAuthDrawer.vue — source_org
// here comes from the same classifier output, so the same map applies.
const ORG_TO_PLATFORM_KEY: Record<string, string> = {
  'salesforce': 'salesforce_mc', 'mailchimp': 'mailchimp', 'sendgrid': 'sendgrid',
  'amazon ses': 'amazon_ses', 'mailgun': 'mailgun', 'postmark': 'postmark',
  'sparkpost': 'sparkpost', 'hubspot': 'hubspot', 'klaviyo': 'klaviyo',
  'zendesk': 'zendesk', 'constant contact': 'constant_contact',
  'google workspace': 'google_workspace', 'microsoft 365': 'microsoft_365',
}
function platformKeyFor(org: string): string | null {
  return ORG_TO_PLATFORM_KEY[org.trim().toLowerCase()] ?? null
}

const counts = computed(() => {
  const gating = props.sourceReadiness.filter(r => r.status !== 'below_floor')
  const ready = gating.filter(r => r.status === 'ready' || r.status === 'will_be_blocked').length
  return { ready, total: gating.length }
})

const STATUS_ICON: Record<string, string> = { ready: '✓', blocking: '⚠', will_be_blocked: '○', below_floor: '·' }
const STATUS_LABEL: Record<string, string> = {
  ready: 'Ready', blocking: 'Blocking', will_be_blocked: 'Will be blocked (intended)', below_floor: 'Below volume floor',
}
</script>

<template>
  <div v-if="sourceReadiness.length" class="readiness-card">
    <div class="rc-header">
      <span class="rc-title">Enforcement readiness</span>
      <span class="rc-pill" :class="{ complete: counts.ready === counts.total }">
        {{ counts.ready }} / {{ counts.total }} sources ready
      </span>
    </div>

    <div v-for="r in sourceReadiness" :key="r.source_org" :class="['rc-row', r.status]">
      <span class="rc-icon" :class="r.status">{{ STATUS_ICON[r.status] }}</span>
      <div class="rc-main">
        <span class="rc-org">{{ r.source_org }}</span>
        <span class="rc-status-label">{{ STATUS_LABEL[r.status] }}</span>
        <span v-if="r.fail_count > 0" class="rc-vol">{{ r.fail_count.toLocaleString() }} of {{ r.total_count.toLocaleString() }} would be acted on</span>
      </div>
      <button
        v-if="r.status === 'blocking' && platformKeyFor(r.source_org)"
        class="rc-fix-btn"
        @click="setupPlatformKey = platformKeyFor(r.source_org)"
      >Fix this →</button>
    </div>

    <PlatformSetupModal
      v-if="setupPlatformKey"
      :domain-id="domainId"
      :platform-key="setupPlatformKey"
      @close="setupPlatformKey = null"
      @done="setupPlatformKey = null"
    />
  </div>
</template>

<style scoped>
.readiness-card {
  background: var(--glass); border: 1px solid var(--line); border-radius: 16px;
  padding: 16px 18px; margin-bottom: 16px;
}
.rc-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 10px; flex-wrap: wrap; gap: 8px; }
.rc-title { font-family: var(--disp); font-weight: 700; font-size: 13.5px; }
.rc-pill {
  font-family: var(--mono); font-size: 11px; font-weight: 700; color: var(--amber);
  background: rgba(245,197,66,.12); border: 1px solid rgba(245,197,66,.3);
  padding: 4px 11px; border-radius: 20px;
}
.rc-pill.complete { color: var(--good); background: rgba(52,224,161,.12); border-color: rgba(52,224,161,.3); }

.rc-row { display: flex; align-items: center; gap: 10px; padding: 9px 4px; border-bottom: 1px solid rgba(255,255,255,.04); }
.rc-row:last-of-type { border-bottom: none; }
.rc-row.below_floor { opacity: .55; }
.rc-icon { font-weight: 800; font-size: 13px; flex: none; width: 18px; text-align: center; }
.rc-icon.ready { color: var(--good); }
.rc-icon.blocking { color: var(--bad); }
.rc-icon.will_be_blocked { color: var(--faint); }
.rc-icon.below_floor { color: var(--faint); }
.rc-main { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 1px; }
.rc-org { font-size: 12.5px; font-weight: 600; color: var(--txt); }
.rc-status-label { font-family: var(--mono); font-size: 10px; color: var(--faint); }
.rc-vol { font-size: 10.5px; color: var(--amber); }
.rc-fix-btn {
  flex: none; background: rgba(91,92,240,.16); border: 1px solid rgba(91,92,240,.35); color: #9aa6ff;
  border-radius: 9px; padding: 6px 12px; font-size: 11px; font-weight: 700; cursor: pointer;
}
</style>
