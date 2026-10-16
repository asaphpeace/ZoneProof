<script setup lang="ts">
import { computed, ref } from 'vue'
import { api } from '@/api/client'
import { useBrandGuardStore } from '@/stores/brandGuard'
import { useUiStore } from '@/stores/ui'
import { DECISION_TEXT } from './brandLabels'

// One place for the analyst's decision buttons (drawer and bulk bar). "Not a threat" asks WHY, because the three reasons
// mean different things: yours (added to your official domains), a partner, or simply unrelated.
const props = defineProps<{ items: any[]; compact?: boolean }>()
const emit = defineEmits<{ decided: [] }>()

const store = useBrandGuardStore()
const ui = useUiStore()
const asking = ref(false)
const reason = ref<'customer_owned' | 'partner' | 'false_positive'>('false_positive')
const busy = ref(false)
const more = ref(false)

const REASONS = [
  { value: 'false_positive', label: 'Unrelated to my brand', help: 'A different business or an innocent name.' },
  { value: 'customer_owned', label: 'It is mine', help: 'Your own registration. It is added to your official domains.' },
  { value: 'partner', label: 'A partner or supplier', help: 'Allowed to use your name.' },
] as const

const plural = computed(() => (props.items.length > 1 ? `${props.items.length} candidates` : props.items[0]?.candidate_domain_unicode ?? ''))

async function apply(status: string, note?: string) {
  busy.value = true
  try {
    for (const c of props.items) await store.decide(c.id, status, note)
    if (status === 'customer_owned') await addToOfficial()
    ui.toast(`${DECISION_TEXT[status] ?? 'Updated'}: ${plural.value}`)
    asking.value = false
    more.value = false
    await store.refreshAfterChange()
    emit('decided')
  } catch (e: any) {
    ui.toast(e.message || 'Update failed', 'error')
  } finally { busy.value = false }
}

// A look-alike the customer says is theirs becomes an official domain, so it is never flagged again and feeds the baseline.
// Hosts under a hosting platform or subdomains are not registrations of their own, so they are left out.
async function addToOfficial() {
  const profile = store.profile
  if (!profile) return
  const add = props.items
    .filter(c => c.threat_class !== 'subdomain_abuse' && !c.enrichment?.platform_suffix)
    .map(c => c.candidate_domain)
    .filter(d => !(profile.official_domains || []).includes(d))
  if (!add.length) return
  const updated = await api.brandUpdateProfile(profile.id, { official_domains: [...(profile.official_domains || []), ...add] })
  store.applyProfile(updated)
}
</script>

<template>
  <div class="dec" :class="{ compact }">
    <div class="row">
      <button type="button" class="btn primary" :disabled="busy" @click="apply('confirmed')">Confirm impersonation</button>
      <button type="button" class="btn" :disabled="busy" @click="apply('monitoring')">Watch</button>
      <button type="button" class="btn" :disabled="busy" :aria-expanded="asking" @click="asking = !asking; more = false">Not a threat…</button>
      <button type="button" class="btn ghost" :aria-expanded="more" @click="more = !more; asking = false">More</button>
    </div>
    <div v-if="more" class="panel">
      <button type="button" class="btn" :disabled="busy" @click="apply('takedown')">Takedown requested</button>
      <button type="button" class="btn" :disabled="busy" @click="apply('ignored')">Ignore</button>
      <span class="help">Cases and takedown sending are not part of Brand Guard yet; this only records what you did elsewhere.</span>
    </div>
    <fieldset v-if="asking" class="panel why">
      <legend>Why is it not a threat?</legend>
      <label v-for="r in REASONS" :key="r.value" class="opt">
        <input v-model="reason" type="radio" name="reason" :value="r.value" />
        <span><b>{{ r.label }}</b><small>{{ r.help }}</small></span>
      </label>
      <div class="row">
        <button type="button" class="btn primary" :disabled="busy" @click="apply(reason)">Mark as not a threat</button>
        <button type="button" class="btn ghost" @click="asking = false">Cancel</button>
      </div>
    </fieldset>
  </div>
</template>

<style scoped>
.dec { display: flex; flex-direction: column; gap: 10px; }
.row { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
.btn { min-height: 38px; padding: 0 14px; border-radius: 10px; border: 1px solid var(--line2); background: rgba(255,255,255,.03); color: var(--txt); font: 600 12.5px var(--body); cursor: pointer; }
.btn:hover:not(:disabled) { border-color: var(--indigo); }
.btn:disabled { opacity: .5; cursor: default; }
.btn.primary { background: linear-gradient(90deg, #5b5cf0, #4b4ce0); border-color: transparent; color: #fff; }
.btn.ghost { background: transparent; color: var(--muted); }
.compact .btn { min-height: 34px; }
.panel { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; padding: 12px; border-radius: 12px; border: 1px solid var(--line); background: rgba(255,255,255,.025); }
.help { font-size: 12px; color: var(--muted); }
.why { flex-direction: column; align-items: stretch; margin: 0; }
legend { font-family: var(--mono); font-size: 10px; letter-spacing: .6px; text-transform: uppercase; color: var(--muted); padding: 0 6px; }
.opt { display: flex; gap: 10px; align-items: flex-start; padding: 8px 6px; border-radius: 8px; cursor: pointer; }
.opt:hover { background: rgba(255,255,255,.04); }
.opt input { margin-top: 4px; accent-color: var(--indigo); }
.opt b { display: block; font-size: 13px; font-weight: 600; }
.opt small { display: block; color: var(--muted); font-size: 12px; }
</style>
