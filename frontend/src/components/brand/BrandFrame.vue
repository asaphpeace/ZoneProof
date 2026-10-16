<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { api } from '@/api/client'
import { useDomainsStore } from '@/stores/domains'
import { useBrandGuardStore } from '@/stores/brandGuard'
import { useUiStore } from '@/stores/ui'
import PlanGate from '@/components/ui/PlanGate.vue'

// Wraps every Brand Guard page: loads the shared state once and shows the loading, plan-gate and first-run setup states,
// so each page only has to draw what it is for.
const store = useBrandGuardStore()
const domains = useDomainsStore()
const ui = useUiStore()

const form = ref({ domain_id: '', brand_name: '', keywords: '', official_domains: '' })
const creating = ref(false)
// Verified domains that are not already protected (a domain has at most one brand).
const verified = computed(() => domains.list.filter(d => d.ownership_verified && !store.profiles.some(p => p.domain_id === d.id)))
const csv = (v: string) => v.split(/[,\n]/).map(s => s.trim()).filter(Boolean)

onMounted(async () => {
  await domains.fetch()
  await store.ensureLoaded()
})

async function create() {
  creating.value = true
  try {
    const created = await api.brandCreateProfile({
      domain_id: form.value.domain_id, brand_name: form.value.brand_name,
      keywords: csv(form.value.keywords), official_domains: csv(form.value.official_domains),
    })
    // Learn what the real brand looks like first, so the very first scan can recognise the customer's own infrastructure.
    let fingerprinted: any = null
    try { fingerprinted = await api.brandFingerprint(created.id) } catch (e: any) { ui.toast(e.message || 'Could not read your site yet; you can rebuild it from the brand profile.', 'error') }
    ui.toast('Brand Guard enabled. Running the first scan…')
    await store.load()
    if (fingerprinted) store.applyProfile(fingerprinted)
    await store.select(created.id)   // a second brand: show the new one, and scan it rather than the previous one
    store.adding = false
    form.value = { domain_id: '', brand_name: '', keywords: '', official_domains: '' }
    await store.scan()
  } catch (e: any) {
    if (/not available|plan/i.test(e.message)) store.gated = true
    ui.toast(e.message || 'Could not enable Brand Guard', 'error')
  } finally { creating.value = false }
}
</script>

<template>
  <div class="frame">
    <PlanGate v-if="store.gated" feature="Brand Guard" required-plan="Starter" />
    <div v-else-if="store.loading && !store.loaded" class="state" role="status">Loading Brand Guard…</div>
    <section v-else-if="!store.profile || store.adding" class="setup" aria-labelledby="bgs-t">
      <h1 id="bgs-t">{{ store.profile ? 'Add a brand' : 'Protect your brand' }}</h1>
      <p class="sub">Tell us what your legitimate brand looks like. We compare everything we discover against it, so the more precise this is, the fewer false alarms you get.</p>
      <label>Domain to protect
        <select v-model="form.domain_id">
          <option value="" disabled>Choose a verified domain…</option>
          <option v-for="d in verified" :key="d.id" :value="d.id">{{ d.domain }}</option>
        </select>
      </label>
      <p v-if="!verified.length" class="hint">{{ store.profile ? 'Every verified domain is already protected. Verify another domain first.' : 'No verified domains yet. Verify ownership of a domain first.' }}</p>
      <label>Brand name<input v-model="form.brand_name" placeholder="Acme Financial" /></label>
      <label>Related keywords <span class="opt">(products, words attackers might add; comma separated)</span><input v-model="form.keywords" placeholder="pay, wallet, portal" /></label>
      <label>Other domains you own <span class="opt">(so we never flag them)</span><input v-model="form.official_domains" placeholder="acmefinancial.com, acme-fin.co.za" /></label>
      <button type="button" class="btn" :disabled="creating || !form.domain_id || form.brand_name.trim().length < 2" @click="create">
        {{ creating ? 'Enabling…' : 'Enable Brand Guard' }}
      </button>
      <button v-if="store.profile" type="button" class="btn ghost" :disabled="creating" @click="store.adding = false">Cancel</button>
    </section>
    <slot v-else />
  </div>
</template>

<style scoped>
.frame { max-width: 1200px; }
.state { color: var(--muted); text-align: center; padding: 60px 0; font-size: 13px; }
.setup { display: grid; gap: 14px; max-width: 560px; background: var(--glass); border: 1px solid var(--line); border-radius: 16px; padding: 24px; }
h1 { font-family: var(--disp); font-size: 22px; font-weight: 800; margin: 0; }
.sub { color: var(--muted); font-size: 13px; margin: 0; }
label { display: grid; gap: 6px; font-family: var(--mono); font-size: 11px; color: var(--muted); }
.opt { color: var(--faint); }
input, select { background: rgba(255,255,255,.04); border: 1px solid var(--line2); border-radius: 10px; padding: 10px 12px; color: var(--txt); font-family: var(--body); font-size: 13px; }
.hint { font-size: 12px; color: var(--faint); margin: 0; }
.btn { background: linear-gradient(90deg, #5b5cf0, #4b4ce0); color: #fff; border: 0; border-radius: 10px; padding: 10px 18px; font-family: var(--mono); font-size: 12px; cursor: pointer; }
.btn:disabled { opacity: .5; cursor: default; }
.btn.ghost { background: rgba(255,255,255,.04); border: 1px solid var(--line2); color: var(--txt); }
</style>
