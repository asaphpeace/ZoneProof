<script setup lang="ts">
import { computed } from 'vue'
import { useBrandGuardStore } from '@/stores/brandGuard'

// Page title row + the scan status every Brand Guard page needs (progress, a failed run, the last scan error).
defineProps<{ title: string; crumb?: string; sub?: string; noScan?: boolean }>()

const store = useBrandGuardStore()
const PHASE_LABEL: Record<string, string> = {
  discovering: 'Finding candidate names', certificates: 'Checking certificate logs', dns: 'Checking DNS',
  registration: 'Looking up registration dates', mail: 'Checking mail setup', scoring: 'Scoring candidates',
}
const progressLabel = computed(() => {
  const r = store.run
  if (!r) return ''
  if (r.status === 'queued') return 'Scan queued…'
  const label = PHASE_LABEL[r.phase] ?? 'Scanning'
  return r.progress_total > 0 ? `${label} (${r.progress_done} of ${r.progress_total})` : `${label}…`
})
const pct = computed(() => (store.run && store.run.progress_total > 0 ? Math.min(100, Math.round((store.run.progress_done / store.run.progress_total) * 100)) : 0))
</script>

<template>
  <header class="hd">
    <div class="row">
      <div class="txt">
        <nav v-if="crumb" class="crumb" aria-label="Breadcrumb"><RouterLink :to="{ name: 'brand-guard' }">Brand Guard</RouterLink> / {{ crumb }}</nav>
        <h1>{{ title }}</h1>
        <p v-if="sub" class="sub">{{ sub }}</p>
      </div>
      <div class="acts">
        <template v-if="store.profiles.length > 1">
          <label class="sr" for="bg-brand">Brand</label>
          <select id="bg-brand" class="brandsel" :value="store.profile?.id" @change="store.select(($event.target as HTMLSelectElement).value)">
            <option v-for="p in store.profiles" :key="p.id" :value="p.id">{{ p.brand_name }} · {{ p.primary_domain }}</option>
          </select>
        </template>
        <slot name="actions" />
        <button v-if="store.profile" type="button" class="btn ghost" @click="store.adding = true">+ Add brand</button>
        <button v-if="!noScan && store.profile" type="button" class="btn" :disabled="store.scanning" @click="store.scan()">
          {{ store.scanning ? 'Scanning…' : 'Scan now' }}
        </button>
      </div>
    </div>
    <div v-if="store.scanning" class="progress" role="status" aria-live="polite">
      <div class="pt">{{ progressLabel }}</div>
      <div class="pb"><i :style="{ width: pct + '%' }" /></div>
    </div>
    <p v-else-if="store.run?.status === 'failed'" class="note">{{ store.run.error || 'The last scan failed.' }} Use “Scan now” to try again.</p>
    <p v-if="store.profile?.last_scan_error" class="note">{{ store.profile.last_scan_error }}</p>
  </header>
</template>

<style scoped>
.hd { display: flex; flex-direction: column; gap: 12px; margin-bottom: 18px; }
.row { display: flex; justify-content: space-between; align-items: flex-end; gap: 18px; flex-wrap: wrap; }
.txt { display: flex; flex-direction: column; gap: 6px; min-width: 0; }
.crumb { font-family: var(--mono); font-size: 11.5px; color: var(--muted); }
.crumb a { color: var(--indigo); text-decoration: none; }
h1 { margin: 0; font-family: var(--disp); font-size: 26px; font-weight: 800; letter-spacing: -.8px; }
.sub { margin: 0; font-size: 13.5px; color: var(--muted); max-width: 70ch; }
.sr { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; }
.brandsel { min-height: 40px; max-width: 260px; padding: 0 12px; border-radius: 10px; background: rgba(255,255,255,.04); border: 1px solid var(--line2); color: var(--txt); font: 500 13px var(--body); }
.acts { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
.btn { min-height: 40px; background: linear-gradient(90deg, #5b5cf0, #4b4ce0); color: #fff; border: 0; border-radius: 10px; padding: 0 18px; font-family: var(--mono); font-size: 12px; cursor: pointer; }
.btn:disabled { opacity: .5; cursor: default; }
.btn.ghost { background: rgba(255,255,255,.04); border: 1px solid var(--line2); color: var(--txt); }
.progress .pt { font-family: var(--mono); font-size: 11px; color: var(--muted); margin-bottom: 6px; }
.pb { height: 6px; background: rgba(255,255,255,.08); border-radius: 4px; overflow: hidden; }
.pb i { display: block; height: 100%; background: linear-gradient(90deg, #5b5cf0, #4b4ce0); transition: width .4s ease; }
.note { margin: 0; background: rgba(245,197,66,.08); border: 1px solid rgba(245,197,66,.25); color: var(--warn); border-radius: 10px; padding: 8px 12px; font-size: 12.5px; }
</style>
