<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, watch } from 'vue'
import { api } from '@/api/client'

const props = defineProps<{ domainId: string }>()

const emit = defineEmits<{
  change: [{ fromDate: string | null, toDate: string | null, reporters: string[] }]
}>()

const histogram   = ref<any>(null)
const loading     = ref(false)
const fromIdx     = ref<number | null>(null)
const toIdx       = ref<number | null>(null)
const dragging    = ref(false)
const dragAnchor  = ref<number | null>(null)
const selectedReporters = ref<Set<string>>(new Set())

onMounted(() => { load(); window.addEventListener('mouseup', onGlobalMouseup) })
onUnmounted(() => { window.removeEventListener('mouseup', onGlobalMouseup) })
watch(() => props.domainId, load)

async function load() {
  if (!props.domainId) return
  loading.value = true
  histogram.value = null
  fromIdx.value = null
  toIdx.value = null
  selectedReporters.value = new Set()
  try {
    histogram.value = await api.dmarcHistogram(props.domainId)
    emitChange()
  } finally {
    loading.value = false
  }
}

const buckets   = computed(() => histogram.value?.buckets ?? [])
const reporters = computed(() => histogram.value?.reporters ?? [])
const maxTotal  = computed(() => Math.max(...buckets.value.map((b: any) => b.total), 1))

const selFrom = computed(() =>
  fromIdx.value === null ? null : Math.min(fromIdx.value, toIdx.value ?? fromIdx.value)
)
const selTo = computed(() =>
  toIdx.value === null ? null : Math.max(fromIdx.value ?? toIdx.value, toIdx.value)
)

function inRange(i: number) {
  if (selFrom.value === null) return true
  return i >= selFrom.value && i <= selTo.value!
}

function onBarMousedown(i: number, e: MouseEvent) {
  e.preventDefault()
  dragging.value = true
  dragAnchor.value = i
  fromIdx.value = i
  toIdx.value = i
}

function onBarMouseenter(i: number) {
  if (!dragging.value || dragAnchor.value === null) return
  fromIdx.value = Math.min(dragAnchor.value, i)
  toIdx.value   = Math.max(dragAnchor.value, i)
}

function onGlobalMouseup() {
  if (dragging.value) {
    dragging.value = false
    emitChange()
  }
}

function selectAll() {
  fromIdx.value = null
  toIdx.value   = null
  emitChange()
}

function setPreset(months: number) {
  const cutoff = new Date()
  cutoff.setUTCMonth(cutoff.getUTCMonth() - months)
  const cutoffStr = cutoff.toISOString().split('T')[0]
  const idx = buckets.value.findIndex((b: any) => b.week_start >= cutoffStr)
  if (idx === -1) {
    selectAll()
  } else {
    fromIdx.value = idx
    toIdx.value   = buckets.value.length - 1
    emitChange()
  }
}

function toggleReporter(r: string) {
  const next = new Set(selectedReporters.value)
  if (next.has(r)) { next.delete(r) } else { next.add(r) }
  selectedReporters.value = next
  emitChange()
}

function emitChange() {
  let fromDate: string | null = null
  let toDate:   string | null = null
  if (selFrom.value !== null) {
    fromDate = buckets.value[selFrom.value]?.week_start ?? null
    const ws  = buckets.value[selTo.value!]?.week_start
    if (ws) {
      const d = new Date(ws + 'T00:00:00Z')
      d.setUTCDate(d.getUTCDate() + 6)
      toDate = d.toISOString().split('T')[0]
    }
  }
  emit('change', {
    fromDate,
    toDate,
    reporters: [...selectedReporters.value],
  })
}

function fmt(iso: string | null | undefined, short = false): string {
  if (!iso) return '?'
  const d = new Date((iso.includes('T') ? iso : iso + 'T00:00:00Z'))
  return d.toLocaleDateString('en-GB', {
    month: short ? 'short' : 'short',
    day:   'numeric',
    year:  short ? undefined : '2-digit',
    timeZone: 'UTC',
  })
}

const contextLine = computed(() => {
  if (!histogram.value) return null
  const total    = histogram.value.total_reports
  const rCount   = reporters.value.length
  const earliest = fmt(histogram.value.earliest)
  const latest   = fmt(histogram.value.latest)
  let showing = 'all time'
  if (selFrom.value !== null) {
    const f = fmt(buckets.value[selFrom.value]?.week_start)
    const t = fmt(buckets.value[selTo.value!]?.week_start)
    showing = `${f} – ${t}`
  }
  return { total, rCount, earliest, latest, showing }
})

// Tick labels: show one label every N bars so they don't crowd
// Manual date input refs — updated by histogram selection and vice-versa
const inputFrom = ref<string>('')
const inputTo   = ref<string>('')

function onInputFrom(e: Event) {
  const val = (e.target as HTMLInputElement).value
  inputFrom.value = val
  if (!val) { selectAll(); return }
  // Snap histogram selection to nearest bucket >= this date
  const idx = buckets.value.findIndex((b: any) => b.week_start >= val)
  const newFrom = idx === -1 ? 0 : idx
  fromIdx.value = newFrom
  toIdx.value   = toIdx.value === null ? buckets.value.length - 1 : Math.max(newFrom, toIdx.value)
  emitChange()
}

function onInputTo(e: Event) {
  const val = (e.target as HTMLInputElement).value
  inputTo.value = val
  if (!val) { if (!inputFrom.value) { selectAll(); return } }
  // Snap histogram selection to last bucket whose week_start <= val
  let idx = -1
  for (let i = buckets.value.length - 1; i >= 0; i--) {
    if (buckets.value[i].week_start <= val) { idx = i; break }
  }
  toIdx.value   = idx === -1 ? buckets.value.length - 1 : idx
  fromIdx.value = fromIdx.value === null ? 0 : Math.min(fromIdx.value, toIdx.value as number)
  emitChange()
}

// Keep inputs in sync when histogram selection changes
watch([selFrom, selTo], () => {
  if (selFrom.value === null) {
    inputFrom.value = ''
    inputTo.value   = ''
  } else {
    inputFrom.value = buckets.value[selFrom.value]?.week_start ?? ''
    const ws = buckets.value[selTo.value!]?.week_start
    if (ws) {
      const d = new Date(ws + 'T00:00:00Z')
      d.setUTCDate(d.getUTCDate() + 6)
      inputTo.value = d.toISOString().split('T')[0]
    }
  }
})

const tickLabels = computed(() => {
  const n = buckets.value.length
  if (n === 0) return []
  const step = n <= 12 ? 1 : n <= 26 ? 2 : n <= 52 ? 4 : 8
  return buckets.value.map((b: any, i: number) => ({
    i,
    label: i % step === 0 ? fmt(b.week_start, true) : null,
  }))
})
</script>

<template>
  <div class="rt-root" @mouseleave="dragging && (dragging = false, emitChange())">

    <!-- Context line -->
    <div v-if="contextLine" class="rt-context">
      <span class="rt-ctx-chip">{{ contextLine.total }} report{{ contextLine.total !== 1 ? 's' : '' }}</span>
      <span class="rt-ctx-chip">{{ contextLine.rCount }} sender{{ contextLine.rCount !== 1 ? 's' : '' }}</span>
      <span class="rt-ctx-sep">·</span>
      <span class="rt-ctx-range">data: {{ contextLine.earliest }} – {{ contextLine.latest }}</span>
      <span class="rt-ctx-sep">·</span>
      <span class="rt-ctx-showing">showing: <b>{{ contextLine.showing }}</b></span>
    </div>
    <div v-else-if="loading" class="rt-context rt-loading">Loading report history…</div>

    <!-- Histogram -->
    <div v-if="buckets.length" class="rt-histogram" @mouseleave="dragging && null">
      <div
        v-for="(b, i) in buckets"
        :key="b.week_start"
        class="rt-bar-col"
        :class="{ 'in-range': inRange(i), 'out-range': !inRange(i) }"
        @mousedown="onBarMousedown(i, $event)"
        @mouseenter="onBarMouseenter(i)"
        :title="`${fmt(b.week_start)}: ${b.total.toLocaleString()} msgs (${b.report_count} report${b.report_count !== 1 ? 's' : ''})`"
      >
        <div class="rt-bar-inner">
          <div class="rt-bar-pass" :style="{ height: (b.pass_count  / maxTotal * 100) + '%' }" />
          <div class="rt-bar-fail" :style="{ height: (b.fail_count  / maxTotal * 100) + '%' }" />
        </div>
      </div>
    </div>
    <div v-else-if="!loading" class="rt-empty">No report history yet — reports from Google, Microsoft and other senders will appear here.</div>

    <!-- Tick labels -->
    <div v-if="buckets.length" class="rt-ticks">
      <div v-for="t in tickLabels" :key="t.i" class="rt-tick-col">
        <span v-if="t.label" class="rt-tick-label">{{ t.label }}</span>
      </div>
    </div>

    <!-- Controls row: presets + date inputs + clear -->
    <div v-if="buckets.length" class="rt-controls">
      <div class="rt-presets">
        <button class="rt-preset" :class="{ active: selFrom === null }" @click="selectAll">All time</button>
        <button class="rt-preset" @click="setPreset(1)">Last month</button>
        <button class="rt-preset" @click="setPreset(3)">Last 3 months</button>
        <button class="rt-preset" @click="setPreset(6)">Last 6 months</button>
      </div>
      <div class="rt-date-inputs">
        <input type="date" class="rt-date-input" :value="inputFrom" @change="onInputFrom" :min="histogram?.earliest?.slice(0,10)" :max="histogram?.latest?.slice(0,10)" title="From date" />
        <span class="rt-date-sep">–</span>
        <input type="date" class="rt-date-input" :value="inputTo" @change="onInputTo" :min="histogram?.earliest?.slice(0,10)" :max="histogram?.latest?.slice(0,10)" title="To date" />
      </div>
      <button v-if="selFrom !== null" class="rt-clear" @click="selectAll">✕ Clear</button>
    </div>

    <!-- Reporter pills -->
    <div v-if="reporters.length > 1" class="rt-reporters">
      <span class="rt-rep-label">Senders:</span>
      <button
        v-for="r in reporters"
        :key="r"
        class="rt-rep-pill"
        :class="{ active: selectedReporters.size === 0 || selectedReporters.has(r) }"
        @click="toggleReporter(r)"
      >{{ r }}</button>
      <button v-if="selectedReporters.size > 0" class="rt-rep-clear" @click="selectedReporters.clear(); emitChange()">All senders</button>
    </div>

  </div>
</template>

<style scoped>
.rt-root {
  user-select: none;
  margin-bottom: 16px;
}

/* Context line */
.rt-context {
  display: flex; align-items: center; gap: 8px; flex-wrap: wrap;
  font-family: var(--mono); font-size: 10.5px; color: var(--muted);
  margin-bottom: 10px; letter-spacing: .2px;
}
.rt-ctx-chip {
  background: rgba(255,255,255,.06); border: 1px solid var(--line2);
  border-radius: 6px; padding: 2px 8px; color: var(--txt); font-weight: 600;
}
.rt-ctx-sep { color: var(--faint); }
.rt-ctx-range { color: var(--faint); }
.rt-ctx-showing b { color: var(--teal); }
.rt-loading { color: var(--faint); font-style: italic; }

/* Histogram */
.rt-histogram {
  display: flex; align-items: flex-end; gap: 2px;
  height: 52px; cursor: col-resize; padding: 0 1px;
}
.rt-bar-col {
  flex: 1; min-width: 3px; height: 100%;
  display: flex; align-items: flex-end;
  border-radius: 3px 3px 0 0; transition: opacity .1s;
}
.rt-bar-col.out-range { opacity: .2; }
.rt-bar-col.in-range  { opacity: 1; }
.rt-bar-col:hover { outline: 1px solid rgba(91,92,240,.5); }
.rt-bar-inner {
  width: 100%; display: flex; flex-direction: column-reverse;
  align-items: stretch; gap: 0;
}
.rt-bar-pass { background: #34e0a1; border-radius: 2px 2px 0 0; min-height: 1px; }
.rt-bar-fail { background: #ff5050; border-radius: 0; min-height: 1px; }
/* When only pass exists, give it rounded bottom too */
.rt-bar-inner .rt-bar-fail:first-child { border-radius: 2px 2px 0 0; }

/* Tick labels */
.rt-ticks {
  display: flex; gap: 2px; margin-top: 3px; padding: 0 1px;
}
.rt-tick-col {
  flex: 1; min-width: 3px; display: flex; justify-content: center;
}
.rt-tick-label {
  font-family: var(--mono); font-size: 8.5px; color: var(--faint);
  white-space: nowrap; letter-spacing: .2px;
}

/* Controls */
.rt-controls {
  display: flex; align-items: center; justify-content: space-between;
  margin-top: 8px; flex-wrap: wrap; gap: 6px;
}
.rt-presets { display: flex; gap: 4px; flex-wrap: wrap; }
.rt-preset {
  font-family: var(--mono); font-size: 10.5px;
  background: rgba(255,255,255,.04); border: 1px solid var(--line2);
  color: var(--muted); border-radius: 7px; padding: 4px 10px; cursor: pointer;
  transition: all .15s;
}
.rt-preset:hover { color: var(--txt); border-color: rgba(91,92,240,.5); }
.rt-preset.active { background: rgba(91,92,240,.15); border-color: rgba(91,92,240,.5); color: #9aa6ff; }
.rt-clear {
  font-family: var(--mono); font-size: 10px; color: var(--muted);
  background: none; border: none; cursor: pointer; padding: 0;
}
.rt-clear:hover { color: var(--bad); }

/* Date inputs */
.rt-date-inputs { display: flex; align-items: center; gap: 4px; }
.rt-date-input {
  font-family: var(--mono); font-size: 10.5px; padding: 4px 8px;
  background: rgba(255,255,255,.04); border: 1px solid var(--line2);
  border-radius: 7px; color: var(--txt); outline: none;
  transition: border-color .15s; cursor: pointer;
}
.rt-date-input:focus { border-color: rgba(91,92,240,.5); }
.rt-date-input::-webkit-calendar-picker-indicator { filter: invert(.5) sepia(1) hue-rotate(190deg); cursor: pointer; }
.rt-date-sep { font-family: var(--mono); font-size: 10px; color: var(--faint); }

/* Reporter pills */
.rt-reporters {
  display: flex; align-items: center; gap: 6px; flex-wrap: wrap;
  margin-top: 10px;
}
.rt-rep-label {
  font-family: var(--mono); font-size: 9.5px; color: var(--faint);
  letter-spacing: .5px; text-transform: uppercase;
}
.rt-rep-pill {
  font-family: var(--mono); font-size: 10.5px; padding: 3px 10px;
  border-radius: 8px; border: 1px solid var(--line2); cursor: pointer;
  background: rgba(255,255,255,.04); color: var(--muted); transition: all .15s;
}
.rt-rep-pill.active {
  background: rgba(52,224,161,.1); border-color: rgba(52,224,161,.35); color: var(--good);
}
.rt-rep-pill:not(.active) { opacity: .4; }
.rt-rep-clear {
  font-family: var(--mono); font-size: 10px; color: var(--teal);
  background: none; border: none; cursor: pointer; padding: 0; text-decoration: underline;
}

/* Empty */
.rt-empty {
  font-size: 12.5px; color: var(--muted); padding: 16px 0;
  border: 1px dashed var(--line2); border-radius: 10px; text-align: center;
  margin-bottom: 8px;
}
</style>
