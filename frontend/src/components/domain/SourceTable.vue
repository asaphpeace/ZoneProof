<script setup lang="ts">
import { ref } from 'vue'
import StatusChip from '@/components/ui/StatusChip.vue'
import { useUiStore } from '@/stores/ui'

defineProps<{ sources: any[] }>()
const emit = defineEmits<{ 'open-drawer': [ip: any] }>()

const ui = useUiStore()
const openSources = ref<Set<string>>(new Set())

const toggle = (key: string) => {
  if (openSources.value.has(key)) openSources.value.delete(key)
  else openSources.value.add(key)
}

function openClassification(source: any) {
  ui.openDrawer('Source classification', {
    component: null,
    html: `
      <div style="font-size:13px;line-height:1.65;color:#dbe0f2">
        <div style="font-family:var(--mono);font-size:9.5px;letter-spacing:1px;text-transform:uppercase;color:var(--faint);margin:14px 0 7px">Classification</div>
        <b style="color:var(--teal)">${source.classification_label}</b> — ${source.classification_confidence}% confidence
        <div style="font-family:var(--mono);font-size:9.5px;letter-spacing:1px;text-transform:uppercase;color:var(--faint);margin:14px 0 7px">Reasoning</div>
        ${source.classification_reason}
        <div style="font-family:var(--mono);font-size:9.5px;letter-spacing:1px;text-transform:uppercase;color:var(--faint);margin:14px 0 7px">Recommended action</div>
        ${source.recommended_action}
      </div>
    `,
  })
}

function fmtPeriod(iso: string | null | undefined): string {
  if (!iso) return '?'
  const d = new Date(iso)
  return d.toLocaleDateString('en-GB', { month: 'short', day: 'numeric', timeZone: 'UTC' })
}

function relativeActive(iso: string | null | undefined): string {
  if (!iso) return ''
  const diff = Math.floor((Date.now() - new Date(iso).getTime()) / 86400000)
  if (diff === 0) return 'active today'
  if (diff === 1) return 'active yesterday'
  if (diff < 7) return `active ${diff}d ago`
  if (diff < 30) return `active ${Math.floor(diff / 7)}w ago`
  return `active ${Math.floor(diff / 30)}mo ago`
}

const mini = (v: string | null) => {
  if (!v) return 'f'
  if (v === 'pass') return 'p'
  if (v === 'softfail' || v === 'neutral') return 'w'
  return 'f'
}

// Envelope indicator: null = clean, 'esp' = known ESP mismatch, 'mismatch' = unknown mismatch
function envelopeState(ip: any): 'clean' | 'esp' | 'mismatch' {
  if (!ip.envelope_mismatch) return 'clean'
  if (ip.known_esp) return 'esp'
  return 'mismatch'
}
</script>

<template>
  <div>
    <!-- Table header -->
    <div class="thead-row">
      <span>Source</span>
      <span>Volume</span>
      <span>SPF</span>
      <span>DKIM</span>
      <span>DMARC</span>
      <span>Class</span>
      <span></span>
    </div>

    <!-- Source rows -->
    <div v-for="src in sources" :key="src.source_org" class="exp" :class="{ open: openSources.has(src.source_org) }">
      <div class="exp-head srchead" @click="toggle(src.source_org)" tabindex="0" role="button" @keydown.enter.prevent="toggle(src.source_org)" @keydown.space.prevent="toggle(src.source_org)">
        <div class="src">
          <div class="srci">{{ src.source_org[0] }}</div>
          <div>
            <div class="sn">{{ src.source_org }}</div>
            <div class="si">{{ src.ips[0]?.rdns || src.ips[0]?.source_ip || '' }}</div>
          </div>
        </div>
        <div class="vol-cell">
          <div class="vol">{{ src.volume.toLocaleString() }}</div>
          <div v-if="src.report_count" class="vol-period">
            {{ src.report_count }} report{{ src.report_count !== 1 ? 's' : '' }}
            <template v-if="src.earliest_period"> · {{ fmtPeriod(src.earliest_period) }}
              <template v-if="src.latest_period && fmtPeriod(src.latest_period) !== fmtPeriod(src.earliest_period)"> – {{ fmtPeriod(src.latest_period) }}</template>
            </template>
          </div>
          <div v-if="src.latest_period" class="vol-relative">{{ relativeActive(src.latest_period) }}</div>
        </div>
        <StatusChip variant="am" :value="src.spf_alignment" />
        <StatusChip variant="am" :value="src.dkim_alignment === 'NONE' ? 'NONE' : src.dkim_alignment" />
        <StatusChip variant="am" :value="src.dmarc_result" />
        <span class="cls-chip" :class="src.classification" @click.stop="openClassification(src)" tabindex="0" role="button" @keydown.enter.prevent="openClassification(src)" @keydown.space.prevent="openClassification(src)">
          {{ src.classification_label }}
        </span>
        <svg class="chev" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M9 18l6-6-6-6"/>
        </svg>
      </div>

      <!-- IP rows -->
      <div class="exp-body">
        <div class="ipwrap">
          <div class="iphead">
            <span>Sending IP</span>
            <span>rDNS</span>
            <span>Volume</span>
            <span>SPF</span>
            <span>DKIM</span>
            <span>DMARC</span>
            <span>Envelope</span>
            <span></span>
          </div>

          <div
            v-for="ip in src.ips"
            :key="ip.source_ip"
            class="iprow"
            @click="emit('open-drawer', ip)"
          >
            <span class="ipa">{{ ip.source_ip }}</span>
            <span class="mono-sm">{{ ip.rdns || '—' }}</span>
            <span class="mono-sm">{{ ip.volume.toLocaleString() }}</span>
            <StatusChip variant="mini" :value="mini(ip.spf_result)" />
            <StatusChip variant="mini" :value="mini(ip.dkim_result)" />
            <StatusChip variant="mini" :value="ip.dmarc_result === 'pass' ? 'p' : 'f'" />

            <!-- Envelope indicator -->
            <span v-if="envelopeState(ip) === 'clean'" class="env-clean">—</span>
            <span v-else-if="envelopeState(ip) === 'esp'" class="env-badge esp" :title="`${ip.known_esp} bounce routing`">
              <span class="env-dot esp" />{{ ip.known_esp }}
            </span>
            <span v-else class="env-badge mismatch" title="Envelope domain doesn't match header-from">
              <span class="env-dot mismatch" />Mismatch
            </span>

            <svg class="row-arrow" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M9 18l6-6-6-6"/>
            </svg>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.thead-row {
  display: grid;
  grid-template-columns: 1.7fr .85fr .85fr .95fr .75fr 1fr 20px;
  gap: 11px; font-family: var(--mono); font-size: 9px; letter-spacing: .8px;
  text-transform: uppercase; color: var(--faint);
  padding: 0 4px 11px; border-bottom: 1px solid var(--line);
}
.srchead {
  display: grid;
  grid-template-columns: 1.7fr .85fr .85fr .95fr .75fr 1fr 20px;
  gap: 11px; align-items: center; padding: 13px 4px; cursor: pointer;
  border-bottom: 1px solid var(--line); transition: .15s;
}
.srchead:hover { background: rgba(255,255,255,.03); }
.src { display: flex; align-items: center; gap: 11px; }
.srci { width: 30px; height: 30px; border-radius: 9px; background: rgba(255,255,255,.06); display: grid; place-items: center; font-family: var(--disp); font-weight: 700; font-size: 12px; flex: none; }
.sn { font-size: 13px; font-weight: 600; }
.si { font-family: var(--mono); font-size: 10px; color: var(--faint); }
.vol-cell { display: flex; flex-direction: column; gap: 2px; }
.vol { font-family: var(--mono); font-size: 12.5px; }
.vol-period { font-family: var(--mono); font-size: 9px; color: var(--faint); letter-spacing: .2px; }
.vol-relative { font-family: var(--mono); font-size: 9px; color: var(--teal); opacity: .7; }
.cls-chip { font-size: 10px; font-weight: 600; padding: 5px 10px; border-radius: 20px; cursor: pointer; transition: .15s; }
.cls-chip:hover { opacity: .8; }
.cls-chip.authorized { background: rgba(52,224,161,.14); color: var(--good); }
.cls-chip.forwarded  { background: rgba(91,92,240,.16); color: #9aa6ff; }
.cls-chip.unauth     { background: rgba(245,197,66,.16); color: var(--amber); }
.cls-chip.spoof, .cls-chip.unknown { background: rgba(255,77,109,.16); color: var(--bad); }
.chev { color: var(--faint); transition: .2s; width: 16px; height: 16px; }
.exp.open > .exp-head .chev { transform: rotate(90deg); color: var(--teal); }
.exp-body { display: none; }
.exp.open > .exp-body { display: block; }

/* IP level */
.ipwrap { padding: 4px 6px 14px 50px; }
.iphead {
  display: grid;
  grid-template-columns: 1.1fr 1.4fr .6fr .5fr .5fr .5fr 1fr 18px;
  gap: 9px; font-family: var(--mono); font-size: 8.5px; letter-spacing: .5px;
  text-transform: uppercase; color: var(--faint);
  padding: 7px 0; border-bottom: 1px solid var(--line);
}
.iprow {
  display: grid;
  grid-template-columns: 1.1fr 1.4fr .6fr .5fr .5fr .5fr 1fr 18px;
  gap: 9px; align-items: center;
  font-family: var(--mono); font-size: 11px;
  padding: 9px 0; border-bottom: 1px solid rgba(255,255,255,.04);
  cursor: pointer; color: var(--muted); transition: .15s;
  border-radius: 6px;
}
.iprow:hover { background: rgba(255,255,255,.03); color: var(--txt); }
.ipa { color: var(--txt); font-weight: 600; }
.mono-sm { font-family: var(--mono); font-size: 10.5px; }

/* Envelope indicator */
.env-clean { color: var(--faint); font-size: 10px; }
.env-badge { display: inline-flex; align-items: center; gap: 5px; font-family: var(--mono); font-size: 9.5px; padding: 2px 8px; border-radius: 20px; font-weight: 600; }
.env-badge.esp      { background: rgba(245,197,66,.12); color: var(--amber); border: 1px solid rgba(245,197,66,.25); }
.env-badge.mismatch { background: rgba(255,80,80,.1); color: var(--bad); border: 1px solid rgba(255,80,80,.25); }
.env-dot { width: 6px; height: 6px; border-radius: 50%; flex: none; }
.env-dot.esp      { background: var(--amber); }
.env-dot.mismatch { background: var(--bad); }

.row-arrow { width: 14px; height: 14px; color: var(--faint); }
.iprow:hover .row-arrow { color: var(--teal); }
</style>
