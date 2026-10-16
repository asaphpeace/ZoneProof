<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{
  data: {
    period_days: number
    total_attempts: number
    blocked: number
    blocked_pct: number
    exposed: number
    unique_ips: number
    unique_orgs: number
    top_targeted: Array<{
      domain: string
      attempts: number
      blocked: number
      blocked_pct: number
      exposed: number
      dmarc_stage: string
    }>
    top_sources: Array<{
      source_org: string
      source_ip: string
      attempts: number
      rdns: string | null
      asn: string | null
    }>
    has_data: boolean
  }
}>()

const exposedPct = computed(() =>
  props.data.total_attempts
    ? Math.round(props.data.exposed / props.data.total_attempts * 100)
    : 0
)

const headline = computed(() => {
  const n = props.data.total_attempts
  if (!n) return 'No impersonation attempts detected in this period.'
  return `${n.toLocaleString()} impersonation attempt${n === 1 ? '' : 's'} detected in the last ${props.data.period_days} days`
})

const stageColor = (stage: string) =>
  stage === 'reject' ? 'var(--good)'
  : stage === 'quarantine' ? '#5b5cf0'
  : 'var(--bad)'

const stageLabel = (stage: string) =>
  stage === 'reject' ? 'REJECT'
  : stage === 'quarantine' ? 'QUAR'
  : 'NONE'
</script>

<template>
  <div class="ts-wrap">

    <!-- Header row -->
    <div class="ts-header">
      <div class="ts-eyebrow">
        <span class="ts-tag">THREAT SURFACE</span>
        <span class="ts-period">Last {{ data.period_days }} days</span>
      </div>
      <div v-if="data.has_data" class="ts-meta">
        <span class="meta-chip">{{ data.unique_ips }} attacker IP{{ data.unique_ips !== 1 ? 's' : '' }}</span>
        <span class="meta-chip">{{ data.unique_orgs }} org{{ data.unique_orgs !== 1 ? 's' : '' }}</span>
      </div>
    </div>

    <!-- No data state -->
    <div v-if="!data.has_data" class="ts-empty">
      <div class="ts-empty-icon">✓</div>
      <div class="ts-empty-title">No suspicious senders detected</div>
      <div class="ts-empty-sub">No DMARC-failing messages from unrecognised sources in the last {{ data.period_days }} days. This may mean no data has been ingested yet.</div>
    </div>

    <template v-else>
      <!-- Headline number -->
      <div class="ts-headline">{{ headline }}</div>

      <!-- Blocked vs exposed split -->
      <div class="ts-split">
        <div class="ts-split-bar">
          <div
            class="ts-bar-seg blocked"
            :style="`flex:${data.blocked_pct}`"
            :title="`Blocked: ${data.blocked.toLocaleString()}`"
          />
          <div
            class="ts-bar-seg exposed"
            :style="`flex:${exposedPct}`"
            :title="`Reached inboxes: ${data.exposed.toLocaleString()}`"
            v-if="data.exposed > 0"
          />
        </div>
        <div class="ts-split-legend">
          <span class="leg blocked">
            <span class="leg-dot blocked" />
            {{ data.blocked.toLocaleString() }} blocked
            <b>{{ data.blocked_pct }}%</b>
          </span>
          <span class="leg exposed" v-if="data.exposed > 0">
            <span class="leg-dot exposed" />
            {{ data.exposed.toLocaleString() }} reached inboxes
          </span>
          <span class="leg ok" v-else>
            <span class="leg-dot ok" />
            None reached inboxes
          </span>
        </div>
      </div>

      <!-- Exposure warning -->
      <div v-if="data.exposed > 0" class="ts-warning">
        <span class="warn-icon">⚠</span>
        <span>
          <b>{{ data.exposed.toLocaleString() }}</b> messages bypassed filtering —
          {{ data.top_targeted.filter(t => t.exposed > 0).map(t => t.domain).join(', ') }}
          {{ data.top_targeted.filter(t => t.exposed > 0).length === 1 ? 'has' : 'have' }} no DMARC enforcement yet.
          Publishing a quarantine or reject policy will block these.
        </span>
      </div>

      <!-- Two-col detail tables -->
      <div class="ts-tables">

        <!-- Top targeted domains -->
        <div class="ts-table-block">
          <div class="ts-table-title">Most targeted domains</div>
          <div class="ts-table">
            <div class="ts-thead">
              <span>Domain</span>
              <span>Attempts</span>
              <span>Blocked</span>
            </div>
            <div v-for="t in data.top_targeted" :key="t.domain" class="ts-trow">
              <div class="ts-domain-cell">
                <span class="ts-domain-name">{{ t.domain }}</span>
                <span class="stage-badge" :style="`color:${stageColor(t.dmarc_stage)}`">{{ stageLabel(t.dmarc_stage) }}</span>
              </div>
              <div class="ts-num">{{ t.attempts.toLocaleString() }}</div>
              <div class="ts-blocked-cell">
                <div class="mini-bar-track">
                  <div class="mini-bar-fill" :style="`width:${t.blocked_pct}%;background:${t.blocked_pct >= 90 ? 'var(--good)' : t.blocked_pct >= 50 ? 'var(--amber)' : 'var(--bad)'}`" />
                </div>
                <span class="mini-pct" :style="`color:${t.blocked_pct >= 90 ? 'var(--good)' : t.blocked_pct >= 50 ? 'var(--amber)' : 'var(--bad)'}`">{{ t.blocked_pct }}%</span>
              </div>
            </div>
          </div>
        </div>

        <!-- Top attacker sources -->
        <div class="ts-table-block">
          <div class="ts-table-title">Top attacker sources</div>
          <div class="ts-table">
            <div class="ts-thead">
              <span>Source</span>
              <span>IP</span>
              <span>Msgs</span>
            </div>
            <div v-for="s in data.top_sources" :key="s.source_ip" class="ts-trow">
              <div class="ts-source-cell">
                <span class="ts-source-org">{{ s.source_org || 'Unknown' }}</span>
                <span v-if="s.asn" class="ts-source-asn">{{ s.asn }}</span>
              </div>
              <div class="ts-ip">
                <span class="ts-ip-addr">{{ s.source_ip }}</span>
                <span v-if="s.rdns" class="ts-rdns">{{ s.rdns }}</span>
              </div>
              <div class="ts-num">{{ s.attempts.toLocaleString() }}</div>
            </div>
          </div>
        </div>

      </div>
    </template>

  </div>
</template>

<style scoped>
.ts-wrap {
  padding: 2px 0;
}

/* ── Header ─────────────────────────────────────────────────── */
.ts-header {
  display: flex; align-items: center; justify-content: space-between;
  margin-bottom: 14px; flex-wrap: wrap; gap: 8px;
}
.ts-eyebrow { display: flex; align-items: center; gap: 10px; }
.ts-tag {
  font-family: var(--mono); font-size: 9px; letter-spacing: 1.4px; text-transform: uppercase;
  color: var(--faint); border: 1px solid var(--line2); border-radius: 6px; padding: 3px 8px;
}
.ts-period { font-family: var(--mono); font-size: 10.5px; color: var(--faint); }
.ts-meta { display: flex; gap: 6px; }
.meta-chip {
  font-family: var(--mono); font-size: 9.5px; padding: 3px 9px; border-radius: 8px;
  background: rgba(255,80,80,.1); color: var(--bad); border: 1px solid rgba(255,80,80,.2);
}

/* ── Headline ────────────────────────────────────────────────── */
.ts-headline {
  font-family: var(--disp); font-weight: 800; font-size: 18px;
  letter-spacing: -.4px; line-height: 1.3; margin-bottom: 16px;
  color: var(--txt);
}

/* ── Split bar ───────────────────────────────────────────────── */
.ts-split { margin-bottom: 12px; }
.ts-split-bar {
  display: flex; height: 10px; border-radius: 6px; overflow: hidden; gap: 2px;
  margin-bottom: 8px;
}
.ts-bar-seg { min-width: 3px; border-radius: 3px; transition: flex .6s ease; }
.ts-bar-seg.blocked { background: var(--good); }
.ts-bar-seg.exposed { background: var(--bad); }

.ts-split-legend { display: flex; gap: 18px; flex-wrap: wrap; }
.leg { font-family: var(--mono); font-size: 11px; display: flex; align-items: center; gap: 6px; }
.leg b { font-size: 12px; }
.leg.blocked { color: var(--good); }
.leg.exposed { color: var(--bad); }
.leg.ok      { color: var(--good); }
.leg-dot { width: 7px; height: 7px; border-radius: 50%; flex: none; }
.leg-dot.blocked { background: var(--good); }
.leg-dot.exposed { background: var(--bad); }
.leg-dot.ok      { background: var(--good); }

/* ── Warning ─────────────────────────────────────────────────── */
.ts-warning {
  display: flex; gap: 10px; align-items: flex-start;
  background: rgba(255,140,66,.08); border: 1px solid rgba(255,140,66,.25);
  border-radius: 10px; padding: 10px 14px; margin-bottom: 16px;
  font-size: 12.5px; color: var(--muted); line-height: 1.5;
}
.warn-icon { color: var(--amber); font-size: 15px; flex: none; margin-top: 1px; }
.ts-warning b { color: var(--txt); }

/* ── Tables ──────────────────────────────────────────────────── */
.ts-tables {
  display: grid; grid-template-columns: 1fr 1fr; gap: 18px;
}
@media (max-width: 700px) { .ts-tables { grid-template-columns: 1fr; } }

.ts-table-block {}
.ts-table-title {
  font-family: var(--mono); font-size: 9px; letter-spacing: .8px; text-transform: uppercase;
  color: var(--faint); margin-bottom: 10px;
}
.ts-table {}
.ts-thead {
  display: grid; grid-template-columns: 1.5fr 1fr .8fr;
  gap: 8px; font-family: var(--mono); font-size: 8.5px; letter-spacing: .6px;
  text-transform: uppercase; color: var(--faint);
  padding: 0 6px 7px; border-bottom: 1px solid var(--line);
  margin-bottom: 2px;
}
.ts-trow {
  display: grid; grid-template-columns: 1.5fr 1fr .8fr;
  gap: 8px; align-items: center;
  padding: 7px 6px; border-radius: 8px;
  transition: .12s;
}
.ts-trow:hover { background: rgba(255,255,255,.03); }

.ts-domain-cell { display: flex; align-items: center; gap: 6px; min-width: 0; }
.ts-domain-name { font-family: var(--mono); font-size: 11.5px; font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.stage-badge { font-family: var(--mono); font-size: 8px; font-weight: 700; letter-spacing: .5px; flex: none; }

.ts-blocked-cell { display: flex; align-items: center; gap: 6px; }
.mini-bar-track { flex: 1; height: 4px; background: rgba(255,255,255,.07); border-radius: 3px; overflow: hidden; }
.mini-bar-fill  { height: 100%; border-radius: 3px; transition: width .5s ease; }
.mini-pct { font-family: var(--mono); font-size: 10px; font-weight: 700; white-space: nowrap; }

.ts-source-cell { min-width: 0; }
.ts-source-org { font-family: var(--mono); font-size: 11px; font-weight: 600; display: block; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.ts-source-asn { font-family: var(--mono); font-size: 9px; color: var(--faint); display: block; }

.ts-ip { min-width: 0; }
.ts-ip-addr { font-family: var(--mono); font-size: 10.5px; color: var(--muted); display: block; }
.ts-rdns { font-family: var(--mono); font-size: 8.5px; color: var(--faint); display: block; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

.ts-num { font-family: var(--disp); font-weight: 700; font-size: 13px; text-align: right; }

/* ── Empty state ─────────────────────────────────────────────── */
.ts-empty { display: flex; flex-direction: column; align-items: center; padding: 24px 16px; gap: 8px; }
.ts-empty-icon { font-size: 28px; color: var(--good); }
.ts-empty-title { font-family: var(--disp); font-weight: 700; font-size: 15px; color: var(--good); }
.ts-empty-sub { font-family: var(--mono); font-size: 11px; color: var(--faint); text-align: center; max-width: 380px; line-height: 1.6; }
</style>
