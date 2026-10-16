<script setup lang="ts">
// The single shared display for "what should my SPF record say" — never
// rendered as a one-platform-in-isolation instruction. PlatformSetupModal
// embeds this; whatever record it shows already accounts for every
// declared + detected platform on the domain, not just the one currently
// being set up. See PAIN_POINT_RESOLUTION_PLAN.md Pain 1's critical fix.
const props = defineProps<{
  record: string
  recordHost?: string
  mechanisms: string[]
  totalLookups: number
  lookupLimit: number
  overLimit: boolean
  nearLimit: boolean
  warnings: string[]
  existingRecordFound?: boolean
  realLookupCount?: boolean
}>()

function copyRecord() {
  navigator.clipboard.writeText(props.record)
}

const gaugePct = () => Math.min(100, Math.round((props.totalLookups / props.lookupLimit) * 100))
</script>

<template>
  <div class="spf-builder">
    <div class="spf-head">
      <span class="spf-title">Your combined SPF record</span>
      <span class="spf-sub">Covers every sending platform on this domain — one record, not one per platform</span>
    </div>

    <div class="spf-fetch-status">
      <span v-if="existingRecordFound" class="spf-fetch-tag found">
        ✓ Fetched your live record and merged into it
      </span>
      <span v-else class="spf-fetch-tag none">
        No existing SPF record found — this would be a new one
      </span>
      <span v-if="realLookupCount" class="spf-fetch-tag real">
        Lookup count recursively verified against live DNS, not estimated
      </span>
    </div>

    <div class="spf-record-row">
      <code class="spf-record">{{ record }}</code>
      <button class="spf-copy" @click="copyRecord">Copy</button>
    </div>

    <!-- Where this gets published — previously the record was shown with
         nothing telling the user where to put it once copied. -->
    <div v-if="recordHost" class="spf-publish-row">
      <span class="spf-publish-item"><span class="spf-publish-label">Type</span><code>TXT</code></span>
      <span class="spf-publish-item"><span class="spf-publish-label">Host / Name</span><code>{{ recordHost }}</code></span>
    </div>

    <div class="spf-gauge-wrap">
      <div class="spf-gauge-track">
        <div
          class="spf-gauge-fill"
          :class="overLimit ? 'over' : nearLimit ? 'near' : 'ok'"
          :style="{ width: gaugePct() + '%' }"
        />
      </div>
      <span class="spf-gauge-label" :class="overLimit ? 'over' : nearLimit ? 'near' : 'ok'">
        {{ totalLookups }} / {{ lookupLimit }} DNS lookups
      </span>
    </div>

    <div v-if="warnings.length" class="spf-warnings">
      <div v-for="(w, i) in warnings" :key="i" class="spf-warning" :class="overLimit ? 'bad' : 'amber'">
        {{ w }}
      </div>
    </div>

    <div v-if="mechanisms.length" class="spf-mech-list">
      <span class="spf-mech-label">Included from:</span>
      <span v-for="m in mechanisms" :key="m" class="spf-mech-chip">{{ m }}</span>
    </div>
  </div>
</template>

<style scoped>
.spf-builder {
  background: rgba(91,92,240,.05); border: 1px solid rgba(91,92,240,.18);
  border-radius: 14px; padding: 16px;
}
.spf-head { margin-bottom: 12px; }
.spf-title { display: block; font-family: var(--disp); font-weight: 700; font-size: 13px; color: var(--txt); }
.spf-sub { display: block; font-size: 11px; color: var(--faint); margin-top: 2px; }

.spf-fetch-status { display: flex; gap: 6px; flex-wrap: wrap; margin: 8px 0 12px; }
.spf-fetch-tag { font-family: var(--mono); font-size: 9.5px; padding: 3px 9px; border-radius: 7px; }
.spf-fetch-tag.found { background: rgba(52,224,161,.12); color: var(--good); }
.spf-fetch-tag.none  { background: rgba(245,197,66,.12); color: var(--amber); }
.spf-fetch-tag.real  { background: rgba(91,92,240,.12); color: #9aa6ff; }

.spf-record-row { display: flex; gap: 8px; align-items: flex-start; margin-bottom: 12px; }
.spf-record {
  flex: 1; font-family: var(--mono); font-size: 12px; color: var(--txt);
  background: rgba(0,0,0,.25); border: 1px solid var(--line); border-radius: 9px;
  padding: 10px 12px; word-break: break-all; line-height: 1.5;
}
.spf-copy {
  flex: none; background: rgba(91,92,240,.16); border: 1px solid rgba(91,92,240,.35); color: #9aa6ff;
  border-radius: 9px; padding: 9px 14px; font-size: 11.5px; font-weight: 700; cursor: pointer;
}

.spf-publish-row { display: flex; gap: 16px; margin-bottom: 12px; flex-wrap: wrap; }
.spf-publish-item { display: flex; align-items: center; gap: 6px; font-size: 11.5px; }
.spf-publish-item code { font-family: var(--mono); color: var(--txt); background: rgba(255,255,255,.06); padding: 2px 8px; border-radius: 6px; }
.spf-publish-label { font-family: var(--mono); font-size: 9px; letter-spacing: .5px; text-transform: uppercase; color: var(--faint); }

.spf-gauge-wrap { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }
.spf-gauge-track { flex: 1; height: 6px; background: rgba(255,255,255,.08); border-radius: 4px; overflow: hidden; }
.spf-gauge-fill { height: 100%; border-radius: 4px; transition: width .3s ease; }
.spf-gauge-fill.ok   { background: var(--good); }
.spf-gauge-fill.near { background: var(--amber); }
.spf-gauge-fill.over { background: var(--bad); }
.spf-gauge-label { font-family: var(--mono); font-size: 10.5px; flex: none; }
.spf-gauge-label.ok   { color: var(--good); }
.spf-gauge-label.near { color: var(--amber); }
.spf-gauge-label.over { color: var(--bad); }

.spf-warnings { display: flex; flex-direction: column; gap: 6px; margin-bottom: 10px; }
.spf-warning { font-size: 11.5px; line-height: 1.5; padding: 8px 10px; border-radius: 9px; }
.spf-warning.amber { background: rgba(245,197,66,.1); color: var(--amber); border: 1px solid rgba(245,197,66,.25); }
.spf-warning.bad   { background: rgba(255,77,109,.1); color: var(--bad); border: 1px solid rgba(255,77,109,.25); }

.spf-mech-list { display: flex; gap: 6px; flex-wrap: wrap; align-items: center; }
.spf-mech-label { font-family: var(--mono); font-size: 9px; letter-spacing: .5px; text-transform: uppercase; color: var(--faint); margin-right: 4px; }
.spf-mech-chip { font-family: var(--mono); font-size: 10px; background: rgba(255,255,255,.06); color: var(--muted); padding: 2px 8px; border-radius: 6px; }
</style>
