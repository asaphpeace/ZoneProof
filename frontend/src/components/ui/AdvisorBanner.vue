<script setup lang="ts">
import AiBadge from './AiBadge.vue'
defineProps<{
  message: string
  commend?: boolean
  citations?: string[]
  loading?: boolean      // true = no content yet, show skeleton
  refreshing?: boolean   // true = content exists but is being refreshed, show subtle spinner
  isAi?: boolean
  model?: string
}>()
const emit = defineEmits<{ regenerate: [] }>()
</script>

<template>
  <div :class="['advisor', commend ? 'commend' : '', refreshing ? 'refreshing' : '']">
    <div class="orb" :class="{ spinning: refreshing }" />
    <div style="flex:1">
      <div class="who-row">
        <span class="who">ZoneProof Advisor</span>
        <span v-if="refreshing" class="refresh-label">Updating…</span>
      </div>

      <!-- Skeleton: first load only -->
      <div v-if="loading" class="skel-block">
        <div class="skel" style="width:88%;height:13px" />
        <div class="skel" style="width:70%;height:13px;margin-top:7px" />
      </div>

      <!-- Content: cached while refreshing -->
      <div v-else class="msg" v-html="message" />

      <div v-if="citations?.length" class="advfoot">
        <span v-for="c in citations" :key="c" style="color:var(--teal)">↗ {{ c }}</span>
      </div>
      <div class="advfoot">
        <AiBadge v-if="isAi !== false" :loading="loading" />
        <span v-else class="rule-label">Analysis</span>
        <span v-if="model && !loading" class="model-label">{{ model }}</span>
        <button class="re" :disabled="refreshing" @click="emit('regenerate')">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"
            :class="{ spin: refreshing }">
            <path d="M23 4v6h-6"/><path d="M1 20v-6h6"/>
            <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>
          </svg>
          Regenerate
        </button>
      </div>
    </div>
  </div>
</template>

<style scoped>
.advisor {
  background: linear-gradient(160deg, rgba(91,92,240,.1), rgba(255,255,255,.012));
  border: 1px solid var(--line2); border-radius: 16px; padding: 16px 18px;
  margin-bottom: 16px; display: flex; gap: 14px; align-items: flex-start;
  backdrop-filter: blur(12px); transition: border-color .3s;
}
.advisor.commend {
  background: linear-gradient(160deg, rgba(52,224,161,.1), rgba(255,255,255,.012));
  border-color: rgba(52,224,161,.3);
}
.advisor.refreshing { border-color: rgba(91,92,240,.35); }

.orb {
  width: 30px; height: 30px; border-radius: 50%; flex: none; margin-top: 1px;
  background: radial-gradient(circle at 30% 30%, #6ff7e0, #5b5cf0);
  box-shadow: 0 0 18px rgba(46,230,197,.5);
  animation: pulse-orb 2.6s ease-in-out infinite;
  transition: opacity .2s;
}
.orb.spinning { animation: pulse-orb 2.6s ease-in-out infinite, spin-orb 1.4s linear infinite; }
.advisor.commend .orb { background: radial-gradient(circle at 30% 30%, #9ff5cf, #34e0a1); }

.who-row { display: flex; align-items: center; gap: 10px; margin-bottom: 5px; }
.who { font-family: var(--mono); font-size: 9px; letter-spacing: 1px; text-transform: uppercase; color: var(--teal); }
.refresh-label { font-family: var(--mono); font-size: 9px; color: var(--faint); letter-spacing: .3px; }

.msg { font-size: 13px; line-height: 1.65; color: #dbe0f2; }
.msg :deep(b) { color: var(--teal); }
.advisor.commend .msg :deep(b) { color: var(--good); }
.advisor.refreshing .msg { opacity: .6; transition: opacity .25s; }

.skel-block { padding: 2px 0 4px; }
.skel {
  background: rgba(255,255,255,.06); border-radius: 6px;
  animation: skel-pulse 1.4s ease-in-out infinite;
}
@keyframes skel-pulse { 0%,100%{opacity:.5} 50%{opacity:.9} }

.advfoot {
  font-family: var(--mono); font-size: 9.5px; color: var(--faint);
  margin-top: 11px; display: flex; gap: 10px; align-items: center; flex-wrap: wrap;
}
.rule-label { border: 1px solid var(--line); border-radius: 20px; padding: 3px 10px; font-size: 9px; }
.model-label { color: var(--faint); font-size: 9px; opacity: .6; }

.re {
  display: flex; align-items: center; gap: 5px;
  background: none; border: none; padding: 0;
  color: var(--teal); font-family: var(--mono); font-size: 9.5px;
  cursor: pointer; transition: opacity .15s;
}
.re:hover:not(:disabled) { text-decoration: underline; }
.re:disabled { opacity: .45; cursor: not-allowed; }
.re svg { width: 11px; height: 11px; }
.re svg.spin { animation: spin-orb .9s linear infinite; }

@keyframes pulse-orb { 50% { box-shadow: 0 0 28px rgba(91,92,240,.8); } }
@keyframes spin-orb  { to { transform: rotate(360deg); } }
</style>
