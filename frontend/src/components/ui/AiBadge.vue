<script setup lang="ts">
defineProps<{
  timestamp?: string | null
  loading?: boolean
}>()

function fmtTs(iso: string) {
  const d = new Date(iso)
  return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) +
    ' · ' + d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })
}
</script>

<template>
  <span class="ai-badge" :class="{ loading }">
    <span class="ai-star">✦</span>
    <span class="ai-label">ZoneProof AI</span>
    <span v-if="loading" class="ai-pulse" />
    <span v-else-if="timestamp" class="ai-ts">{{ fmtTs(timestamp) }}</span>
  </span>
</template>

<style scoped>
.ai-badge {
  display: inline-flex; align-items: center; gap: 5px;
  background: rgba(46,230,197,.08); border: 1px solid rgba(46,230,197,.22);
  border-radius: 20px; padding: 3px 10px 3px 8px;
  font-family: var(--mono); font-size: 9.5px; letter-spacing: .4px;
  color: var(--teal); white-space: nowrap; flex: none;
}
.ai-star { font-size: 10px; }
.ai-label { text-transform: uppercase; letter-spacing: .8px; font-weight: 600; }
.ai-ts { color: rgba(46,230,197,.55); font-size: 9px; }
.ai-pulse {
  width: 6px; height: 6px; border-radius: 50%; background: var(--teal);
  animation: blink 1.2s ease-in-out infinite;
}
@keyframes blink { 0%,100% { opacity:.3 } 50% { opacity:1 } }
</style>
