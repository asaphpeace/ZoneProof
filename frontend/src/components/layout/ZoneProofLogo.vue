<script setup lang="ts">
// The ZoneProof mark and wordmark, in one place so every screen agrees.
withDefaults(defineProps<{ size?: number; subtitle?: string; wordmark?: boolean }>(), { size: 38, wordmark: true })
</script>

<template>
  <div class="zp">
    <div class="mark" :style="{ width: size + 'px', height: size + 'px', borderRadius: Math.round(size * 0.29) + 'px' }">
      <svg :width="Math.round(size * 0.63)" :height="Math.round(size * 0.63)" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
        <path d="M3 8V5a2 2 0 0 1 2-2h3M16 3h3a2 2 0 0 1 2 2v3M21 16v3a2 2 0 0 1-2 2h-3M8 21H5a2 2 0 0 1-2-2v-3" />
        <path d="M8 12.5l2.8 2.8L16.5 9" />
      </svg>
    </div>
    <div v-if="wordmark" class="words">
      <div class="name">Zone<b>Proof</b></div>
      <div v-if="subtitle" class="sub">{{ subtitle }}</div>
    </div>
  </div>
</template>

<style scoped>
.zp { display: flex; align-items: center; gap: 12px; }
.mark { background: var(--accent); display: grid; place-items: center; flex: none; }
.name { font-family: var(--disp); font-weight: 800; font-size: 17px; letter-spacing: -.3px; line-height: 1.1; }
.name b { color: var(--accent-soft); font-weight: 800; }
.sub { font-family: var(--body); font-size: 10.5px; color: var(--faint); margin-top: 2px; white-space: nowrap; }
</style>
