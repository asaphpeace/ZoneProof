<script setup lang="ts">
defineProps<{ grade: string; color: string }>()
</script>

<template>
  <span class="score">
    <span class="shield" :style="`background:${color}`">{{ grade }}</span>
  </span>
</template>

<style scoped>
.score { display: inline-flex; align-items: center; }
.shield {
  width: 34px; height: 38px; display: grid; place-items: center;
  font-family: var(--disp); font-weight: 800; font-size: 13px; color: var(--ink);
  clip-path: polygon(50% 0, 100% 16%, 100% 60%, 50% 100%, 0 60%, 0 16%);
}
</style>
