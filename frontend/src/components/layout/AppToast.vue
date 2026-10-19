<script setup lang="ts">
import { useUiStore } from '@/stores/ui'
const ui = useUiStore()
</script>

<template>
  <Teleport to="body">
    <div
      :class="['toast', ui.toastVisible ? 'show' : '', ui.toastType === 'error' ? 'error' : '']"
      role="status" aria-atomic="true" :aria-live="ui.toastType === 'error' ? 'assertive' : 'polite'"
    >{{ ui.toastVisible ? ui.toastMsg : '' }}</div>
  </Teleport>
</template>

<style scoped>
.toast {
  position: fixed; bottom: 92px; left: 50%;
  transform: translateX(-50%) translateY(20px);
  background: var(--surface-raised); border: 1px solid var(--line2); border-radius: 11px;
  padding: 12px 18px; font-size: 12.5px; z-index: 90;
  opacity: 0; pointer-events: none; transition: .25s;
  box-shadow: 0 12px 30px rgba(0,0,0,.5);
}
.toast.show { opacity: 1; transform: translateX(-50%) translateY(0); }
.toast.error { border-color: var(--bad); color: var(--bad); }
</style>
