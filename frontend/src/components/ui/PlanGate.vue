<script setup lang="ts">
import { useRouter } from 'vue-router'

const props = defineProps<{
  feature: string        // human-readable name e.g. "PDF reports"
  requiredPlan?: string  // e.g. "Starter"
  compact?: boolean      // inline chip vs full banner
}>()

const router = useRouter()
</script>

<template>
  <div v-if="compact" class="pg-chip">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
      <rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/>
    </svg>
    {{ feature }} — <span class="pg-link" @click="router.push('/billing')" tabindex="0" role="link" @keydown.enter.prevent="router.push('/billing')" @keydown.space.prevent="router.push('/billing')">upgrade to {{ requiredPlan ?? 'a paid plan' }}</span>
  </div>

  <div v-else class="pg-banner">
    <div class="pg-icon">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" width="28" height="28">
        <rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/>
      </svg>
    </div>
    <div class="pg-body">
      <div class="pg-title">{{ feature }} requires {{ requiredPlan ?? 'a paid plan' }}</div>
      <div class="pg-sub">Upgrade your plan to unlock this feature.</div>
    </div>
    <button class="pg-btn" @click="router.push('/billing')">View plans</button>
  </div>
</template>

<style scoped>
.pg-chip {
  display: inline-flex; align-items: center; gap: 6px;
  font-family: var(--mono); font-size: 10px; color: var(--faint);
  background: rgba(91,92,240,.08); border: 1px solid rgba(91,92,240,.2);
  border-radius: 8px; padding: 4px 10px;
}
.pg-chip svg { width: 11px; height: 11px; flex: none; }
.pg-link { color: var(--indigo); cursor: pointer; text-decoration: underline; }

.pg-banner {
  display: flex; align-items: center; gap: 16px;
  background: rgba(91,92,240,.07); border: 1px solid rgba(91,92,240,.2);
  border-radius: 14px; padding: 18px 20px;
}
.pg-icon { color: var(--indigo); flex: none; }
.pg-body { flex: 1; }
.pg-title { font-family: var(--disp); font-weight: 700; font-size: 14px; color: var(--txt); }
.pg-sub   { font-family: var(--mono); font-size: 10px; color: var(--faint); margin-top: 3px; }
.pg-btn {
  flex: none; background: linear-gradient(90deg,#5b5cf0,#4b4ce0);
  color: #fff; border: none; border-radius: 10px;
  padding: 8px 18px; font-family: var(--disp); font-weight: 700;
  font-size: 12px; cursor: pointer; white-space: nowrap;
  transition: opacity .15s;
}
.pg-btn:hover { opacity: .88; }
</style>
