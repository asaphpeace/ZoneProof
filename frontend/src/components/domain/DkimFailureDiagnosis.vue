<script setup lang="ts">
// PAIN_POINT_RESOLUTION_PLAN.md Pain 3 — renders the two ranked,
// evidence-based DKIM-failure hypotheses instead of one lumped sentence.
// Neither is presented as certain; each carries its own evidence and fix.
const props = defineProps<{
  hypotheses: {
    id: string
    label: string
    confidence: number
    evidence: string
    explanation: string
    fix: string
  }[]
  platformKey?: string | null  // recognized sending platform, if any — routes the key-mismatch fix
}>()
const emit = defineEmits<{ 'open-platform-setup': [key: string]; 'open-arc-info': [] }>()
</script>

<template>
  <div class="diag">
    <div class="diag-head">Two possible causes — ranked by the evidence available, neither certain</div>
    <div v-for="h in hypotheses" :key="h.id" class="hyp">
      <div class="hyp-top">
        <span class="hyp-label">{{ h.label }}</span>
        <span class="hyp-conf">{{ h.confidence }}% likely</span>
      </div>
      <p class="hyp-evidence">{{ h.evidence }}</p>
      <p class="hyp-explain">{{ h.explanation }}</p>
      <div class="hyp-foot">
        <span class="hyp-fix">{{ h.fix }}</span>
        <button
          v-if="h.id === 'key_mismatch' && platformKey"
          class="hyp-btn"
          @click="emit('open-platform-setup', platformKey)"
        >Fix this →</button>
        <button v-else-if="h.id === 'transit_modification'" class="hyp-btn ghost" @click="emit('open-arc-info')">
          Learn about ARC →
        </button>
      </div>
    </div>
  </div>
</template>

<style scoped>
.diag { display: flex; flex-direction: column; gap: 10px; margin-top: 10px; }
.diag-head { font-family: var(--mono); font-size: 9px; letter-spacing: .6px; text-transform: uppercase; color: var(--faint); }
.hyp { background: rgba(255,255,255,.03); border: 1px solid var(--line); border-radius: 11px; padding: 11px 13px; }
.hyp-top { display: flex; align-items: center; justify-content: space-between; margin-bottom: 6px; }
.hyp-label { font-size: 12.5px; font-weight: 600; color: var(--txt); }
.hyp-conf { font-family: var(--mono); font-size: 10px; color: #9aa6ff; background: rgba(91,92,240,.12); padding: 2px 8px; border-radius: 6px; }
.hyp-evidence { font-size: 11.5px; color: var(--muted); line-height: 1.5; margin: 0 0 4px; }
.hyp-explain { font-size: 11.5px; color: var(--faint); line-height: 1.5; margin: 0 0 8px; }
.hyp-foot { display: flex; align-items: flex-end; justify-content: space-between; gap: 10px; }
.hyp-fix { font-size: 11px; color: var(--amber); line-height: 1.5; flex: 1; }
.hyp-btn {
  flex: none; background: rgba(91,92,240,.16); border: 1px solid rgba(91,92,240,.35); color: #9aa6ff;
  border-radius: 8px; padding: 5px 11px; font-size: 11px; font-weight: 700; cursor: pointer;
}
.hyp-btn.ghost { background: none; border-color: var(--line2); color: var(--muted); }
</style>
