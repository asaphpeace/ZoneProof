<script setup lang="ts">
import { ref } from 'vue'
import { api } from '@/api/client'
import AskFollowUp from './AskFollowUp.vue'

// PAIN_POINT_RESOLUTION_PLAN.md Pain 2 — a small "?" attached to the exact
// term that caused real confusion in the original training calls, rendered
// with the user's own live values, not a generic glossary entry. Fades to
// a quieter state once dismissed, but never disappears — always reachable.
const props = defineProps<{
  conceptId: string
  context?: Record<string, any>
  screen?: string
  domainId?: string
}>()

const open = ref(false)
const rendered = ref<any>(null)
const loading = ref(false)
const seen = ref(false)

async function toggle() {
  open.value = !open.value
  if (open.value && !rendered.value) {
    loading.value = true
    try {
      rendered.value = await api.conceptRender(props.conceptId, props.context || {})
      seen.value = rendered.value.seen
    } finally {
      loading.value = false
    }
  }
}

async function gotIt() {
  await api.conceptMarkSeen(props.conceptId)
  seen.value = true
  open.value = false
}
</script>

<template>
  <span class="concept-wrap">
    <button class="concept-btn" :class="{ seen }" @click.stop="toggle" title="What does this mean?">?</button>
    <div v-if="open" class="concept-popover" @click.stop>
      <div v-if="loading" class="concept-loading">Loading…</div>
      <template v-else-if="rendered">
        <div class="concept-term">{{ rendered.term }}</div>
        <p class="concept-text">{{ rendered.text }}</p>
        <AskFollowUp
          v-if="screen"
          :screen="screen"
          :domain-id="domainId"
          :seed-context="`Concept: ${rendered.term}. ${rendered.text}`"
        />
        <button class="concept-gotit" @click="gotIt">Got it</button>
      </template>
    </div>
  </span>
</template>

<style scoped>
.concept-wrap { position: relative; display: inline-block; }
.concept-btn {
  width: 16px; height: 16px; border-radius: 50%; border: 1px solid var(--line2);
  background: rgba(255,255,255,.04); color: var(--faint); font-size: 9px; font-weight: 700;
  cursor: pointer; line-height: 1; padding: 0; display: inline-grid; place-items: center;
}
.concept-btn:hover { border-color: #9aa6ff; color: #9aa6ff; }
.concept-btn.seen { opacity: .45; }

.concept-popover {
  position: absolute; top: calc(100% + 6px); left: 0; z-index: 250; width: 280px;
  background: var(--surface-raised); border: 1px solid var(--line2); border-radius: 13px;
  padding: 14px 16px; box-shadow: 0 20px 50px rgba(0,0,0,.6);
}
.concept-loading { font-family: var(--mono); font-size: 11px; color: var(--faint); }
.concept-term { font-family: var(--disp); font-weight: 700; font-size: 12.5px; color: #9aa6ff; margin-bottom: 6px; }
.concept-text { font-size: 12px; color: var(--muted); line-height: 1.55; margin: 0 0 10px; }
.concept-gotit {
  background: rgba(255,255,255,.04); border: 1px solid var(--line2); color: var(--muted);
  border-radius: 8px; padding: 5px 12px; font-size: 11px; cursor: pointer;
}
.concept-gotit:hover { border-color: var(--indigo); color: var(--txt); }
</style>
