<script setup lang="ts">
defineProps<{
  role: 'user' | 'assistant'
  content: string
  loading?: boolean
}>()
</script>

<template>
  <div class="bubble-row" :class="role">
    <div v-if="role === 'assistant'" class="orb">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:12px"><path d="M22 6l-10 7L2 6"/><rect x="2" y="4" width="20" height="16" rx="2"/></svg>
    </div>
    <div class="bubble" :class="role">
      <span v-if="loading" class="cursor">▍</span>
      <span v-else>{{ content }}</span>
    </div>
  </div>
</template>

<style scoped>
.bubble-row { display: flex; align-items: flex-end; gap: 8px; margin-bottom: 12px; }
.bubble-row.user { flex-direction: row-reverse; }
.orb { width: 28px; height: 28px; border-radius: 50%; background: radial-gradient(circle at 30% 30%, #2ef5d4, #5b5cf0); display: grid; place-items: center; flex: none; color: var(--ink); }
.bubble { max-width: 80%; padding: 10px 14px; border-radius: 16px; font-size: 13px; line-height: 1.6; }
.bubble.assistant { background: rgba(255,255,255,.06); border: 1px solid var(--line); border-bottom-left-radius: 4px; }
.bubble.user { background: linear-gradient(135deg,#5b5cf0,#4b4ce0); color:#fff; border-bottom-right-radius: 4px; }
.cursor { animation: blink .8s step-end infinite; }
@keyframes blink { 0%,100%{opacity:1} 50%{opacity:0} }
</style>
