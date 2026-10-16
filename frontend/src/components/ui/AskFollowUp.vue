<script setup lang="ts">
import { ref } from 'vue'
import { api } from '@/api/client'

// GUIDED_ONBOARDING_PLAN.md Part 2, item 2: "Ask a follow-up" beneath the
// instant deterministic explanation — opens the AI advisor pre-seeded with
// this row's exact data as context, so the AI elaborates on a specific
// situation instead of being asked to decide anything from scratch. The
// deterministic explanation (shown by the caller, above this component)
// is always the first response; this is only for genuine follow-up.
const props = defineProps<{
  screen: string
  domainId?: string
  seedContext: string   // plain-language description of the row, sent as the first message
}>()

interface Msg { role: 'user' | 'assistant'; content: string; citations?: string[] }

const open = ref(false)
const messages = ref<Msg[]>([])
const loading = ref(false)
const draft = ref('')

async function start() {
  open.value = true
  if (messages.value.length) return
  await send(`Can you explain why this happened and what I should do? Context: ${props.seedContext}`, true)
}

async function send(text: string, isSeed = false) {
  if (!text.trim()) return
  messages.value.push({ role: 'user', content: isSeed ? 'Explain this and what I should do' : text })
  loading.value = true
  draft.value = ''
  try {
    const result = await api.advisorChat(text, messages.value.slice(0, -1), props.screen, props.domainId)
    messages.value.push({ role: 'assistant', content: result.reply, citations: result.citations })
  } catch {
    messages.value.push({ role: 'assistant', content: "Sorry, I couldn't reach the advisor right now — try again in a moment." })
  } finally {
    loading.value = false
  }
}

function submitDraft() {
  if (!draft.value.trim() || loading.value) return
  send(draft.value)
}
</script>

<template>
  <div class="ask-follow-up">
    <button v-if="!open" class="ask-btn" @click="start">Ask a follow-up →</button>
    <div v-else class="thread">
      <div v-for="(m, i) in messages" :key="i" :class="['msg', m.role]">
        <span class="msg-who">{{ m.role === 'user' ? 'You' : 'Advisor' }}</span>
        <span class="msg-text">{{ m.content }}</span>
        <!-- Grounded knowledge actually used for this reply — the fact ids
             we injected into the prompt, not anything parsed back out of
             the model's text, so this is a real citation, not a guess. -->
        <span v-if="m.citations?.length" class="msg-cites">Grounded in: {{ m.citations.join(', ') }}</span>
      </div>
      <div v-if="loading" class="msg assistant"><span class="msg-who">Advisor</span><span class="msg-text typing">…</span></div>

      <div class="composer">
        <input
          v-model="draft" type="text" placeholder="Ask another question…"
          :disabled="loading" @keyup.enter="submitDraft"
        />
        <button :disabled="loading || !draft.trim()" @click="submitDraft">Send</button>
      </div>
    </div>
  </div>
</template>

<style scoped>
.ask-follow-up { margin-top: 8px; }
.ask-btn {
  background: none; border: none; color: #9aa6ff; font-size: 11.5px; font-weight: 600;
  cursor: pointer; padding: 0; font-family: var(--disp);
}
.ask-btn:hover { text-decoration: underline; }

.thread {
  display: flex; flex-direction: column; gap: 8px; margin-top: 8px;
  background: rgba(91,92,240,.05); border: 1px solid rgba(91,92,240,.18);
  border-radius: 12px; padding: 12px;
}
.msg { display: flex; flex-direction: column; gap: 2px; }
.msg-who { font-family: var(--mono); font-size: 8.5px; letter-spacing: .6px; text-transform: uppercase; color: var(--faint); }
.msg.user .msg-who { color: #9aa6ff; }
.msg-text { font-size: 12px; line-height: 1.55; color: var(--txt); }
.msg-text.typing { color: var(--faint); }
.msg-cites { font-family: var(--mono); font-size: 9px; color: var(--faint); margin-top: 2px; }

.composer { display: flex; gap: 6px; margin-top: 4px; }
.composer input {
  flex: 1; background: rgba(255,255,255,.04); border: 1px solid var(--line2);
  border-radius: 8px; padding: 6px 10px; font-size: 11.5px; color: var(--txt); outline: none;
}
.composer input:focus { border-color: var(--indigo); }
.composer button {
  background: rgba(91,92,240,.16); border: 1px solid rgba(91,92,240,.35); color: #9aa6ff;
  border-radius: 8px; padding: 6px 12px; font-size: 11px; font-weight: 700; cursor: pointer;
}
.composer button:disabled { opacity: .5; cursor: not-allowed; }
</style>
