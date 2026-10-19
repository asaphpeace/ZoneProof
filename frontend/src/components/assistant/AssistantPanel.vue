<script setup lang="ts">
import { ref, nextTick } from 'vue'
import { useRoute } from 'vue-router'
import { api } from '@/api/client'
import ChatBubble from './ChatBubble.vue'

const route = useRoute()
const open      = ref(false)
const input     = ref('')
const msgs      = ref<{ role: 'user' | 'assistant'; content: string }[]>([])
const thinking  = ref(false)
const scroll    = ref<HTMLElement>()
const lastModel = ref('')

const QUICK = [
  'What should I do next?',
  'Why is my compliance low?',
  'Explain DMARC quarantine',
  'What is MTA-STS?',
]

async function send(text?: string) {
  const msg = (text ?? input.value).trim()
  if (!msg || thinking.value) return
  input.value = ''
  msgs.value.push({ role: 'user', content: msg })
  thinking.value = true
  await nextTick()
  scroll.value?.scrollTo({ top: 99999, behavior: 'smooth' })

  // Pass history excluding the message we just appended (it's the current turn)
  const history = msgs.value.slice(0, -1)
  const screen = (route.name as string) ?? 'overview'

  try {
    const r = await api.advisorChat(msg, history, screen)
    msgs.value.push({ role: 'assistant', content: r.reply })
    if (r.model) lastModel.value = r.model
  } catch {
    msgs.value.push({ role: 'assistant', content: 'I couldn\'t reach the advisor right now. Try again in a moment.' })
  } finally {
    thinking.value = false
    await nextTick()
    scroll.value?.scrollTo({ top: 99999, behavior: 'smooth' })
  }
}

function toggle() {
  open.value = !open.value
  if (open.value && !msgs.value.length) {
    msgs.value.push({
      role: 'assistant',
      content: 'Hi — I\'m ZoneProof AI. I have access to your live security data and can answer questions about your DMARC posture, MTA-STS setup, certificates, and what to do next.',
    })
  }
}

function clear() {
  msgs.value = []
  msgs.value.push({
    role: 'assistant',
    content: 'Conversation cleared. What would you like to know?',
  })
}
</script>

<template>
  <!-- FAB -->
  <button class="fab" :class="{ active: open }" @click="toggle" title="ZoneProof AI">
    <svg v-if="!open" viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
      <circle cx="16" cy="16" r="16" fill="url(#fab-grad)"/>
      <path d="M10 16.5l3.5 3.5L22 11" style="stroke: var(--ink)" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
      <defs>
        <linearGradient id="fab-grad" x1="0" y1="0" x2="32" y2="32">
          <stop offset="0%" stop-color="#5b5cf0"/>
          <stop offset="100%" stop-color="#2ee6c5"/>
        </linearGradient>
      </defs>
    </svg>
    <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
      <path d="M18 6L6 18M6 6l12 12"/>
    </svg>
  </button>

  <!-- Panel -->
  <Teleport to="body">
    <Transition name="panel">
      <div v-if="open" class="panel">

        <!-- Header -->
        <div class="panel-header">
          <div class="orb">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:13px">
              <path d="M22 6l-10 7L2 6"/><rect x="2" y="4" width="20" height="16" rx="2"/>
            </svg>
          </div>
          <div class="header-text">
            <div class="panel-title">ZoneProof AI</div>
            <div class="panel-sub">Grounded on your reports</div>
          </div>
          <div class="header-actions">
            <button class="icon-btn" title="Clear conversation" @click="clear">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:14px">
                <polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6M14 11v6"/>
              </svg>
            </button>
            <button class="icon-btn" @click="open = false">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="width:14px">
                <path d="M18 6L6 18M6 6l12 12"/>
              </svg>
            </button>
          </div>
        </div>

        <!-- Context pill -->
        <div class="context-pill">
          <span class="ctx-dot" />
          Live data · {{ (route.name as string) ?? 'overview' }}
          <span v-if="lastModel" class="model-tag">{{ lastModel }}</span>
        </div>

        <!-- Messages -->
        <div class="msgs" ref="scroll">
          <ChatBubble v-for="(m, i) in msgs" :key="i" :role="m.role" :content="m.content" />
          <ChatBubble v-if="thinking" role="assistant" content="" :loading="true" />
        </div>

        <!-- Quick replies (show only when chat is fresh) -->
        <div v-if="msgs.length <= 1" class="quick">
          <button v-for="q in QUICK" :key="q" class="qchip" @click="send(q)">{{ q }}</button>
        </div>

        <!-- Input -->
        <div class="input-row">
          <input
            v-model="input"
            type="text"
            placeholder="Ask about your email security…"
            :disabled="thinking"
            @keydown.enter="send()"
          />
          <button class="send-btn" :disabled="!input.trim() || thinking" @click="send()">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="width:15px">
              <path d="M22 2L11 13M22 2l-7 20-4-9-9-4 20-7z"/>
            </svg>
          </button>
        </div>

      </div>
    </Transition>
  </Teleport>
</template>

<style scoped>
/* ── FAB ──────────────────────────────────────────────────────────────── */
.fab {
  position: fixed; bottom: 28px; right: 28px; z-index: 900;
  width: 52px; height: 52px; border-radius: 50%;
  background: var(--bg); border: 1px solid var(--line2);
  color: var(--txt); cursor: pointer;
  box-shadow: 0 8px 32px rgba(91,92,240,.35);
  display: grid; place-items: center; transition: .2s;
}
.fab svg { width: 52px; height: 52px; }
.fab:hover { transform: scale(1.07); box-shadow: 0 12px 40px rgba(91,92,240,.5); }
.fab.active { background: rgba(255,255,255,.08); box-shadow: none; }
.fab.active svg { width: 20px; height: 20px; }

/* ── Panel ────────────────────────────────────────────────────────────── */
.panel {
  position: fixed; bottom: 92px; right: 28px; z-index: 900;
  width: 370px; max-height: 540px;
  background: #0d0e1a;
  border: 1px solid rgba(91,92,240,.25);
  border-radius: 20px;
  box-shadow: 0 32px 80px rgba(0,0,0,.75), 0 0 0 1px rgba(46,230,197,.06);
  display: flex; flex-direction: column; overflow: hidden;
}

.panel-enter-active, .panel-leave-active { transition: opacity .18s, transform .18s; }
.panel-enter-from, .panel-leave-to { opacity: 0; transform: translateY(12px) scale(.97); }

/* ── Header ───────────────────────────────────────────────────────────── */
.panel-header {
  display: flex; align-items: center; gap: 10px;
  padding: 14px 14px 10px; border-bottom: 1px solid var(--line);
}
.orb {
  width: 34px; height: 34px; border-radius: 50%; flex: none;
  background: radial-gradient(circle at 30% 30%, #2ef5d4, #5b5cf0);
  display: grid; place-items: center; color: var(--ink);
}
.header-text { flex: 1; }
.panel-title { font-family: var(--disp); font-weight: 700; font-size: 13.5px; }
.panel-sub { font-family: var(--mono); font-size: 9px; color: var(--teal); text-transform: uppercase; letter-spacing: .8px; margin-top: 2px; }
.header-actions { display: flex; gap: 4px; }
.icon-btn {
  background: none; border: none; color: var(--faint); cursor: pointer;
  width: 28px; height: 28px; border-radius: 7px; display: grid; place-items: center;
  transition: .15s;
}
.icon-btn:hover { color: var(--txt); background: rgba(255,255,255,.06); }

/* ── Context pill ─────────────────────────────────────────────────────── */
.context-pill {
  display: flex; align-items: center; gap: 6px;
  font-family: var(--mono); font-size: 9px; color: var(--faint);
  padding: 6px 14px; letter-spacing: .4px;
}
.ctx-dot {
  width: 6px; height: 6px; border-radius: 50%;
  background: var(--teal); flex: none;
  box-shadow: 0 0 6px var(--teal);
  animation: pulse-dot 2s ease-in-out infinite;
}
@keyframes pulse-dot { 0%,100%{opacity:1} 50%{opacity:.4} }
.model-tag {
  margin-left: auto;
  font-family: var(--mono); font-size: 8.5px;
  color: var(--indigo); opacity: .7;
  background: rgba(91,92,240,.1); border: 1px solid rgba(91,92,240,.2);
  border-radius: 4px; padding: 1px 5px;
}

/* ── Messages ─────────────────────────────────────────────────────────── */
.msgs { flex: 1; overflow-y: auto; padding: 10px 14px 4px; }

/* ── Quick replies ────────────────────────────────────────────────────── */
.quick { display: flex; flex-wrap: wrap; gap: 6px; padding: 6px 14px 10px; }
.qchip {
  font-family: var(--mono); font-size: 10.5px; padding: 6px 12px;
  border-radius: 20px; border: 1px solid rgba(91,92,240,.3);
  background: rgba(91,92,240,.08); color: #9aa6ff;
  cursor: pointer; transition: .15s;
}
.qchip:hover { border-color: rgba(91,92,240,.6); background: rgba(91,92,240,.16); }

/* ── Input ────────────────────────────────────────────────────────────── */
.input-row {
  display: flex; align-items: center; gap: 8px;
  padding: 10px 12px; border-top: 1px solid var(--line);
}
.input-row input {
  flex: 1; background: rgba(255,255,255,.05); border: 1px solid var(--line2);
  border-radius: 10px; padding: 9px 12px; color: var(--txt);
  font-family: var(--body); font-size: 13px; outline: none; transition: .15s;
}
.input-row input:focus { border-color: rgba(91,92,240,.5); }
.input-row input:disabled { opacity: .5; }
.send-btn {
  width: 34px; height: 34px; border-radius: 10px; flex: none;
  background: linear-gradient(135deg, #5b5cf0, #2ee6c5);
  border: none; color: var(--ink); cursor: pointer;
  display: grid; place-items: center; transition: .15s;
}
.send-btn:disabled { opacity: .35; cursor: not-allowed; }
.send-btn:not(:disabled):hover { transform: scale(1.05); }
</style>
