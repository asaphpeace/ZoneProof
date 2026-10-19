<script setup lang="ts">
import { ref, watch, nextTick } from 'vue'
import { useUiStore } from '@/stores/ui'

const ui = useUiStore()
const panel = ref<HTMLElement | null>(null)
let opener: HTMLElement | null = null

// Move focus into the dialog when it opens and give it back when it closes.
watch(() => ui.modalOpen, async (open) => {
  if (open) {
    opener = document.activeElement as HTMLElement | null
    await nextTick()
    panel.value?.focus()
  } else {
    opener?.focus?.()
    opener = null
  }
})

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'

function onKey(e: KeyboardEvent) {
  if (e.key === 'Escape') { e.stopPropagation(); ui.closeModal(); return }
  if (e.key !== 'Tab' || !panel.value) return
  const items = Array.from(panel.value.querySelectorAll<HTMLElement>(FOCUSABLE))
  if (!items.length) { e.preventDefault(); return }
  const first = items[0], last = items[items.length - 1]
  if (e.shiftKey && (document.activeElement === first || document.activeElement === panel.value)) { e.preventDefault(); last.focus() }
  else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus() }
}
</script>

<template>
  <Teleport to="body">
    <div v-if="ui.modalOpen" class="backdrop" aria-hidden="true" @click="ui.closeModal()" />
    <div
      v-if="ui.modalOpen" ref="panel" class="modal show" role="dialog" aria-modal="true"
      :aria-label="ui.modalTitle || 'Dialog'" tabindex="-1" @keydown="onKey"
    >
      <div class="mdhead">
        <span>{{ ui.modalTitle }}</span>
        <button type="button" class="drx" aria-label="Close dialog" @click="ui.closeModal()">✕</button>
      </div>
      <component :is="ui.modalContent?.component" v-bind="ui.modalContent?.props" v-if="ui.modalContent?.component" />
    </div>
  </Teleport>
</template>

<style scoped>
.backdrop { position: fixed; inset: 0; background: rgba(3,4,12,.62); backdrop-filter: blur(3px); z-index: 60; }
.modal {
  position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%);
  width: 580px; max-width: 94vw; max-height: 88vh; overflow-y: auto;
  background: linear-gradient(160deg, var(--surface-raised), var(--bg));
  border: 1px solid var(--line2); border-radius: 18px; z-index: 70;
  padding: 24px; box-shadow: 0 30px 80px rgba(0,0,0,.6);
  animation: modal-in .25s ease;
}
.modal:focus { outline: none; }
@keyframes modal-in { from { opacity: 0; transform: translate(-50%, -46%); } to { opacity: 1; transform: translate(-50%, -50%); } }
.mdhead { display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px; }
.mdhead > span:first-child { font-family: var(--disp); font-weight: 800; font-size: 17px; }
.drx { cursor: pointer; color: var(--muted); width: 30px; height: 30px; display: grid; place-items: center; border-radius: 9px; border: 1px solid var(--line); background: transparent; font: inherit; }
.drx:hover { color: var(--txt); }
</style>
