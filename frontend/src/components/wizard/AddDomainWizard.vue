<script setup lang="ts">
import { ref } from 'vue'
import { useUiStore } from '@/stores/ui'
import StepTracker from '@/components/ui/StepTracker.vue'
import WizardStep1Domains   from './WizardStep1Domains.vue'
import WizardStep2Records   from './WizardStep2Records.vue'
import WizardStepPlatforms  from './WizardStepPlatforms.vue'
import { useRouter } from 'vue-router'
import { api } from '@/api/client'

const emit = defineEmits<{ close: [] }>()
const ui     = useUiStore()
const router = useRouter()

const step    = ref(0)
const domains = ref<string[]>([])
const confirmedDomainNames = ref<string[]>([])

const STEPS = ['Domains', 'DNS records', 'Platforms']

function step1Done(d: string[]) { domains.value = d; step.value = 1 }
function step2Done(names: string[]) { confirmedDomainNames.value = names; step.value = 2 }
function done() {
  emit('close')
  const first = confirmedDomainNames.value[0]
  router.push({ name: 'roadmap', query: first ? { domain: first } : {} })
}

async function abort() {
  // Delete any is_active=false draft domains created by wizardStart.
  // Fire-and-forget — don't block the UI close on a network call.
  if (domains.value.length && step.value < 2) {
    api.wizardAbort(domains.value).catch(() => {})
  }
  emit('close')
}
</script>

<template>
  <Teleport to="body">
    <div class="overlay" @click.self="abort">
      <div class="wizard-panel">
        <div class="wizard-header">
          <div class="wh-title">
            <div class="wh-logo">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" style="width:16px">
                <path d="M22 6l-10 7L2 6"/><rect x="2" y="4" width="20" height="16" rx="2"/>
              </svg>
            </div>
            Add domains to ZoneProof
          </div>
          <button class="close-btn" @click="abort">×</button>
        </div>

        <div class="wizard-steps">
          <StepTracker :steps="STEPS" :current="step" />
        </div>

        <div class="wizard-body">
          <WizardStep1Domains v-if="step === 0" @next="step1Done" />
          <WizardStep2Records v-else-if="step === 1" :domains="domains" @next="step2Done" @cancel="abort" />
          <WizardStepPlatforms v-else :domain-names="confirmedDomainNames" @done="done" />
        </div>
      </div>
    </div>
  </Teleport>
</template>

<style scoped>
.overlay { position: fixed; inset: 0; background: rgba(0,0,0,.6); backdrop-filter: blur(6px); z-index: 1000; display: grid; place-items: center; padding: 20px; }
.wizard-panel { width: 660px; max-width: 96vw; max-height: 90vh; background: #0f1118; border: 1px solid var(--line2); border-radius: 22px; box-shadow: 0 40px 120px rgba(0,0,0,.7); display: flex; flex-direction: column; overflow: hidden; }
.wizard-header { display: flex; align-items: center; justify-content: space-between; padding: 20px 24px 0; }
.wh-title { display: flex; align-items: center; gap: 10px; font-family: var(--disp); font-weight: 800; font-size: 15px; }
.wh-logo { width: 32px; height: 32px; border-radius: 10px; background: radial-gradient(circle at 30% 25%,#2ef5d4,#5b5cf0); display: grid; place-items: center; color: var(--ink); }
.close-btn { background: none; border: none; color: var(--muted); font-size: 22px; cursor: pointer; line-height: 1; padding: 4px; border-radius: 8px; }
.close-btn:hover { color: var(--txt); background: rgba(255,255,255,.06); }
.wizard-steps { padding: 20px 24px 0; }
.wizard-body { flex: 1; overflow-y: auto; padding: 20px 24px 24px; }
</style>
