<script setup lang="ts">
import { ref, watch, onMounted, onUnmounted } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import AppSidebar from './AppSidebar.vue'
import AppTopbar from './AppTopbar.vue'
import AppDrawer from './AppDrawer.vue'
import AppModal from './AppModal.vue'
import AppToast from './AppToast.vue'
import AlertMenu from '../alerts/AlertMenu.vue'
import AssistantPanel from '../assistant/AssistantPanel.vue'
import { useUiStore } from '@/stores/ui'
import { useScopeStore, SCOPED_ROUTES } from '@/stores/scope'
import { useDomainsStore } from '@/stores/domains'
import { api, upgradeRequired } from '@/api/client'

const ui     = useUiStore()
const router = useRouter()
const route  = useRoute()
const scope  = useScopeStore()
const domainsStore = useDomainsStore()

// A ?domain= in the address (deep links, shared URLs) wins and becomes the scope.
function adoptFromUrl() {
  const q = route.query.domain
  if (typeof q === 'string' && q && q !== scope.domain) scope.set(q)
}
// On a scoped page, the address reflects the scope so it can be shared or reloaded.
function reflectInUrl() {
  if (!SCOPED_ROUTES.includes(String(route.name))) return
  const want = scope.domain || undefined
  if ((route.query.domain as string | undefined) === want) return
  router.replace({ query: { ...route.query, domain: want } })
}
watch(() => route.query.domain, adoptFromUrl, { immediate: true })
watch(() => scope.domain, reflectInUrl)
watch(() => route.name, reflectInUrl, { immediate: true })
watch(() => domainsStore.list, (list) => scope.reconcile(list.map((d: any) => d.domain)))

const showBanner = ref(false)
const resending  = ref(false)
const resent     = ref(false)

// Upgrade prompt — shown whenever any API call returns 403 upgrade_required
const upgradePrompt = ref<{ message: string; current_plan: string } | null>(null)

function handleUpgradeRequired(detail: any) {
  upgradePrompt.value = { message: detail.message, current_plan: detail.current_plan }
}

onMounted(async () => {
  upgradeRequired.on(handleUpgradeRequired)
  try {
    const me = await api.me()
    showBanner.value = !me.email_verified
  } catch { /* leave hidden */ }
})

onUnmounted(() => {
  upgradeRequired.off(handleUpgradeRequired)
})

async function resendVerification() {
  resending.value = true
  try {
    await api.resendVerification()
    resent.value = true
  } catch { /* swallow — banner stays, user can retry */ }
  finally { resending.value = false }
}

function focusMain() {
  document.getElementById('main-content')?.focus()
}

function goUpgrade() {
  upgradePrompt.value = null
  router.push({ name: 'billing' })
}
</script>

<template>
  <div class="app">
    <!-- Overlay backdrop (mobile only) -->
    <Transition name="fade">
      <div v-if="ui.navOpen" class="nav-backdrop" aria-hidden="true" @click="ui.closeNav()" />
    </Transition>

    <a class="skip-link" href="#main-content" @click.prevent="focusMain">Skip to main content</a>
    <AppSidebar />
    <main id="main-content" class="main" tabindex="-1">
      <div v-if="showBanner" class="verify-banner">
        <span>Please verify your email address to secure your account.</span>
        <button v-if="!resent" class="verify-btn" :disabled="resending" @click="resendVerification">
          {{ resending ? 'Sending…' : 'Resend verification email' }}
        </button>
        <span v-else class="verify-sent">Sent — check your inbox.</span>
        <button class="verify-dismiss" @click="showBanner = false" aria-label="Dismiss">✕</button>
      </div>
      <AppTopbar />
      <RouterView class="fade-up" />
    </main>
  </div>
  <AppDrawer />
  <AppModal />
  <AppToast />
  <AlertMenu />
  <AssistantPanel />

  <!-- ── Plan limit / upgrade prompt ──────────────────────────────────── -->
  <Teleport to="body">
    <div v-if="upgradePrompt" class="upgrade-overlay" @click.self="upgradePrompt = null">
      <div class="upgrade-modal">
        <div class="upgrade-icon">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z"/>
          </svg>
        </div>
        <div class="upgrade-title">Plan limit reached</div>
        <div class="upgrade-msg">{{ upgradePrompt.message }}</div>
        <div class="upgrade-actions">
          <button class="upgrade-btn-cancel" @click="upgradePrompt = null">Not now</button>
          <button class="upgrade-btn-cta" @click="goUpgrade">View upgrade options →</button>
        </div>
      </div>
    </div>
  </Teleport>
</template>

<style scoped>
#main-content:focus { outline: none; }
.app { display: grid; grid-template-columns: 232px 1fr; min-height: 100vh; }
.main { padding: 14px 22px 60px; overflow: hidden; }

.nav-backdrop {
  display: none;
  position: fixed; inset: 0; z-index: 99;
  background: rgba(0,0,0,.55); backdrop-filter: blur(2px);
}

.verify-banner {
  display: flex; align-items: center; gap: 14px; flex-wrap: wrap;
  background: rgba(245,197,66,.1); border: 1px solid rgba(245,197,66,.3);
  border-radius: 14px; padding: 11px 16px; margin-bottom: 14px;
  font-size: 12.5px; color: #f5e49a;
}
.verify-btn {
  background: rgba(245,197,66,.18); border: 1px solid rgba(245,197,66,.4); color: #f5e49a;
  border-radius: 9px; padding: 6px 14px; font-size: 11.5px; font-weight: 600; cursor: pointer;
  font-family: var(--body);
}
.verify-btn:disabled { opacity: .6; cursor: not-allowed; }
.verify-sent { color: var(--good); font-weight: 600; }
.verify-dismiss {
  margin-left: auto; background: none; border: none; color: #f5e49a; opacity: .7;
  cursor: pointer; font-size: 13px; padding: 2px 6px;
}
.verify-dismiss:hover { opacity: 1; }

@media (max-width: 1000px) {
  .app { grid-template-columns: 1fr; }
  .nav-backdrop { display: block; }
}

/* ── Upgrade prompt ───────────────────────────────────────────── */
.upgrade-overlay {
  position: fixed; inset: 0; z-index: 2000;
  background: color-mix(in srgb, var(--bg) 70%, transparent); backdrop-filter: blur(8px);
  display: grid; place-items: center; padding: 20px;
}
.upgrade-modal {
  width: 400px; max-width: 94vw;
  background: #0f1118; border: 1px solid rgba(91,92,240,.35);
  border-radius: 20px; padding: 32px; text-align: center;
  box-shadow: 0 40px 80px rgba(0,0,0,.6), 0 0 0 1px rgba(91,92,240,.1);
}
.upgrade-icon {
  width: 52px; height: 52px; border-radius: 16px; margin: 0 auto 18px;
  display: grid; place-items: center;
  background: rgba(91,92,240,.12); border: 1px solid rgba(91,92,240,.3);
  color: #9aa6ff;
}
.upgrade-icon svg { width: 22px; height: 22px; }
.upgrade-title {
  font-family: var(--disp); font-weight: 800; font-size: 18px;
  margin-bottom: 10px;
}
.upgrade-msg {
  color: var(--muted); font-size: 13px; line-height: 1.65; margin-bottom: 24px;
}
.upgrade-actions { display: flex; gap: 10px; }
.upgrade-btn-cancel {
  flex: 1; background: rgba(255,255,255,.06); border: 1px solid var(--line2);
  border-radius: 11px; padding: 11px; color: var(--muted);
  font-family: var(--disp); font-weight: 600; font-size: 13px; cursor: pointer;
}
.upgrade-btn-cancel:hover { color: var(--txt); }
.upgrade-btn-cta {
  flex: 2; background: linear-gradient(90deg,#5b5cf0,#4b4ce0); color: #fff;
  border: none; border-radius: 11px; padding: 11px;
  font-family: var(--disp); font-weight: 700; font-size: 13px; cursor: pointer;
}
.upgrade-btn-cta:hover { opacity: .88; }

.fade-enter-active, .fade-leave-active { transition: opacity .2s; }
.fade-enter-from, .fade-leave-to { opacity: 0; }
</style>
