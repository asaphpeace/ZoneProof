<script setup lang="ts">
import { useRouter, useRoute } from 'vue-router'
import { useScopeStore, SCOPED_ROUTES } from '@/stores/scope'
import { useUiStore } from '@/stores/ui'
import { useAuthStore } from '@/stores/auth'
import { useDomainsStore } from '@/stores/domains'
import { ref, computed, onMounted } from 'vue'
import { api } from '@/api/client'
import GlossaryModal from '@/components/ui/GlossaryModal.vue'

const router = useRouter()
const route = useRoute()
const scope = useScopeStore()
const showScope = computed(() => SCOPED_ROUTES.includes(String(route.name)) && domains.list.length > 1)
const scopeValue = computed({
  get: () => scope.domain ?? '',
  set: (v: string) => scope.set(v || null),
})
const ui = useUiStore()
const auth = useAuthStore()
const domains = useDomainsStore()
const alerts = ref<any[]>([])
const unread = ref(0)
const glossaryOpen = ref(false)

const query = ref('')
const searchOpen = ref(false)
const activeIdx = ref(0)

onMounted(() => {
  if (!domains.list.length) domains.fetch()
})

// Persistent progress indicator (GUIDED_ONBOARDING_PLAN.md Part 3 #14) — one
// always-visible "X of Y" widget instead of leaving setup status to whichever
// page the user happens to be on. "Fully protected" = DMARC at reject AND
// MTA-STS at enforce, the same bar RoadmapTrack.vue uses for its "done" state.
const protectionProgress = computed(() => {
  const total = domains.list.length
  const protected_ = domains.list.filter(
    (d: any) => d.dmarc_stage === 'reject' && d.mta_sts_stage === 'enforce'
  ).length
  return { protected_, total }
})

const results = computed(() => {
  const q = query.value.trim().toLowerCase()
  if (!q) return []
  return domains.list
    .filter(d => (d.domain || '').toLowerCase().includes(q))
    .slice(0, 8)
})

function onSearchInput() {
  searchOpen.value = true
  activeIdx.value = 0
}

function selectResult(d: any) {
  router.push({ name: 'domain-detail', params: { id: d.id } })
  query.value = ''
  searchOpen.value = false
}

function onSearchKeydown(e: KeyboardEvent) {
  if (!results.value.length) return
  if (e.key === 'ArrowDown') { e.preventDefault(); activeIdx.value = (activeIdx.value + 1) % results.value.length }
  else if (e.key === 'ArrowUp') { e.preventDefault(); activeIdx.value = (activeIdx.value - 1 + results.value.length) % results.value.length }
  else if (e.key === 'Enter') { e.preventDefault(); selectResult(results.value[activeIdx.value]) }
  else if (e.key === 'Escape') { searchOpen.value = false }
}

function closeSearch() {
  searchOpen.value = false
}

async function toggleAlerts(e: Event) {
  e.stopPropagation()
  if (!ui.alertMenuOpen) {
    alerts.value = await api.alerts()
    unread.value = alerts.value.filter(a => !a.is_read).length
  }
  ui.toggleAlertMenu()
}
</script>

<template>
  <div class="topbar">
    <!-- Hamburger — mobile only -->
    <button class="hamburger" @click="ui.toggleNav()" :class="{ open: ui.navOpen }" aria-label="Toggle menu">
      <span /><span /><span />
    </button>

    <div class="search">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <circle cx="11" cy="11" r="7"/><path d="M21 21l-4-4"/>
      </svg>
      <input
        v-model="query"
        aria-label="Search domains"
        placeholder="Search domains…"
        @input="onSearchInput"
        @focus="searchOpen = true"
        @blur="closeSearch"
        @keydown="onSearchKeydown"
      />
      <div v-if="searchOpen && query.trim()" class="search-dropdown">
        <div
          v-for="(d, i) in results" :key="d.id"
          :class="['search-result', i === activeIdx ? 'active' : '']"
          @mousedown.prevent="selectResult(d)"
        >
          <span class="sr-domain">{{ d.domain }}</span>
          <span class="sr-stage">{{ d.dmarc_stage }}</span>
        </div>
        <div v-if="!results.length" class="search-empty">No domains match "{{ query }}"</div>
      </div>
    </div>
    <label v-if="showScope" class="scope-pick" title="The domain every analysis page is showing">
      <span class="scope-label">Domain</span>
      <select v-model="scopeValue" aria-label="Domain scope">
        <option value="">All domains</option>
        <option v-for="d in domains.list" :key="d.id" :value="d.domain">{{ d.domain }}</option>
      </select>
    </label>
    <div
      v-if="protectionProgress.total > 0"
      class="progress-pill"
      :class="{ complete: protectionProgress.protected_ === protectionProgress.total }"
      title="Domains fully protected — DMARC at reject and MTA-STS at enforce"
      role="link" tabindex="0"
      :aria-label="`${protectionProgress.protected_} of ${protectionProgress.total} domains fully protected. Open the roadmap.`"
      @click="router.push({ name: 'roadmap' })" @keydown.enter.prevent="router.push({ name: 'roadmap' })"
    >
      <span class="pp-dot" />
      {{ protectionProgress.protected_ }} / {{ protectionProgress.total }} protected
    </div>
    <div class="tb-icons">
      <div class="iconbtn" title="Glossary" role="button" tabindex="0" aria-label="Open glossary"
        @click="glossaryOpen = true" @keydown.enter.prevent="glossaryOpen = true" @keydown.space.prevent="glossaryOpen = true">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="12" cy="12" r="10"/><path d="M9.5 9a2.5 2.5 0 0 1 5 0c0 1.5-2.5 2-2.5 3.5"/><line x1="12" y1="17" x2="12.01" y2="17"/>
        </svg>
      </div>
      <div class="iconbtn" role="button" tabindex="0" aria-haspopup="true"
        :aria-label="unread > 0 ? `Alerts, ${unread} unread` : 'Alerts'"
        @click="toggleAlerts" @keydown.enter.prevent="toggleAlerts($event)" @keydown.space.prevent="toggleAlerts($event)">
        <span v-if="unread > 0" class="badge" />
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M18 8a6 6 0 0 0-12 0c0 7-3 9-3 9h18s-3-2-3-9"/>
          <path d="M13.7 21a2 2 0 0 1-3.4 0"/>
        </svg>
      </div>
    </div>
    <GlossaryModal v-if="glossaryOpen" @close="glossaryOpen = false" />
    <div class="profile" role="link" tabindex="0" aria-label="Account and settings"
      @click="router.push({ name: 'profile' })" @keydown.enter.prevent="router.push({ name: 'profile' })">
      <div class="avatar">{{ auth.fullName?.[0]?.toUpperCase() ?? 'A' }}</div>
      <div>
        <div class="nm">{{ auth.fullName || 'Account' }}</div>
        <div class="rl">Admin</div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.topbar { display: flex; align-items: center; gap: 14px; margin-bottom: 20px; }
.search { position: relative; flex: 1; max-width: 380px; display: flex; align-items: center; gap: 10px; background: rgba(255,255,255,.04); border: 1px solid var(--line); border-radius: 13px; padding: 11px 15px; }
.search svg { width: 16px; height: 16px; color: var(--faint); flex: none; }
.search input { background: none; border: none; outline: none; color: var(--txt); font-family: var(--body); font-size: 13px; width: 100%; }
.search input::placeholder { color: var(--faint); }
.search-dropdown {
  position: absolute; top: calc(100% + 8px); left: 0; right: 0; z-index: 50;
  background: rgba(20,20,30,.97); border: 1px solid var(--line); border-radius: 13px;
  padding: 6px; backdrop-filter: blur(14px); box-shadow: 0 14px 40px rgba(0,0,0,.4);
  max-height: 320px; overflow-y: auto;
}
.search-result { display: flex; align-items: center; justify-content: space-between; gap: 10px; padding: 9px 11px; border-radius: 9px; cursor: pointer; font-size: 13px; color: var(--muted); }
.search-result:hover, .search-result.active { background: rgba(91,92,240,.15); color: var(--txt); }
.sr-domain { font-weight: 600; color: var(--txt); }
.sr-stage { font-family: var(--mono); font-size: 10px; color: var(--faint); text-transform: uppercase; }
.search-empty { padding: 10px 11px; font-size: 12.5px; color: var(--faint); }
.progress-pill {
  display: flex; align-items: center; gap: 7px; font-family: var(--mono); font-size: 11px;
  color: var(--muted); background: rgba(255,255,255,.04); border: 1px solid var(--line);
  border-radius: 20px; padding: 8px 14px; cursor: pointer; transition: .15s; flex: none;
}
.progress-pill:hover { border-color: var(--line2); color: var(--txt); }
.progress-pill.complete { color: var(--good); border-color: rgba(52,224,161,.3); }
.pp-dot { width: 6px; height: 6px; border-radius: 50%; background: var(--amber); flex: none; }
.progress-pill.complete .pp-dot { background: var(--good); }
.tb-icons { display: flex; gap: 9px; margin-left: auto; }
.scope-pick { display: flex; align-items: center; gap: 8px; flex: none; background: rgba(255,255,255,.04); border: 1px solid var(--line); border-radius: 13px; padding: 7px 12px; }
.scope-label { font-size: 11px; letter-spacing: .08em; text-transform: uppercase; color: var(--faint); }
.scope-pick select { background: transparent; border: none; outline: none; color: var(--txt); font-family: var(--body); font-size: 13px; max-width: 220px; cursor: pointer; }
.scope-pick select option { background: #14162a; color: #e8e9f2; }
.search { min-width: 0; }
@media (max-width: 760px) {
  .topbar { flex-wrap: wrap; row-gap: 10px; }
  .scope-label { display: none; }
  .scope-pick { padding: 7px 10px; }
  .scope-pick select { max-width: 112px; }
}
.iconbtn { width: 40px; height: 40px; border-radius: 12px; background: rgba(255,255,255,.04); border: 1px solid var(--line); display: grid; place-items: center; cursor: pointer; color: var(--muted); transition: .15s; position: relative; }
.iconbtn:hover { color: var(--txt); border-color: var(--line2); }
.iconbtn svg { width: 17px; height: 17px; }
.badge { position: absolute; top: 8px; right: 9px; width: 7px; height: 7px; border-radius: 50%; background: var(--pink); box-shadow: 0 0 8px var(--pink); }
.profile { display: flex; align-items: center; gap: 10px; background: rgba(255,255,255,.04); border: 1px solid var(--line); border-radius: 13px; padding: 6px 13px 6px 7px; cursor: pointer; }
.avatar { width: 30px; height: 30px; border-radius: 9px; background: linear-gradient(135deg,#f5417a,#8b5cf6); display: grid; place-items: center; font-family: var(--disp); font-weight: 700; font-size: 12px; color: #fff; }
.nm { font-size: 12.5px; font-weight: 600; line-height: 1.1; }
.rl { font-size: 10px; color: var(--faint); }

.hamburger {
  display: none; flex-direction: column; justify-content: center; gap: 5px;
  background: rgba(255,255,255,.04); border: 1px solid var(--line);
  border-radius: 12px; width: 40px; height: 40px; padding: 10px; cursor: pointer;
  flex: none;
}
.hamburger span {
  display: block; height: 2px; border-radius: 2px;
  background: var(--muted); transition: .2s;
}
.hamburger.open span:nth-child(1) { transform: translateY(7px) rotate(45deg); }
.hamburger.open span:nth-child(2) { opacity: 0; }
.hamburger.open span:nth-child(3) { transform: translateY(-7px) rotate(-45deg); }

@media (max-width: 1000px) {
  .hamburger { display: flex; }
}
</style>
