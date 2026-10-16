<script setup lang="ts">
import ZoneProofLogo from './ZoneProofLogo.vue'
import { useRouter, useRoute } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { useUiStore } from '@/stores/ui'
import { useBrandGuardStore } from '@/stores/brandGuard'
import { computed, ref, watch } from 'vue'

const router = useRouter()
const route  = useRoute()
const auth   = useAuthStore()
const ui     = useUiStore()
const brand  = useBrandGuardStore()

// Brand Guard has its own pages: while one is open, its submenu shows under the Brand Guard item.
const inBrand = computed(() => String(route.name ?? '').startsWith('brand-guard'))
const brandOpen = ref(true)   // the user can fold the submenu while staying on a Brand Guard page
watch(inBrand, on => { if (on) { brandOpen.value = true; brand.ensureSummary(); if (!brand.campaigns.length) brand.loadCampaigns() } }, { immediate: true })
type BrandMenuItem = { id?: string; label: string; count?: number | string; urgent?: boolean; soon?: boolean }
const brandMenu = computed((): { label: string; items: BrandMenuItem[] }[] => [
  { label: 'Triage', items: [
    { id: 'brand-guard', label: 'Overview', count: brand.summary?.open_candidates || '', urgent: true },
    { id: 'brand-guard-candidates', label: 'Candidates' },
    { id: 'brand-guard-campaigns', label: 'Campaigns', count: brand.campaigns.length || '' },
  ] },
  { label: 'Respond', items: [{ id: 'brand-guard-cases', label: 'Cases' }, { id: 'brand-guard-defend', label: 'Defend' }] },
  { label: 'Setup', items: [{ id: 'brand-guard-profile', label: 'Brand profile' }, { id: 'brand-guard-notifications', label: 'Alerts' }] },
  { label: 'Insight', items: [{ id: 'brand-guard-funnel', label: 'Funnel' }] },
])

const nav = [
  { label: 'Portfolio',  group: true },
  { id: 'overview', label: 'Overview',        num: '01', icon: 'grid' },
  { id: 'domains',  label: 'Domains',         num: '02', icon: 'globe' },
  { label: 'Analyze', group: true },
  { id: 'posture',  label: 'Posture',         num: '03', icon: 'pulse' },
  { id: 'dmarc',    label: 'DMARC',           num: '04', icon: 'mail' },
  { id: 'tls',      label: 'MTA-STS & TLS',  num: '05', icon: 'lock' },
  { id: 'brand-guard', label: 'Brand Guard', num: '06', icon: 'shield' },
  { label: 'Plan',   group: true },
  { id: 'roadmap',  label: 'Roadmap',         num: '07', icon: 'chevron' },
  { id: 'certs',    label: 'Certificates',    num: '08', icon: 'award' },
  { id: 'timeline', label: 'DNS Timeline',    num: '09', icon: 'clock' },
  { label: 'Account', group: true },
  { id: 'billing',  label: 'Plan & Billing',  num: '10', icon: 'billing' },
  { id: 'profile',  label: 'Settings',        num: '11', icon: 'settings' },
  { id: 'sources',  label: 'Data sources',    num: '12', icon: 'pulse',   adminOnly: true },
  { id: 'msp',      label: 'MSP Clients',     num: '13', icon: 'msp',     mspOnly: true },
  { id: 'audit-log', label: 'Audit Log',      num: '14', icon: 'audit',   enterpriseOnly: true },
  { label: 'Resources', group: true },
  { id: 'docs',     label: 'Documentation',   num: '15', icon: 'book' },
]

const initials = (name: string) => name ? name[0].toUpperCase() : 'A'

function logout() {
  auth.logout()
  router.push({ name: 'login' })
}

// On a Brand Guard page, clicking the Brand Guard item folds/unfolds its submenu; from anywhere else it opens Brand Guard.
function onNavClick(id: string) {
  if (id === 'brand-guard' && inBrand.value) { brandOpen.value = !brandOpen.value; return }
  navigate(id)
}

function navigate(name: string) {
  router.push({ name })
  ui.closeNav()
}
</script>

<template>
  <aside class="sidebar" :class="{ open: ui.navOpen }" aria-label="Main navigation">
    <!-- Brand -->
    <div class="brand">
      <ZoneProofLogo subtitle="DMARC · MTA-STS · BRAND" />
    </div>


    <!-- Nav -->
    <template v-for="item in nav" :key="item.label">
      <div v-if="item.group" class="nav-label">{{ item.label }}</div>
      <div v-else-if="(!item.mspOnly || ['msp','enterprise'].includes(auth.plan)) && (!item.adminOnly || auth.isAdmin())"
        :class="['nav-item', route.name === item.id || (item.id === 'brand-guard' && inBrand) ? 'active' : '', item.enterpriseOnly && auth.plan !== 'enterprise' ? 'locked' : '']"
        :role="item.id === 'brand-guard' ? 'button' : 'link'" tabindex="0"
        :aria-current="route.name === item.id ? 'page' : undefined"
        :aria-expanded="item.id === 'brand-guard' && inBrand ? brandOpen : undefined"
        @click="onNavClick(item.id!)"
        @keydown.enter.prevent="onNavClick(item.id!)" @keydown.space.prevent="onNavClick(item.id!)"
      >
        <!-- icons inline for simplicity -->
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <template v-if="item.icon === 'grid'">
            <rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/>
            <rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/>
          </template>
          <template v-else-if="item.icon === 'globe'">
            <circle cx="12" cy="12" r="10"/>
            <line x1="2" y1="12" x2="22" y2="12"/>
            <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
          </template>
          <path v-else-if="item.icon === 'pulse'" d="M3 12h4l3 8 4-16 3 8h4"/>
          <template v-else-if="item.icon === 'mail'">
            <path d="M22 6l-10 7L2 6"/><rect x="2" y="4" width="20" height="16" rx="2"/>
          </template>
          <template v-else-if="item.icon === 'lock'">
            <rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
          </template>
          <path v-else-if="item.icon === 'chevron'" d="M9 18l6-6-6-6"/>
          <template v-else-if="item.icon === 'award'">
            <circle cx="12" cy="8" r="6"/><path d="M9 13l-2 8 5-3 5 3-2-8"/>
          </template>
          <template v-else-if="item.icon === 'clock'">
            <circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>
          </template>
          <template v-else-if="item.icon === 'billing'">
            <rect x="1" y="4" width="22" height="16" rx="2"/><line x1="1" y1="10" x2="23" y2="10"/>
          </template>
          <template v-else-if="item.icon === 'msp'">
            <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/>
            <circle cx="9" cy="7" r="4"/>
            <path d="M23 21v-2a4 4 0 0 0-3-3.87"/>
            <path d="M16 3.13a4 4 0 0 1 0 7.75"/>
          </template>
          <template v-else-if="item.icon === 'settings'">
            <circle cx="12" cy="12" r="3"/>
            <path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z"/>
          </template>
          <template v-else-if="item.icon === 'book'">
            <path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/>
            <path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/>
          </template>
          <template v-else-if="item.icon === 'shield'">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/>
          </template>
          <template v-else-if="item.icon === 'audit'">
            <path d="M9 11l3 3L22 4"/>
            <path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/>
          </template>
        </svg>
        {{ item.label }}
        <span v-if="item.enterpriseOnly && auth.plan !== 'enterprise'" class="lock-badge" title="Enterprise feature">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2">
            <rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
          </svg>
        </span>
        <span v-else class="num">{{ item.num }}</span>
      </div>
      <div v-if="item.id === 'brand-guard' && inBrand && brandOpen" class="subnav" role="group" aria-label="Brand Guard">
        <template v-for="g in brandMenu" :key="g.label">
          <div class="sub-label">{{ g.label }}</div>
          <template v-for="s in g.items" :key="s.label">
            <span v-if="s.soon" class="sub-item soon" aria-disabled="true" title="Not part of Brand Guard yet">{{ s.label }}<em>Soon</em></span>
            <div v-else :class="['sub-item', route.name === s.id ? 'on' : '']" :aria-current="route.name === s.id ? 'page' : undefined" role="link" tabindex="0"
              @click="navigate(s.id!)" @keydown.enter="navigate(s.id!)">
              {{ s.label }}<b v-if="s.count" :class="{ urgent: s.urgent }">{{ s.count }}</b>
            </div>
          </template>
        </template>
      </div>
    </template>

    <!-- Add domain CTA -->
    <div class="add-domain-btn" role="link" tabindex="0" @click="navigate('domains')"
      @keydown.enter.prevent="navigate('domains')" @keydown.space.prevent="navigate('domains')">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2">
        <path d="M12 5v14M5 12h14"/>
      </svg>
      Add domain
    </div>

    <!-- User footer -->
    <div class="side-user">
      <div class="avatar">{{ initials(auth.fullName) }}</div>
      <div class="user-info">
        <div class="nm">{{ auth.fullName || 'Account' }}</div>
        <div class="rl-row">
          <span class="rl">{{ auth.role || 'Admin' }}</span>
          <span class="plan-pill" @click.stop="router.push({ name: 'billing' })" tabindex="0" role="link" @keydown.enter.prevent="router.push({ name: 'billing' })" @keydown.space.prevent="router.push({ name: 'billing' })">{{ auth.plan }}</span>
        </div>
        <div class="ws" v-if="auth.workspaceName">{{ auth.workspaceName }}</div>
      </div>
      <button class="logout-btn" title="Sign out" @click.stop="logout">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/>
          <polyline points="16 17 21 12 16 7"/>
          <line x1="21" y1="12" x2="9" y2="12"/>
        </svg>
      </button>
    </div>
  </aside>
</template>

<style scoped>
.sidebar {
  margin: 14px 0 14px 14px; border-radius: 22px; padding: 18px 14px;
  background: linear-gradient(180deg, rgba(255,255,255,.05), rgba(255,255,255,.012));
  border: 1px solid var(--line); backdrop-filter: blur(14px);
  display: flex; flex-direction: column; gap: 4px;
  position: sticky; top: 14px; height: calc(100vh - 28px); overflow-y: auto;
}
.brand { display: flex; align-items: center; gap: 11px; padding: 4px 8px 14px; }
.nav-label { font-family: var(--mono); font-size: 9px; letter-spacing: 1.4px; color: var(--faint); text-transform: uppercase; padding: 12px 12px 5px; }
.nav-item { display: flex; align-items: center; gap: 12px; padding: 9px 13px; border-radius: 12px; color: var(--muted); cursor: pointer; font-weight: 500; font-size: 13px; transition: all .16s ease; }
.nav-item svg { width: 17px; height: 17px; flex: none; opacity: .85; }
.nav-item:hover { background: rgba(255,255,255,.05); color: var(--txt); }
.nav-item.active { background: linear-gradient(90deg, #5b5cf0, #4b4ce0); color: #fff; box-shadow: 0 8px 24px rgba(91,92,240,.45); }
.nav-item.active svg { opacity: 1; }
.num { font-family: var(--mono); font-size: 9.5px; margin-left: auto; opacity: .55; }
.subnav { margin: 2px 0 6px; padding: 6px 6px 8px; border-radius: 12px; background: rgba(255,255,255,.03); border: 1px solid var(--line); display: flex; flex-direction: column; gap: 1px; }
.sub-label { font-family: var(--mono); font-size: 9px; letter-spacing: 1.2px; text-transform: uppercase; color: var(--faint); padding: 8px 10px 3px; }
.sub-item { display: flex; align-items: center; justify-content: space-between; gap: 8px; min-height: 34px; padding: 0 10px; border-radius: 9px; font-size: 12.5px; color: var(--muted); cursor: pointer; position: relative; }
.sub-item:hover:not(.soon) { background: rgba(255,255,255,.05); color: var(--txt); }
.sub-item.on { background: rgba(91,92,240,.2); color: #fff; }
.sub-item.on::before { content: ''; position: absolute; left: -6px; top: 8px; bottom: 8px; width: 3px; border-radius: 0 3px 3px 0; background: var(--indigo); }
.sub-item b { font-family: var(--mono); font-size: 10px; padding: 1px 7px; border-radius: 999px; background: rgba(255,255,255,.08); color: var(--muted); }
.sub-item b.urgent { background: rgba(255,77,109,.18); color: #ff8da1; }
.sub-item.soon { cursor: default; opacity: .55; }
.sub-item.soon em { font-style: normal; font-family: var(--mono); font-size: 9px; padding: 1px 6px; border-radius: 4px; border: 1px solid var(--line2); color: var(--faint); }
.nav-item.locked { opacity: .62; }
.nav-item.locked:hover { opacity: .85; }
.lock-badge { margin-left: auto; display: flex; align-items: center; color: var(--faint); }
.lock-badge svg { width: 12px; height: 12px; opacity: .8; }
.nav-item.active .lock-badge { color: rgba(255,255,255,.8); }
.add-domain-btn {
  display: flex; align-items: center; gap: 8px; margin: 8px 4px 0; padding: 9px 13px;
  border-radius: 12px; border: 1px dashed var(--line2); color: var(--accent-soft);
  cursor: pointer; font-size: 12.5px; font-weight: 600; transition: .15s;
}
.add-domain-btn:hover { background: rgba(91,92,240,.1); border-color: var(--accent); }
.add-domain-btn svg { width: 14px; height: 14px; }
.side-user {
  margin-top: auto; display: flex; align-items: center; gap: 10px;
  padding: 10px 11px; border-radius: 14px;
  background: rgba(255,255,255,.04); border: 1px solid var(--line);
}
.avatar {
  width: 34px; height: 34px; border-radius: 10px; flex: none;
  background: linear-gradient(135deg, #f5417a, #8b5cf6);
  display: grid; place-items: center;
  font-family: var(--disp); font-weight: 700; font-size: 14px; color: #fff;
}
.user-info { flex: 1; min-width: 0; }
.nm { font-size: 12.5px; font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.rl-row { display: flex; align-items: center; gap: 6px; margin-top: 1px; }
.rl { font-size: 10px; color: var(--muted); text-transform: capitalize; }
.plan-pill { font-family: var(--mono); font-size: 8px; font-weight: 700; letter-spacing: .4px; text-transform: uppercase; background: rgba(91,92,240,.18); color: var(--indigo); padding: 1px 7px; border-radius: 10px; cursor: pointer; transition: background .15s; }
.plan-pill:hover { background: rgba(91,92,240,.3); }
.ws { font-size: 9.5px; color: var(--faint); font-family: var(--mono); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; margin-top: 1px; }
.logout-btn {
  flex: none; background: none; border: none; cursor: pointer;
  color: var(--faint); padding: 5px; border-radius: 8px;
  display: grid; place-items: center; transition: .15s;
}
.logout-btn:hover { background: rgba(255,77,109,.12); color: var(--bad); }
.logout-btn svg { width: 15px; height: 15px; }

@media (max-width: 1000px) {
  .sidebar {
    position: fixed; top: 0; left: 0; bottom: 0; z-index: 100;
    margin: 0; border-radius: 0 22px 22px 0;
    transform: translateX(-100%);
    transition: transform .25s cubic-bezier(.4,0,.2,1);
    height: 100dvh;
  }
  .sidebar.open { transform: translateX(0); }
}
</style>
