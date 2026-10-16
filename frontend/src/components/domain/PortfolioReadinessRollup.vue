<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { useRouter } from 'vue-router'
import { api } from '@/api/client'

// PAIN_POINT_RESOLUTION_PLAN.md's Portfolio Readiness Rollup — every
// single-domain readiness fix in this plan, rolled up across the whole
// tenant. An MSP managing 30 client domains needs this at a glance, not
// 30 domain pages opened one at a time.
const router = useRouter()
const categories = ref<any[]>([])
const loading = ref(true)
const expanded = ref<string | null>(null)

onMounted(async () => {
  try {
    const result = await api.readinessRollup()
    categories.value = result.categories
  } finally {
    loading.value = false
  }
})

const totalAffected = computed(() => {
  const ids = new Set<string>()
  for (const c of categories.value) for (const d of c.domains) ids.add(d.domain_id)
  return ids.size
})

const CATEGORY_ROUTE: Record<string, string> = {
  platform_setup: 'domain-detail',
  undispositioned_subdomains: 'domain-detail',
  mta_sts_hosting: 'tls',
  blocking_sources: 'roadmap',
}

function goTo(category: string, domainId: string, domainName: string) {
  const routeName = CATEGORY_ROUTE[category]
  if (routeName === 'domain-detail') {
    router.push({ name: 'domain-detail', params: { id: domainId } })
  } else {
    router.push({ name: routeName, query: { domain: domainName } })
  }
}
</script>

<template>
  <div v-if="!loading && totalAffected > 0" class="rollup-card">
    <div class="rollup-header">
      <span class="rollup-title">Portfolio readiness</span>
      <span class="rollup-pill">{{ totalAffected }} domain{{ totalAffected > 1 ? 's' : '' }} need attention</span>
    </div>

    <div v-for="c in categories.filter(c => c.count > 0)" :key="c.category" class="rollup-cat">
      <div class="rollup-cat-head" @click="expanded = expanded === c.category ? null : c.category" tabindex="0" role="button" :aria-expanded="expanded === c.category" @keydown.enter.prevent="expanded = expanded === c.category ? null : c.category" @keydown.space.prevent="expanded = expanded === c.category ? null : c.category">
        <span class="cat-label">{{ c.label }}</span>
        <span class="cat-count">{{ c.count }}</span>
        <svg class="cat-chev" :class="{ open: expanded === c.category }" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
          <path d="M6 9l6 6 6-6"/>
        </svg>
      </div>
      <div v-if="expanded === c.category" class="rollup-domains">
        <div v-for="d in c.domains" :key="d.domain_id" class="rollup-domain-row" @click="goTo(c.category, d.domain_id, d.domain_name)" tabindex="0" role="link" @keydown.enter.prevent="goTo(c.category, d.domain_id, d.domain_name)" @keydown.space.prevent="goTo(c.category, d.domain_id, d.domain_name)">
          <span class="rd-name">{{ d.domain_name }}</span>
          <span class="rd-detail">{{ d.detail }}</span>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.rollup-card { background: var(--glass); border: 1px solid var(--line2); border-radius: 16px; padding: 16px 18px; margin-bottom: 18px; }
.rollup-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 10px; flex-wrap: wrap; gap: 8px; }
.rollup-title { font-family: var(--disp); font-weight: 700; font-size: 14px; }
.rollup-pill { font-family: var(--mono); font-size: 11px; font-weight: 700; color: var(--amber); background: rgba(245,197,66,.12); border: 1px solid rgba(245,197,66,.3); padding: 4px 12px; border-radius: 20px; }

.rollup-cat { border-top: 1px solid var(--line); }
.rollup-cat-head { display: flex; align-items: center; gap: 10px; padding: 10px 2px; cursor: pointer; }
.cat-label { flex: 1; font-size: 12.5px; color: var(--txt); }
.cat-count { font-family: var(--mono); font-size: 11px; color: var(--amber); background: rgba(245,197,66,.1); padding: 2px 9px; border-radius: 8px; }
.cat-chev { width: 13px; height: 13px; color: var(--faint); transition: transform .2s; }
.cat-chev.open { transform: rotate(180deg); }

.rollup-domains { display: flex; flex-direction: column; gap: 4px; padding: 0 2px 10px; }
.rollup-domain-row {
  display: flex; align-items: center; justify-content: space-between; gap: 10px;
  padding: 8px 10px; border-radius: 9px; background: rgba(255,255,255,.025); cursor: pointer; transition: .15s;
}
.rollup-domain-row:hover { background: rgba(91,92,240,.08); }
.rd-name { font-family: var(--mono); font-size: 11.5px; color: var(--txt); flex: none; }
.rd-detail { font-size: 11px; color: var(--faint); text-align: right; }
</style>
