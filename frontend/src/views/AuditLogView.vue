<script setup lang="ts">
import { ref, watch, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { api } from '@/api/client'
import DateRangeFilter from '@/components/ui/DateRangeFilter.vue'

const router = useRouter()

const entries     = ref<any[]>([])
const loading     = ref(false)
const offset      = ref(0)
const totalCount   = ref(0)
const days         = ref(30)
const upgradeInfo  = ref<{ message: string; current_plan: string } | null>(null)
const loadError    = ref<string | null>(null)

const PAGE_SIZE = 50

onMounted(load)
watch(days, () => { offset.value = 0; load() })

async function load(append = false) {
  loading.value = true
  upgradeInfo.value = null
  loadError.value = null
  try {
    const [rows, countRes] = await Promise.all([
      api.auditLog(PAGE_SIZE, append ? offset.value : 0, days.value),
      api.auditLogCount(days.value),
    ])
    entries.value = append ? [...entries.value, ...rows] : rows
    totalCount.value = countRes.count ?? 0
  } catch (e: any) {
    try {
      const parsed = JSON.parse(e.message)
      if (parsed.code === 'feature_not_available') {
        upgradeInfo.value = { message: parsed.message, current_plan: parsed.current_plan }
      } else {
        loadError.value = parsed.message || e.message
      }
    } catch {
      loadError.value = e.message
    }
  } finally {
    loading.value = false
  }
}

async function loadMore() {
  offset.value += PAGE_SIZE
  await load(true)
}

const hasMore = () => entries.value.length < totalCount.value

function actionLabel(action: string): string {
  return action.replace(/[._]/g, ' ')
}

function formatTime(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
  })
}
</script>

<template>
  <div>
    <div class="titlerow">
      <div>
        <div class="crumb">12 / Audit Log</div>
        <h1>Audit Log</h1>
        <div class="sub">Who changed what, and when — every security and admin-relevant action in this workspace</div>
      </div>
    </div>

    <div style="margin-bottom:16px">
      <DateRangeFilter v-model="days" />
    </div>

    <!-- Upgrade prompt — feature not on current plan -->
    <div v-if="upgradeInfo" class="upgrade-card">
      <div class="uc-icon">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
        </svg>
      </div>
      <div class="uc-body">
        <div class="uc-title">Audit Log is an Enterprise feature</div>
        <div class="uc-text">{{ upgradeInfo.message }}</div>
      </div>
      <button class="uc-btn" @click="router.push({ name: 'billing' })">View plans</button>
    </div>

    <!-- Generic error -->
    <div v-else-if="loadError" class="error-state">{{ loadError }}</div>

    <!-- Empty state -->
    <div v-else-if="!loading && entries.length === 0" class="empty-state">
      No audit events yet. Actions like team changes, invites, domain changes, and plan changes will appear here.
    </div>

    <!-- Log table -->
    <div v-else class="log-card">
      <div class="log-row log-head">
        <span>Time</span>
        <span>Actor</span>
        <span>Action</span>
        <span>Target</span>
      </div>
      <div v-for="e in entries" :key="e.id" class="log-row">
        <span class="log-time">{{ formatTime(e.created_at) }}</span>
        <span class="log-actor">{{ e.actor_email || 'system' }}</span>
        <span class="log-action">{{ actionLabel(e.action) }}</span>
        <span class="log-target">{{ e.target_label || '—' }}</span>
      </div>

      <div v-if="hasMore()" class="load-more-row">
        <button class="load-more-btn" :disabled="loading" @click="loadMore">
          {{ loading ? 'Loading…' : `Load more (${entries.length} of ${totalCount})` }}
        </button>
      </div>
    </div>

    <div v-if="loading && entries.length === 0" class="loading-state">Loading audit log…</div>
  </div>
</template>

<style scoped>
.titlerow { margin-bottom: 20px; }
.crumb { font-family: var(--mono); font-size: 10px; color: var(--faint); letter-spacing: 1.4px; text-transform: uppercase; }
h1 { font-family: var(--disp); font-weight: 800; font-size: 25px; letter-spacing: -.7px; margin-top: 5px; }
.sub { color: var(--muted); margin-top: 5px; font-size: 13px; }

/* Upgrade card */
.upgrade-card {
  display: flex; align-items: center; gap: 16px;
  background: linear-gradient(160deg, rgba(91,92,240,.1), rgba(255,255,255,.02));
  border: 1px solid rgba(91,92,240,.25); border-radius: 16px; padding: 20px 22px;
}
.uc-icon {
  width: 44px; height: 44px; border-radius: 12px; flex: none; display: grid; place-items: center;
  background: rgba(91,92,240,.15); color: var(--indigo);
}
.uc-icon svg { width: 22px; height: 22px; }
.uc-body { flex: 1; }
.uc-title { font-family: var(--disp); font-weight: 700; font-size: 14.5px; margin-bottom: 4px; }
.uc-text { font-size: 12.5px; color: var(--muted); line-height: 1.55; }
.uc-btn {
  background: linear-gradient(90deg, #5b5cf0, #4b4ce0); color: #fff; border: none;
  border-radius: 11px; padding: 10px 18px; font-family: var(--disp); font-weight: 700;
  font-size: 12.5px; cursor: pointer; flex: none;
}

.error-state, .empty-state, .loading-state {
  padding: 40px; text-align: center; color: var(--muted); font-size: 13px;
  background: var(--glass); border: 1px solid var(--line); border-radius: 16px;
}

/* Log table */
.log-card { background: var(--glass); border: 1px solid var(--line); border-radius: 16px; overflow: hidden; }
.log-row {
  display: grid; grid-template-columns: 160px 220px 200px 1fr; gap: 12px;
  padding: 12px 18px; border-bottom: 1px solid rgba(255,255,255,.04); font-size: 12.5px;
  align-items: center;
}
.log-row:last-child { border-bottom: none; }
.log-head {
  font-family: var(--mono); font-size: 9.5px; letter-spacing: 1px; text-transform: uppercase;
  color: var(--faint); background: rgba(255,255,255,.02);
}
.log-time { font-family: var(--mono); font-size: 11.5px; color: var(--faint); }
.log-actor { color: var(--muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.log-action { color: var(--txt); font-weight: 600; text-transform: capitalize; }
.log-target { color: var(--muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

.load-more-row { display: flex; justify-content: center; padding: 14px; }
.load-more-btn {
  background: rgba(255,255,255,.05); border: 1px solid var(--line2); color: var(--muted);
  border-radius: 10px; padding: 8px 16px; font-family: var(--mono); font-size: 11.5px; cursor: pointer;
}
.load-more-btn:hover { color: var(--txt); border-color: var(--indigo); }
.load-more-btn:disabled { opacity: .5; cursor: not-allowed; }

@media (max-width: 760px) {
  .log-row { grid-template-columns: 1fr; gap: 4px; }
  .log-head { display: none; }
  .log-row:not(.log-head) { padding: 12px 14px; }
}
</style>
