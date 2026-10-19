<script setup lang="ts">
import { ref, watch } from 'vue'
import { useUiStore } from '@/stores/ui'
import { api } from '@/api/client'

const ui = useUiStore()
const alerts = ref<any[]>([])

watch(() => ui.alertMenuOpen, async (open) => {
  if (open) alerts.value = await api.alerts()
})

const severityColor = (s: string) => ({ critical: 'var(--bad)', warn: 'var(--warn)', info: 'var(--good)' }[s] || 'var(--muted)')
</script>

<template>
  <Teleport to="body">
    <div v-if="ui.alertMenuOpen" class="backdrop-thin" aria-hidden="true" @click="ui.closeAlertMenu()" />
    <div v-show="ui.alertMenuOpen" class="alertmenu">
      <div class="amhead">
        Alerts
        <span class="sectag">✦ AI-narrated</span>
      </div>
      <div v-if="!alerts.length" style="padding:16px;color:var(--muted);font-size:12.5px">No alerts</div>
      <div v-for="a in alerts" :key="a.id" class="alert" @click="api.markAlertRead(a.id)" tabindex="0" role="button" @keydown.enter.prevent="api.markAlertRead(a.id)" @keydown.space.prevent="api.markAlertRead(a.id)">
        <span class="ad" :style="`background:${severityColor(a.severity)}`" />
        <div>
          <div class="at">{{ a.title }}</div>
          <div class="ab">{{ a.body }}</div>
          <div v-if="a.action" class="aa"><span class="aa-label">What to do</span>{{ a.action }}</div>
          <div class="aw">✦ {{ a.category }} · {{ new Date(a.created_at).toLocaleTimeString() }}</div>
        </div>
      </div>
    </div>
  </Teleport>
</template>

<style scoped>
.backdrop-thin { position: fixed; inset: 0; z-index: 71; }
.alertmenu {
  position: fixed; top: 64px; right: 118px; width: 350px; max-width: 92vw;
  background: linear-gradient(160deg, var(--surface-raised), var(--bg));
  border: 1px solid var(--line2); border-radius: 16px; z-index: 72;
  padding: 14px; box-shadow: 0 20px 50px rgba(0,0,0,.55);
}
.amhead { font-family: var(--disp); font-weight: 700; font-size: 14px; display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
.sectag { font-family: var(--mono); font-size: 9px; letter-spacing: 1px; text-transform: uppercase; color: var(--teal); }
.alert { display: flex; gap: 11px; padding: 11px 8px; border-radius: 11px; cursor: pointer; }
.alert:hover { background: rgba(255,255,255,.04); }
.ad { width: 8px; height: 8px; border-radius: 50%; margin-top: 5px; flex: none; }
.at { font-size: 12.5px; font-weight: 600; }
.ab { font-size: 11.5px; color: var(--muted); margin-top: 3px; line-height: 1.45; }
.aa { font-size: 11px; color: #9aa6ff; margin-top: 6px; line-height: 1.5; padding-top: 6px; border-top: 1px solid var(--line); }
.aa-label { display: block; font-family: var(--mono); font-size: 8.5px; letter-spacing: .6px; text-transform: uppercase; color: var(--faint); margin-bottom: 2px; }
.aw { font-family: var(--mono); font-size: 9px; color: var(--teal); margin-top: 5px; }
</style>
