<script setup lang="ts">
import { computed } from 'vue'

// Members on the left, the infrastructure that links them on the right, a line wherever a member uses it. Line weight = how strong the
// link is (shared by few = strong, shared by many = weak). Known-bad members are marked, so "one hit surfaces its cluster" is visible.
const props = defineProps<{ graph: any; seeds?: string[]; guilt?: Record<string, number> }>()
const ROW = 34
const W = 640
const members = computed<string[]>(() => props.graph?.domains ?? [])
const shared = computed<any[]>(() => props.graph?.shared ?? [])
const height = computed(() => Math.max(members.value.length, shared.value.length) * ROW + 24)
const my = (i: number) => 18 + i * ROW
const sy = (i: number) => 18 + i * ROW * (members.value.length / Math.max(shared.value.length, 1))
const mi = computed(() => Object.fromEntries(members.value.map((d, i) => [d, i])))
const si = computed(() => Object.fromEntries(shared.value.map((s, i) => [s.id, i])))
const KIND: Record<string, string> = { certificate: 'Certificate', ip: 'Server address', nameserver: 'Nameservers', mail_host: 'Mail server', batch: 'Registration batch' }
const colour = (kind: string) => ({ certificate: '#ff8da1', ip: '#f7d27a', nameserver: '#b9c0ff', mail_host: '#8fd3ff', batch: '#9aa3b8' } as Record<string, string>)[kind] ?? '#9aa3b8'
const isSeed = (d: string) => (props.seeds ?? []).includes(d)
</script>

<template>
  <div v-if="members.length && shared.length" class="cg">
    <svg :viewBox="`0 0 ${W} ${height}`" role="img" :aria-label="`${members.length} look-alikes linked by ${shared.length} shared things`">
      <g v-for="l in graph.links" :key="l.domain + l.node">
        <line :x1="215" :y1="my(mi[l.domain])" :x2="W - 225" :y2="sy(si[l.node])" :stroke="colour(shared[si[l.node]].kind)"
          :stroke-width="1 + 3 * shared[si[l.node]].weight" stroke-opacity=".55" />
      </g>
      <g v-for="(d, i) in members" :key="d">
        <circle cx="205" :cy="my(i)" r="5" :fill="isSeed(d) ? '#ff4d6d' : '#8b95ab'" />
        <text x="195" :y="my(i) + 4" text-anchor="end" class="m" :class="{ seed: isSeed(d) }">{{ d }}</text>
        <text v-if="guilt && guilt[d]" x="195" :y="my(i) + 15" text-anchor="end" class="g">suspicion {{ Math.round(guilt[d] * 100) }}%</text>
      </g>
      <g v-for="(s, i) in shared" :key="s.id">
        <rect :x="W - 225" :y="sy(i) - 11" width="220" height="22" rx="6" :fill="colour(s.kind)" fill-opacity=".14" :stroke="colour(s.kind)" stroke-opacity=".5" />
        <text :x="W - 215" :y="sy(i) + 4" class="s">{{ KIND[s.kind] }}: {{ s.label.length > 22 ? s.label.slice(0, 21) + '…' : s.label }}</text>
      </g>
    </svg>
    <p class="note">Thicker lines are stronger links: a thing shared by two look-alikes says more than one shared by dozens. Red dots are look-alikes already known to be bad.</p>
  </div>
</template>

<style scoped>
.cg svg { width: 100%; height: auto; display: block; }
.m { font: 600 11.5px var(--mono); fill: #dde1ea; }
.m.seed { fill: #ff8da1; }
.g { font: 10px var(--mono); fill: #f7d27a; }
.s { font: 11px var(--mono); fill: #dde1ea; }
.note { margin: 6px 0 0; font-size: 12px; color: var(--muted); }
</style>
