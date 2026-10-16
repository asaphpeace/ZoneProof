<script setup lang="ts">
import { computed } from 'vue'
import { fmtShort } from './brandLabels'

// One node of the proof behind a verdict (recursive). Facts are the leaves: a stored value with its source and time.
defineOptions({ name: 'DerivationNode' })
const props = defineProps<{ node: any; depth?: number }>()
const depth = computed(() => props.depth ?? 0)
const BASIS_TEXT: Record<string, string> = { measured: 'measured', expert: 'assumed', 'name rules': 'name rules', 'no weight': 'context' }
const open = computed(() => depth.value < 2)
</script>

<template>
  <li class="dn" :class="[node.kind, node.direction]">
    <template v-if="node.kind === 'fact'">
      <span class="fact">{{ node.text }}</span>
      <span class="src">{{ node.source }}<template v-if="node.at"> · {{ fmtShort(node.at) }}</template></span>
    </template>
    <details v-else :open="open">
      <summary>
        <span class="t">{{ node.text }}</span>
        <span v-if="node.kind === 'signal'" class="chips">
          <span class="chip" :class="node.direction">{{ node.direction === 'for' ? 'for' : node.direction === 'against' ? 'against' : 'no weight' }}</span>
          <span class="chip basis" :class="node.basis">{{ BASIS_TEXT[node.basis] ?? node.basis }}</span>
          <span v-if="node.weight" class="w">{{ node.weight > 0 ? '+' : '' }}{{ Math.round(node.weight * 10) / 10 }}</span>
        </span>
      </summary>
      <p v-if="node.rule" class="rule"><b>Rule {{ node.rule.id }}:</b> {{ node.rule.text }}</p>
      <p v-if="node.note" class="note">{{ node.note }}</p>
      <ul v-if="node.children?.length">
        <DerivationNode v-for="c in node.children" :key="c.id" :node="c" :depth="depth + 1" />
      </ul>
    </details>
  </li>
</template>

<style scoped>
.dn { list-style: none; margin: 0; padding: 0; font-size: 13px; line-height: 1.5; }
ul { margin: 4px 0 0 14px; padding: 0 0 0 12px; border-left: 1px solid var(--line); display: flex; flex-direction: column; gap: 6px; }
summary { cursor: pointer; display: flex; gap: 8px; align-items: baseline; flex-wrap: wrap; padding: 2px 0; }
summary::marker { color: var(--faint); }
.t { color: var(--txt); }
.verdict > details > summary .t { font-weight: 700; font-size: 14px; }
.family > details > summary .t, .resemblance > details > summary .t, .abuse > details > summary .t { font-weight: 600; }
.chips { display: inline-flex; gap: 5px; align-items: center; }
.chip { font-family: var(--mono); font-size: 10px; padding: 1px 7px; border-radius: 8px; background: rgba(255,255,255,.06); color: var(--muted); }
.chip.for { background: rgba(255,77,109,.16); color: #ff8da1; }
.chip.against { background: rgba(52,224,161,.12); color: var(--good); }
.chip.basis.expert { background: rgba(245,197,66,.14); color: #f7d27a; }
.chip.basis.measured { background: rgba(91,92,240,.2); color: #b9c0ff; }
.w { font-family: var(--mono); font-size: 11px; color: var(--muted); }
.rule { margin: 4px 0 4px 14px; padding: 8px 10px; border-radius: 8px; background: rgba(255,255,255,.04); color: var(--muted); font-size: 12.5px; }
.rule b { color: var(--txt); }
.note { margin: 2px 0 2px 14px; color: var(--faint); font-size: 12px; }
.fact { color: #c9cee3; }
.src { display: block; font-family: var(--mono); font-size: 10.5px; color: var(--faint); }
.unknown > details > summary .t { color: var(--muted); }
.decision { color: #b9c0ff; }
</style>
