<script setup lang="ts">
defineProps<{ steps: string[]; current: number }>()
</script>

<template>
  <div class="steps">
    <div v-for="(s, i) in steps" :key="s"
      :class="['step', i < current ? 'done' : i === current ? 'now' : 'lock']">
      <div class="node">
        <svg v-if="i < current" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3">
          <path d="M20 6L9 17l-5-5"/>
        </svg>
        <span v-else-if="i === steps.length - 1">★</span>
        <span v-else>{{ i + 1 }}</span>
      </div>
      <div class="lbl">{{ s }}</div>
    </div>
  </div>
</template>

<style scoped>
.steps { display: flex; align-items: flex-start; }
.step { flex: 1; text-align: center; position: relative; }
.node {
  width: 34px; height: 34px; border-radius: 50%; margin: 0 auto 9px;
  display: grid; place-items: center; border: 2px solid var(--line2);
  background: #0c0c18; position: relative; z-index: 2;
  font-family: var(--disp); font-weight: 700; font-size: 12px; color: var(--faint);
}
.node svg { width: 15px; height: 15px; }
.step.done .node { background: linear-gradient(135deg,#34e0a1,#2ee6c5); border-color: transparent; color: #04201b; }
.step.now  .node { background: linear-gradient(135deg,#5b5cf0,#4b4ce0); border-color: transparent; color: #fff; box-shadow: 0 0 18px rgba(91,92,240,.6); }
.lbl { font-size: 11.5px; font-weight: 600; }
.step.lock .lbl { color: var(--muted); }
.step::before { content:""; position:absolute; top:16px; left:-50%; width:100%; height:3px; background:var(--line2); z-index:1; }
.step:first-child::before { display: none; }
.step.done::before { background: #34e0a1; }
.step.now::before  { background: linear-gradient(90deg, #34e0a1, #5b5cf0); }
</style>
