<script setup lang="ts">
// A finding is not a dead end. This is the one link style for "go to the
// evidence" or "go to the fix", so every page points onward the same way and
// carries the domain with it (the shared scope picks it up from ?domain=).
defineProps<{
  to: string               // route name
  label: string
  domain?: string | null
  title?: string
}>()
</script>

<template>
  <RouterLink
    class="next-step"
    :to="{ name: to, query: domain ? { domain } : {} }"
    :title="title"
    @click.stop
  >{{ label }} <span aria-hidden="true">→</span></RouterLink>
</template>

<style scoped>
.next-step {
  display: inline-flex; align-items: center; gap: 4px;
  font-size: 12px; font-weight: 600; color: var(--indigo, #9aa6ff);
  text-decoration: none; white-space: nowrap;
}
.next-step:hover { text-decoration: underline; }
</style>
