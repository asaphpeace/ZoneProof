import { computed, type Ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'

// The open candidate lives in the URL (?c=<id>) so a candidate can be linked to, and Back closes the drawer.
// `list` is whatever the page is showing right now; previous/next walk through it.
export function useCandidateDrawer(list: Ref<any[]>) {
  const route = useRoute()
  const router = useRouter()

  const openId = computed(() => (typeof route.query.c === 'string' ? route.query.c : ''))
  const index = computed(() => list.value.findIndex(c => c.id === openId.value))
  const prevId = computed(() => (index.value > 0 ? list.value[index.value - 1].id : null))
  const nextId = computed(() => (index.value >= 0 && index.value < list.value.length - 1 ? list.value[index.value + 1].id : null))
  const position = computed(() => (index.value >= 0 ? `${index.value + 1} of ${list.value.length}` : ''))

  function open(id: string) { router.push({ query: { ...route.query, c: id } }) }
  function go(id: string) { router.replace({ query: { ...route.query, c: id } }) }
  function close() {
    const { c: _c, ...rest } = route.query
    router.push({ query: rest })
  }

  return { openId, prevId, nextId, position, open, go, close }
}
