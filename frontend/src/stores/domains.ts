import { defineStore } from 'pinia'
import { ref } from 'vue'
import { api } from '@/api/client'

export const useDomainsStore = defineStore('domains', () => {
  const list = ref<any[]>([])
  const loading = ref(false)
  // Set when the last fetch failed. Callers check it, so a failed request is
  // shown as an error instead of rejecting past every page's own loader.
  const error = ref('')

  async function fetch() {
    loading.value = true
    error.value = ''
    try {
      list.value = await api.domains()
    } catch (e: any) {
      error.value = e?.message || 'Could not load your domains.'
    } finally { loading.value = false }
  }

  return { list, loading, error, fetch }
})
