import { defineStore } from 'pinia'
import { ref } from 'vue'

// One working scope for every page that analyses a domain. null means "all
// domains". Each analysis page used to keep its own selector, so changing
// domain on one page was forgotten on the next. The value is a domain name,
// the same key those pages already used, and it is remembered per browser.
//
// Client scope (an MSP switching between its clients) is not here on purpose:
// the domain APIs are scoped to one workspace, so a client switch needs
// client-aware endpoints first.

const KEY = 'zp_scope_domain'

function read(): string | null {
  try { return localStorage.getItem(KEY) || null } catch { return null }
}
function write(v: string | null) {
  try { v ? localStorage.setItem(KEY, v) : localStorage.removeItem(KEY) } catch { /* not remembered */ }
}

// Routes that analyse a domain and follow the shared scope. The selector in the
// top bar is only shown on these.
export const SCOPED_ROUTES = ['dmarc', 'tls', 'posture', 'roadmap', 'certs', 'timeline']

export const useScopeStore = defineStore('scope', () => {
  const domain = ref<string | null>(read())

  function set(value: string | null) {
    domain.value = value || null
    write(domain.value)
  }

  // Drop a remembered domain that no longer exists, so a deleted domain cannot
  // leave every page filtered to nothing.
  function reconcile(names: string[]) {
    if (domain.value && names.length && !names.includes(domain.value)) set(null)
  }

  return { domain, set, reconcile }
})
