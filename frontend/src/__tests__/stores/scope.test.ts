import { describe, it, expect, beforeEach } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'
import { useScopeStore, SCOPED_ROUTES } from '@/stores/scope'

describe('scope store', () => {
  beforeEach(() => {
    localStorage.clear()
    setActivePinia(createPinia())
  })

  it('starts as all domains', () => {
    expect(useScopeStore().domain).toBeNull()
  })

  it('remembers the chosen domain across a new store (a reload)', () => {
    useScopeStore().set('example.com')
    setActivePinia(createPinia())
    expect(useScopeStore().domain).toBe('example.com')
  })

  it('treats an empty value as all domains and forgets it', () => {
    const scope = useScopeStore()
    scope.set('example.com')
    scope.set('')
    expect(scope.domain).toBeNull()
    expect(localStorage.getItem('zp_scope_domain')).toBeNull()
  })

  it('drops a remembered domain that no longer exists', () => {
    const scope = useScopeStore()
    scope.set('gone.example')
    scope.reconcile(['a.example', 'b.example'])
    expect(scope.domain).toBeNull()
  })

  it('keeps a domain that still exists', () => {
    const scope = useScopeStore()
    scope.set('a.example')
    scope.reconcile(['a.example', 'b.example'])
    expect(scope.domain).toBe('a.example')
  })

  it('does not clear the scope when the domain list could not be loaded', () => {
    const scope = useScopeStore()
    scope.set('a.example')
    scope.reconcile([])
    expect(scope.domain).toBe('a.example')
  })

  it('lists the analysis pages that follow the scope', () => {
    expect(SCOPED_ROUTES).toEqual(expect.arrayContaining(['dmarc', 'tls', 'posture', 'roadmap', 'certs', 'timeline']))
  })
})
