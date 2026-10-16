import { describe, it, expect, beforeEach } from 'vitest'
import { mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { nextTick } from 'vue'
import AppModal from '@/components/layout/AppModal.vue'
import { useUiStore } from '@/stores/ui'

const Body = { template: '<div><button id="a">A</button><button id="b">B</button></div>' }

function mountModal() {
  const pinia = createPinia()
  setActivePinia(pinia)
  const wrapper = mount(AppModal, { global: { plugins: [pinia] }, attachTo: document.body })
  return { wrapper, ui: useUiStore() }
}

describe('AppModal', () => {
  beforeEach(() => { document.body.innerHTML = '' })

  it('renders nothing while closed, so there is no hidden content to read', () => {
    mountModal()
    expect(document.querySelector('[role="dialog"]')).toBeNull()
  })

  it('opens as a labelled modal dialog with a named close button', async () => {
    const { ui } = mountModal()
    ui.openModal('Review record', { component: Body, props: {} })
    await nextTick()
    const d = document.querySelector('[role="dialog"]')!
    expect(d.getAttribute('aria-modal')).toBe('true')
    expect(d.getAttribute('aria-label')).toBe('Review record')
    expect(d.querySelector('button[aria-label="Close dialog"]')).not.toBeNull()
  })

  it('moves focus into the dialog and gives it back on close', async () => {
    const opener = document.createElement('button')
    document.body.appendChild(opener)
    const { ui } = mountModal()
    opener.focus()
    ui.openModal('T', { component: Body, props: {} })
    await nextTick(); await nextTick()
    const d = document.querySelector('[role="dialog"]') as HTMLElement
    expect(document.activeElement).toBe(d)
    ui.closeModal()
    await nextTick(); await nextTick()
    expect(document.activeElement).toBe(opener)
  })

  it('closes on Escape', async () => {
    const { ui } = mountModal()
    ui.openModal('T', { component: Body, props: {} })
    await nextTick()
    document.querySelector('[role="dialog"]')!.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }))
    await nextTick()
    expect(ui.modalOpen).toBe(false)
  })

  it('keeps Tab inside the dialog', async () => {
    const { ui } = mountModal()
    ui.openModal('T', { component: Body, props: {} })
    await nextTick(); await nextTick()
    const d = document.querySelector('[role="dialog"]') as HTMLElement
    const close = d.querySelector('button[aria-label="Close dialog"]') as HTMLElement
    const last = d.querySelector('#b') as HTMLElement
    last.focus()
    d.dispatchEvent(new KeyboardEvent('keydown', { key: 'Tab', bubbles: true, cancelable: true }))
    expect(document.activeElement).toBe(close)
  })
})
