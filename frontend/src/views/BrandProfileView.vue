<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { api } from '@/api/client'
import { useBrandGuardStore } from '@/stores/brandGuard'
import { useUiStore } from '@/stores/ui'
import BrandFrame from '@/components/brand/BrandFrame.vue'
import BrandHeader from '@/components/brand/BrandHeader.vue'
import SourceStrip from '@/components/brand/SourceStrip.vue'
import { fmtDate } from '@/components/brand/brandLabels'

// What Brand Guard compares everything against, and a plain statement of what it does and does not watch.
// Edits are held locally until "Save and rescan", so nothing changes (or rescans) half-way through typing.
const store = useBrandGuardStore()
const ui = useUiStore()
const profile = computed(() => store.profile)

const brandName = ref('')
const keywords = ref<string[]>([])
const official = ref<string[]>([])
const marks = ref<{ mark: string; number: string; jurisdiction: string }[]>([])
const newKeyword = ref('')
const newOfficial = ref('')
const saving = ref(false)
const fpBusy = ref(false)

function reset() {
  const p = profile.value
  if (!p) return
  brandName.value = p.brand_name
  keywords.value = [...(p.keywords || [])]
  official.value = [...(p.official_domains || [])]
  marks.value = (p.trademarks ?? []).map((m: any) => ({ ...m }))
}
watch(profile, reset, { immediate: true })

const dirty = computed(() => {
  const p = profile.value
  if (!p) return false
  const cleanMarks = marks.value.filter(m => m.mark.trim())
  return brandName.value.trim() !== p.brand_name
    || JSON.stringify(keywords.value) !== JSON.stringify(p.keywords || [])
    || JSON.stringify(official.value) !== JSON.stringify(p.official_domains || [])
    || JSON.stringify(cleanMarks) !== JSON.stringify(p.trademarks || [])
})

function addTo(list: string[], raw: string): string[] {
  const parts = raw.split(/[,\s]+/).map(s => s.trim().toLowerCase()).filter(Boolean)
  return [...new Set([...list, ...parts])]
}
function addKeyword() { keywords.value = addTo(keywords.value, newKeyword.value); newKeyword.value = '' }
function addOfficial() { official.value = addTo(official.value, newOfficial.value); newOfficial.value = '' }
const suggestions = computed(() => (profile.value?.suggested_official_domains || []).filter((d: string) => !official.value.includes(d)))

async function save() {
  if (!profile.value) return
  saving.value = true
  try {
    const updated = await api.brandUpdateProfile(profile.value.id, {
      brand_name: brandName.value.trim(), keywords: keywords.value, official_domains: official.value,
      trademarks: marks.value.filter(m => m.mark.trim()),
    })
    store.applyProfile(updated)
    ui.toast('Saved. Rescanning with the new profile…')
    await store.scan()
  } catch (e: any) {
    ui.toast(e.message || 'Could not save the profile', 'error')
  } finally { saving.value = false }
}

async function rebuild() {
  if (!profile.value) return
  fpBusy.value = true
  try { store.applyProfile(await api.brandFingerprint(profile.value.id)) }
  catch (e: any) { ui.toast(e.message || 'Could not build the brand fingerprint', 'error') }
  finally { fpBusy.value = false }
}

const fp = computed(() => profile.value?.fingerprint ?? null)
const fpSite = computed(() => fp.value?.site ?? null)
const fpDns = computed(() => fp.value?.dns ?? null)

// The customer's own page as the isolated browser saw it (kept until replaced). Loaded as an image only; nothing from it is ever run.
const pageShot = ref<string | null>(null)
const pageShotLoaded = ref(false)
function dropShot() { if (pageShot.value) URL.revokeObjectURL(pageShot.value); pageShot.value = null }
watch(() => profile.value?.id, async (id) => {
  dropShot(); pageShotLoaded.value = false
  if (!id) return
  try { const url = await api.brandReferenceImage(id); if (profile.value?.id === id) pageShot.value = url; else if (url) URL.revokeObjectURL(url) } catch { /* shown as "no picture yet" */ }
  if (profile.value?.id === id) pageShotLoaded.value = true
}, { immediate: true })
onBeforeUnmount(dropShot)
// Only an https address is ever put in an <img>; anything else (javascript:, data:, http:) is not shown.
const iconUrl = computed(() => { const u = fpSite.value?.favicon?.url; return typeof u === 'string' && /^https:\/\//i.test(u) ? u : null })
const result = computed(() => (profile.value?.latest_run?.status === 'succeeded' ? profile.value.latest_run.result : null) ?? store.run?.result ?? null)

const numbers = computed(() => {
  const r = result.value
  const p = profile.value
  if (!p) return []
  return [
    { v: r?.evaluated ?? '—', l: 'names checked in the last scan' },
    { v: p.ct_enabled ? 'On' : 'Off', l: 'certificate monitoring' },
    { v: store.sources.filter(s => s.source !== 'crt_sh').length || '—', l: 'public feeds used' },
    { v: p.latest_run?.finished_at ? fmtDate(p.latest_run.finished_at) : fmtDate(p.last_scanned_at), l: 'last scan finished' },
  ]
})
const trimmed = computed(() => result.value?.budget?.trimmed ?? 0)
const generated = computed(() => result.value?.budget?.generated ?? 0)

// The live stream is a separate process; the page says what is actually running, not what could be.
const streamOn = computed(() => store.sources.some(s => s.source === 'ct_stream' && s.status !== 'down'))
const WATCH = computed(() => [
  'Name variations of your brand names and keywords (typos, look-alike characters, other endings, added words, fake .co.za)',
  ...(profile.value?.ct_enabled
    ? [streamOn.value ? "New certificates for look-alike names, live: seconds after the Google and Let's Encrypt logs record them" : 'New certificates issued for look-alike names (checked on every scan)', 'A daily sample of newly registered domains']
    : []),
  'DNS, registration age and who registered it, mail setup (SPF, DKIM, DMARC) and hosting',
  'Public abuse lists (phishunt.io and abuse.ch URLhaus) for corroboration',
  'Emails your own team reports, and the senders in your DMARC reports',
])
const UNWATCHED = computed(() => [
  'What is on a web page: logos, colours and login forms are not analysed yet',
  'Social media accounts and posts, mobile app stores, and paid ads',
  'Most new registrations: the free daily list is a sample of about 70,000 names a day, so names that never get a certificate may be missed',
  ...(profile.value?.ct_enabled ? [] : ['New certificates and new registrations (on the Pro plan)']),
  ...(streamOn.value ? ["Certificates recorded only in logs other than Google's and Let's Encrypt's"] : []),
  'Changes to your own site: the brand fingerprint below is rebuilt only when you ask',
])
</script>

<template>
  <BrandFrame>
    <template v-if="profile">
      <BrandHeader title="Brand profile" crumb="Brand profile" no-scan
        sub="What we compare every look-alike against. The more complete this is, the fewer false alarms you will see.">
        <template #actions>
          <button type="button" class="ghost" :disabled="!dirty || saving" @click="reset">Discard</button>
          <button type="button" class="btn" :disabled="!dirty || saving || store.scanning" @click="save">{{ saving ? 'Saving…' : 'Save and rescan' }}</button>
        </template>
      </BrandHeader>

      <div class="grid">
        <div class="col">
          <section class="card" aria-labelledby="bp-n">
            <h2 id="bp-n">Brand name and keywords</h2>
            <p class="hint">We generate look-alike names from these. Keywords are words attackers add, such as login or pay.</p>
            <label for="bp-name">Brand name</label>
            <input id="bp-name" v-model="brandName" class="fld" maxlength="120" />
            <div v-for="w in profile.warnings || []" :key="w" class="warn">{{ w }}</div>
            <span class="lab">Keywords</span>
            <div class="toks">
              <span v-for="k in keywords" :key="k" class="tok">{{ k }}<button type="button" :aria-label="`Remove ${k}`" @click="keywords = keywords.filter(x => x !== k)">×</button></span>
              <span v-if="!keywords.length" class="muted">None yet.</span>
            </div>
            <label for="bp-kw">Add keywords</label>
            <input id="bp-kw" v-model="newKeyword" class="fld" placeholder="pay, wallet, portal" @keydown.enter.prevent="addKeyword" @blur="newKeyword && addKeyword()" />
          </section>

          <section class="card" aria-labelledby="bp-o">
            <h2 id="bp-o">Official domains</h2>
            <p class="hint">These are never flagged. <b class="mono">{{ profile.primary_domain }}</b> is your primary domain.</p>
            <div class="toks">
              <span class="tok fixed">{{ profile.primary_domain }}</span>
              <span v-for="d in official" :key="d" class="tok">{{ d }}<button type="button" :aria-label="`Remove ${d}`" @click="official = official.filter(x => x !== d)">×</button></span>
            </div>
            <div v-if="suggestions.length" class="sugg">
              <span class="muted">Other domains in your workspace. Are these yours?</span>
              <button v-for="d in suggestions" :key="d" type="button" class="mini" @click="official = [...official, d]">+ {{ d }}</button>
            </div>
            <label for="bp-od">Add a domain</label>
            <input id="bp-od" v-model="newOfficial" class="fld" placeholder="acmefin.co.za" @keydown.enter.prevent="addOfficial" @blur="newOfficial && addOfficial()" />
          </section>

          <section class="card" aria-labelledby="bp-f">
            <div class="ch"><h2 id="bp-f">Brand fingerprint</h2>
              <button type="button" class="mini" :disabled="fpBusy" @click="rebuild">{{ fpBusy ? 'Reading your site…' : fp ? 'Rebuild' : 'Build fingerprint' }}</button></div>
            <p class="hint">{{ fp ? `Built ${fmtDate(profile.fingerprint_built_at)}.` : 'Not built yet.' }} We read your public website and DNS to learn what the real brand looks like. A look-alike on your own nameservers or server is flagged as probably yours.</p>
            <div v-for="e in fp?.errors || []" :key="e" class="warn">{{ e }}</div>
            <div v-if="fp" class="fpg">
              <div>
                <h3>Website</h3>
                <template v-if="fpSite">
                  <div class="kv"><span>Title</span><b>{{ fpSite.title || '—' }}</b></div>
                  <div v-if="fpSite.description" class="kv"><span>Description</span><b>{{ fpSite.description }}</b></div>
                  <div class="kv"><span>Favicon</span><b class="mono"><img v-if="iconUrl" :src="iconUrl" class="icon" alt="Your site's icon" referrerpolicy="no-referrer" loading="lazy" />{{ fpSite.favicon ? fpSite.favicon.sha256.slice(0, 16) + '…' : 'not found' }}</b></div>
                  <div v-if="fpSite.social?.length" class="kv"><span>Social profiles</span><b>{{ fpSite.social.map((s: any) => s.network).join(', ') }}</b></div>
                  <div v-if="fpSite.emails?.length" class="kv"><span>Contact emails</span><b class="mono">{{ fpSite.emails.join(', ') }}</b></div>
                  <div v-if="fpSite.phones?.length" class="kv"><span>Phone numbers</span><b class="mono">{{ fpSite.phones.join(', ') }}</b></div>
                </template>
                <p v-else class="muted">Your website could not be read, so only the DNS baseline is available.</p>
              </div>
              <div v-if="fpDns">
                <h3>Infrastructure baseline</h3>
                <div class="kv"><span>Nameservers</span><b class="mono">{{ fpDns.ns.join(', ') || '—' }}</b></div>
                <div class="kv"><span>Server address</span><b class="mono">{{ fpDns.a.join(', ') || '—' }}</b></div>
                <div class="kv"><span>Hosting network</span><b>{{ fpDns.asn?.name || '—' }}<template v-if="fpDns.shared_hosting"> (shared platform)</template></b></div>
                <div class="kv"><span>Mail provider</span><b>{{ fpDns.mail_provider || (fpDns.mx.length ? fpDns.mx[0] : '—') }}</b></div>
                <p v-if="fpDns.shared_hosting" class="muted">Your site is on a shared platform, so sharing a server address with it proves nothing and is ignored.</p>
              </div>
            </div>
            <div v-if="fp" class="look">
              <h3>How your page looks</h3>
              <img v-if="pageShot" :src="pageShot" class="pageshot" alt="Your own home page, taken in an isolated browser" />
              <p v-else-if="pageShotLoaded" class="muted">No picture yet. The isolated browser takes one of your page on the next scan, once the browser worker is switched on. Look-alike pages are compared with this picture.</p>
            </div>
          </section>

          <section class="card" aria-labelledby="bp-t">
            <div class="ch"><h2 id="bp-t">Trademarks</h2>
              <button type="button" class="mini" :disabled="marks.length >= 20" @click="marks.push({ mark: '', number: '', jurisdiction: '' })">+ Add trademark</button></div>
            <p class="hint">Kept as evidence for takedown and domain-dispute requests. They do not affect detection.</p>
            <div v-for="(m, i) in marks" :key="i" class="mk">
              <input v-model="m.mark" class="fld" placeholder="Mark (e.g. ACME)" maxlength="120" :aria-label="`Trademark ${i + 1} name`" />
              <input v-model="m.number" class="fld" placeholder="Registration number" maxlength="40" :aria-label="`Trademark ${i + 1} number`" />
              <input v-model="m.jurisdiction" class="fld" placeholder="Jurisdiction (e.g. ZA)" maxlength="40" :aria-label="`Trademark ${i + 1} jurisdiction`" />
              <button type="button" class="mini" :aria-label="`Remove trademark ${i + 1}`" @click="marks.splice(i, 1)">Remove</button>
            </div>
            <p v-if="!marks.length" class="muted">None added.</p>
          </section>
        </div>

        <aside class="mon" aria-labelledby="bp-w">
          <h2 id="bp-w">What we monitor</h2>
          <p class="hint">A plain statement of coverage, so nobody assumes we are watching something we are not.</p>
          <div class="nums"><div v-for="n in numbers" :key="n.l" class="num"><b>{{ n.v }}</b><span>{{ n.l }}</span></div></div>
          <p v-if="trimmed > 0" class="warn">Your plan checks {{ generated - trimmed }} of the {{ generated }} look-alike names we generate. The most likely ones come first.</p>
          <div class="wl"><h3 class="g">We watch</h3>
            <div v-for="y in WATCH" :key="y" class="li"><svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="var(--good)" stroke-width="2.4" stroke-linecap="round" aria-hidden="true"><path d="M5 12l5 5 9-10" /></svg><span>{{ y }}</span></div></div>
          <div class="wl no"><h3>We do not watch</h3>
            <div v-for="n in UNWATCHED" :key="n" class="li"><svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="var(--faint)" stroke-width="2.2" stroke-linecap="round" aria-hidden="true"><path d="M6 12h12" /></svg><span>{{ n }}</span></div></div>
          <SourceStrip :sources="store.sources" />
        </aside>
      </div>
    </template>
  </BrandFrame>
</template>

<style scoped>
.grid { display: grid; grid-template-columns: minmax(0, 1.4fr) minmax(0, 1fr); gap: 20px; align-items: start; }
.col { display: flex; flex-direction: column; gap: 18px; }
.card { background: var(--glass); border: 1px solid var(--line); border-radius: 16px; padding: 20px 22px; display: flex; flex-direction: column; gap: 10px; }
h2 { margin: 0; font-family: var(--disp); font-size: 16px; font-weight: 700; }
h3 { margin: 4px 0 6px; font-family: var(--mono); font-size: 10.5px; letter-spacing: .1em; text-transform: uppercase; color: var(--muted); }
.ch { display: flex; justify-content: space-between; align-items: center; gap: 10px; }
.hint { margin: 0; font-size: 12.5px; color: var(--muted); line-height: 1.5; }
label, .lab { font-size: 12.5px; font-weight: 600; color: #c9cee3; margin-top: 4px; }
.fld { width: 100%; box-sizing: border-box; min-height: 40px; padding: 8px 12px; border-radius: 10px; background: rgba(255,255,255,.04); border: 1px solid var(--line2); color: var(--txt); font: 500 13.5px var(--body); }
.toks, .sugg { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
.tok { display: inline-flex; align-items: center; gap: 6px; min-height: 30px; padding: 0 6px 0 12px; border-radius: 8px; background: rgba(255,255,255,.06); border: 1px solid var(--line2); font-size: 13px; }
.tok.fixed { padding-right: 12px; font-family: var(--mono); }
.tok button { width: 24px; height: 24px; border: 0; border-radius: 6px; background: transparent; color: var(--muted); cursor: pointer; font-size: 15px; }
.tok button:hover { background: rgba(255,255,255,.1); color: #fff; }
.muted { color: var(--muted); font-size: 12.5px; margin: 0; }
.warn { background: rgba(245,197,66,.08); border: 1px solid rgba(245,197,66,.25); color: var(--warn); border-radius: 10px; padding: 8px 12px; font-size: 12.5px; margin: 0; }
.mini { min-height: 32px; padding: 0 12px; border-radius: 9px; border: 1px solid var(--line2); background: rgba(255,255,255,.03); color: var(--txt); font: 600 12px var(--body); cursor: pointer; }
.mini:hover:not(:disabled) { border-color: var(--indigo); }
.mini:disabled { opacity: .5; cursor: default; }
.btn { min-height: 40px; background: linear-gradient(90deg, #5b5cf0, #4b4ce0); color: #fff; border: 0; border-radius: 10px; padding: 0 18px; font-family: var(--mono); font-size: 12px; cursor: pointer; }
.ghost { min-height: 40px; padding: 0 16px; border-radius: 10px; border: 1px solid var(--line2); background: transparent; color: var(--txt); font: 600 13px var(--body); cursor: pointer; }
.btn:disabled, .ghost:disabled { opacity: .45; cursor: default; }
.fpg { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 18px; }
.kv { display: grid; grid-template-columns: 110px 1fr; gap: 8px; font-size: 12.5px; margin-bottom: 6px; }
.icon { width: 20px; height: 20px; object-fit: contain; vertical-align: middle; margin-right: 8px; border-radius: 3px; background: #fff; }
.look { margin-top: 18px; }
.pageshot { display: block; width: 100%; max-width: 720px; height: auto; border: 1px solid var(--line, #d9dde5); border-radius: 8px; }
.kv span { color: var(--muted); }
.kv b { font-weight: 500; word-break: break-word; }
.mono { font-family: var(--mono); }
.mk { display: grid; grid-template-columns: 1.4fr 1.2fr 1fr auto; gap: 8px; align-items: center; }
.mon { background: rgba(13,18,32,.7); border: 1px solid rgba(91,92,240,.3); border-radius: 16px; padding: 22px; display: flex; flex-direction: column; gap: 16px; position: sticky; top: 14px; }
.nums { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; }
.num { padding: 12px; border-radius: 10px; background: rgba(255,255,255,.04); display: flex; flex-direction: column; gap: 3px; min-width: 0; }
.num b { font-family: var(--disp); font-size: 17px; font-weight: 800; overflow-wrap: anywhere; }
.num span { font-size: 12px; color: var(--muted); }
.wl { display: flex; flex-direction: column; gap: 10px; }
.wl .g { color: var(--good); }
.wl.no { padding-top: 14px; border-top: 1px solid var(--line); }
.li { display: flex; gap: 10px; align-items: flex-start; font-size: 13px; line-height: 1.5; }
.li svg { flex: none; margin-top: 2px; }
.wl.no .li { color: var(--muted); }
@media (max-width: 1000px) { .grid { grid-template-columns: 1fr; } .mon { position: static; } }
@media (max-width: 640px) { .mk { grid-template-columns: 1fr; } .kv { grid-template-columns: 1fr; } }
</style>
