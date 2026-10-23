/**
 * The sign-up modal.
 *
 * Two things, in order: a key, then a name. The name is what makes you
 * reachable — claiming it is what publishes the key other people encrypt to.
 */

import { Gateway } from '../../shared/client.js'
import { identity as getIdentity, signer as getSigner } from '../../shared/keysource.js'
import { renderAccountChip } from './session.js'

const el = (id) => document.getElementById(id)
const gateway = new Gateway(location.origin)

let identity = null
let name = null
let ready = false

/**
 * The invitation this visit came from, remembered so that a visitor who wanders
 * off and comes back is still recognised as invited.
 */
const INVITE_KEY = 'pinesign.invite'
const fromUrl = new URLSearchParams(location.search).get('invite')
if (fromUrl) localStorage.setItem(INVITE_KEY, fromUrl)
const inviteId = fromUrl ?? localStorage.getItem(INVITE_KEY)

function status(node, message, kind = '') {
  const n = el(node)
  n.textContent = message
  n.className = `status ${kind}`.trim()
}

function mark(step, state) {
  el(step).className = state
}

export function openModal() {
  el('onboard').hidden = false
  document.body.style.overflow = 'hidden'
  if (!ready) boot()
}

export function closeModal() {
  el('onboard').hidden = true
  document.body.style.overflow = ''
}

// ---- steps ----

function renderKey() {
  el('enc-key').textContent = identity.publicKey
  el('enc-key').hidden = false
  el('key-hint').textContent =
    'Held in this browser. It is what files are encrypted to, and the only thing that can open them.'
  mark('s-key', 'done')
}

function renderName() {
  if (name) {
    el('your-name').textContent = name.name
    el('your-name').hidden = false
    el('claim-form').hidden = true
    el('done-note').hidden = false
    el('invite-banner').hidden = true
    refreshInvites()
    return mark('s-name', 'done')
  }

  el('claim-form').hidden = false
  mark('s-name', identity ? 'todo' : 'blocked')
  status('name-status', '')
}

// ---- invitations ----

function validEmail(v) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)
}

function checkInviteForm() {
  el('inv-send').disabled = !(validEmail(el('inv-to').value.trim()) && validEmail(el('inv-from').value.trim()))
}
el('inv-to').addEventListener('input', checkInviteForm)
el('inv-from').addEventListener('input', checkInviteForm)

el('inv-send').addEventListener('click', async () => {
  el('inv-send').disabled = true
  status('inv-status', 'Sending…')
  try {
    await gateway.invite(await getSigner(), {
      toEmail: el('inv-to').value.trim(),
      fromEmail: el('inv-from').value.trim(),
    })
    status('inv-status', `Invitation sent to ${el('inv-to').value.trim()}. You will get an email when they accept.`, 'done')
    el('inv-to').value = ''
    refreshInvites()
  } catch (err) {
    status('inv-status', err.message, 'error')
    checkInviteForm()
  }
})

async function refreshInvites() {
  try {
    const list = await gateway.myInvites(await getSigner())
    el('inv-list').hidden = list.length === 0
    el('inv-items').innerHTML = list
      .map((i) => {
        const state = i.status === 'accepted'
          ? `accepted as ${i.acceptedBy.name}`
          : i.status
        return `<li><span class="who">${i.toEmail}</span><span class="st ${i.status}">${state}</span></li>`
      })
      .join('')
  } catch {
    // Not fatal; the form still works.
  }
}

async function refreshName() {
  name = identity ? await gateway.reverseName(identity.publicKey) : null
  renderName()
}

// ---- availability ----

let checkTimer = null
let checked = null

el('label').addEventListener('input', () => {
  checked = null
  el('claim').disabled = true
  el('label-check').textContent = ''
  el('label-check').className = 'resolved'

  const label = el('label').value.trim().toLowerCase()
  if (label.length < 3) return

  clearTimeout(checkTimer)
  el('label-check').textContent = 'checking…'
  checkTimer = setTimeout(async () => {
    try {
      const result = await gateway.nameAvailable(label)
      if (result.available) {
        checked = label
        el('label-check').textContent = `${result.name} is free.`
        el('label-check').className = 'resolved ok'
        el('claim').disabled = !identity
      } else {
        el('label-check').textContent = result.reason ?? 'Already taken.'
        el('label-check').className = 'resolved error'
      }
    } catch (err) {
      el('label-check').textContent = err.message
      el('label-check').className = 'resolved error'
    }
  }, 300)
})

el('claim').addEventListener('click', async () => {
  el('claim').disabled = true
  status('name-status', 'Claiming…')
  try {
    name = await gateway.registerName(await getSigner(), checked, inviteId)
    localStorage.removeItem(INVITE_KEY) // used; a later visit is not an acceptance
    status('name-status', '')
    renderName()
    renderAccountChip(openModal)
  } catch (err) {
    status('name-status', err.message, 'error')
    el('claim').disabled = false
  }
})

// ---- boot ----

async function showInvitation() {
  if (!inviteId) return
  try {
    const inv = await gateway.inviteStatus(inviteId)
    if (inv.status !== 'pending') return
    el('invite-from').textContent = inv.fromName
    el('invite-banner').hidden = false
  } catch {
    // An invalid link just gets the ordinary flow.
  }
}

async function boot() {
  ready = true
  showInvitation()

  const health = await gateway.health().catch(() => null)
  if (health?.parentName) el('suffix').textContent = `.${health.parentName}`

  identity = await getIdentity()
  renderKey()

  await refreshName()
}

/**
 * Reopen the modal only when the user was explicitly sent back to it. Merely
 * having a key is not a reason to interrupt someone who came to read the page.
 */
export function resumeIfReturning() {
  if (location.hash === '#get-started') openModal()
}
