/**
 * The account chip in the nav, shared by every page.
 *
 * Signed out it reads "Get started"; signed in it shows the name the key
 * answers to, or the key's address until a name is claimed. One element, two
 * states, so the nav never lies about whether you have an account.
 */

import { identity as getIdentity } from '../../shared/keysource.js'
import { Gateway } from '../../shared/client.js'

const gateway = new Gateway(location.origin)
const short = (addr) => `${addr.slice(0, 6)}…${addr.slice(-4)}`

/**
 * @param onGetStarted - called when a signed-out visitor clicks the chip.
 *   Omit it on pages with no sign-up UI of their own and the chip becomes a
 *   link to the one page that has.
 */
export async function renderAccountChip(onGetStarted) {
  const slot = document.getElementById('account-slot')
  if (!slot) return

  const identity = await getIdentity().catch(() => null)

  if (!identity) {
    slot.innerHTML = ''
    const chip = document.createElement(onGetStarted ? 'button' : 'a')
    chip.className = 'cta-btn'
    chip.textContent = 'Get started'
    if (onGetStarted) {
      chip.addEventListener('click', onGetStarted)
    } else {
      chip.href = '/#get-started'
    }
    slot.append(chip)
    return
  }

  const named = await gateway.reverseName(identity.publicKey)
  const label = named ? named.name : short(identity.address)

  slot.innerHTML = `
    <div class="account-chip" tabindex="0">
      <span class="dot"></span>
      <span class="addr">${label}</span>
      <div class="account-menu">
        <div class="full">${identity.address}</div>
      </div>
    </div>`
}
