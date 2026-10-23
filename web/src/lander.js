/** Lander: the nav account chip, and the sign-up modal it opens. */

import { openModal, closeModal, resumeIfReturning } from './onboard.js'
import { renderAccountChip } from './session.js'

renderAccountChip(openModal)

for (const button of document.querySelectorAll('[data-open-onboard]')) {
  button.addEventListener('click', openModal)
}
for (const target of document.querySelectorAll('[data-close-onboard]')) {
  target.addEventListener('click', closeModal)
}
document.getElementById('mobile-start')?.addEventListener('click', (e) => {
  e.preventDefault()
  openModal()
})

addEventListener('keydown', (e) => {
  if (e.key === 'Escape') closeModal()
})

// Sent here to sign up: open the modal straight away.
resumeIfReturning()
