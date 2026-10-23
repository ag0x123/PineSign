/**
 * Email, via Resend.
 *
 * Every message here is a hand-off between two people who cannot see each
 * other's screens: an invitation, an acceptance, a file, a receipt. Nothing
 * secret goes in one — links carry ids, never keys.
 */

const API_KEY = process.env.RESEND_API_KEY ?? null
const FROM = process.env.MAIL_FROM ?? 'PineSign <noreply@localhost>'

export const configured = Boolean(API_KEY)

export async function send({ to, subject, text, html }) {
  if (!configured) {
    // Without a key, log instead of failing: the flow still runs in local dev.
    console.log(`  [mail not configured] to=${to} subject="${subject}"\n${text}\n`)
    return { id: null, skipped: true }
  }

  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: `Bearer ${API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ from: FROM, to: [to], subject, text, html: html ?? toHtml(text) }),
  })
  const body = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error(`mail: ${body.message ?? res.status}`)
  return { id: body.id }
}

/** Plain text, with links made clickable. Nothing fancier is needed. */
function toHtml(text) {
  const escaped = text.replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' })[c])
  const linked = escaped.replace(/(https?:\/\/[^\s]+)/g, '<a href="$1">$1</a>')
  return `<pre style="font:14px/1.6 -apple-system,Segoe UI,sans-serif;white-space:pre-wrap">${linked}</pre>`
}

// ---- the four messages ----

export function invitation({ to, fromName, link }) {
  return send({
    to,
    subject: `${fromName} wants to send you a file, verifiably`,
    text: [
      `${fromName} wants to send you a file through PineSign.`,
      '',
      'It will be encrypted so only you can open it, and both of you get a receipt that',
      'proves it was delivered — written once, editable by nobody.',
      '',
      `Accept here: ${link}`,
      '',
      'You will sign in with an email code and your passkey, then pick a name. That takes about a minute.',
    ].join('\n'),
  })
}

export function accepted({ to, recipientName, link }) {
  return send({
    to,
    subject: `${recipientName} accepted — you can send now`,
    text: [
      `${recipientName} has accepted your invitation and is ready to receive.`,
      '',
      `Send to: ${recipientName}`,
      '',
      `Or start from here: ${link}`,
    ].join('\n'),
  })
}

export function fileReady({ to, fromName, filename, link, expires }) {
  return send({
    to,
    subject: `${fromName} sent you ${filename}`,
    text: [
      `${fromName} has sent you "${filename}".`,
      '',
      `Open it here: ${link}`,
      '',
      `It expires ${expires}. If you never accept, it disappears and nothing is recorded.`,
    ].join('\n'),
  })
}

export function delivered({ to, recipientName, filename, receiptLink }) {
  return send({
    to,
    subject: `Delivered: ${recipientName} received ${filename}`,
    text: [
      `${recipientName} has decrypted and accepted "${filename}".`,
      '',
      'The receipt is written and cannot be edited or withdrawn — by you or by them.',
      '',
      `Receipt: ${receiptLink}`,
    ].join('\n'),
  })
}
