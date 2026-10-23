/**
 * Server setup page.
 *
 * The server owns the state; this walks the admin through whatever step it says
 * is next, and re-reads after every action rather than tracking progress itself.
 */

import {
  walletPresent, walletName, send as sendFromWallet, connect, signMessage, sendXdai, sendToken,
} from './wallet.js'

/**
 * BZZ, on whichever chain the Bee node is funded from. Sixteen decimals, not
 * eighteen. The address is per chain, so it is compiled in from .env rather
 * than written here — see BZZ_TOKEN in .env.example.
 */
const BZZ_TOKEN = __PINESIGN_BZZ_TOKEN__
const BZZ_DECIMALS = 16n

const el = (id) => document.getElementById(id)

let token = new URLSearchParams(location.search).get('token') ?? localStorage.getItem('pinesign.setupToken') ?? ''
let session = localStorage.getItem('pinesign.adminSession') ?? ''
let adminAddress = null
let pollTimer = null

/**
 * A step the operator has navigated back to, overriding whatever the server
 * says comes next. Cleared as soon as they act, so the flow resumes.
 */
let viewing = null
let latest = null

async function api(path, options = {}) {
  const res = await fetch(path, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      // Either proof is enough; the session is preferred and the token remains
      // as recovery for an admin who has lost the wallet.
      ...(session ? { 'x-admin-session': session } : {}),
      ...(token ? { 'x-setup-token': token } : {}),
      ...(options.headers ?? {}),
    },
  })
  const body = await res.json().catch(() => ({}))
  if (!res.ok) throw Object.assign(new Error(body.error ?? res.statusText), { status: res.status })
  return body
}

function status(node, message, kind = '') {
  el(node).textContent = message
  el(node).className = `status ${kind}`.trim()
}

const STEPS = ['name', 'keys', 'fund', 'swarm']

function showOnly(step) {
  for (const s of ['locked', 'step-name', 'step-keys', 'step-fund', 'step-swarm', 'step-done']) {
    el(s).hidden = true
  }
  el(step).hidden = false
}

/**
 * The rail marks everything before the current step as finished, and makes the
 * finished ones clickable where going back is still allowed.
 */
function renderProgress(serverStep, shownStep) {
  const at = STEPS.indexOf(serverStep)
  const shown = STEPS.indexOf(shownStep)

  for (const li of el('progress').children) {
    const i = STEPS.indexOf(li.dataset.step)
    const done = at === -1 || i < at
    li.className = i === shown ? 'current' : done ? 'done' : ''

    const revisitable = done && (li.dataset.step !== 'name' || latest?.canChangeName)
    li.classList.toggle('clickable', Boolean(revisitable))
    li.onclick = revisitable
      ? () => {
          viewing = li.dataset.step
          render(latest)
        }
      : null
  }
}

/**
 * Funding packages, paid straight from the operator's own wallet.
 *
 * Each button is priced by the server at the current gas price, so what it
 * charges and what the server will spend are the same arithmetic.
 */
function renderPackages(state) {
  const box = el('packages')
  // Before setup is paid for, offer the small first rung; afterwards, top-ups.
  const setUp = state.nameRegistered && state.receiptsAddress
  const packages = (setUp ? state.budget?.topUpPackages : state.budget?.setupPackages) ?? []

  if (!walletPresent()) {
    box.innerHTML = ''
    el('pay-hint').textContent =
      'No browser wallet detected. Install MetaMask or Phantom to pay from here, or send to the address in the top right by hand.'
    return
  }

  el('pay-hint').textContent = `Pick what this server should be able to do. Paid from ${walletName()} on Sepolia.`
  box.innerHTML = ''

  for (const pkg of packages) {
    const button = document.createElement('button')
    button.className = 'package'
    // Shown as what is still owed, with the full figure alongside when the
    // wallet already covers part of it.
    const price = pkg.alreadyCovered
      ? 'covered'
      : Number(pkg.wei) < Number(pkg.target)
        ? `+${Number(pkg.eth).toFixed(4)} ETH`
        : `${Number(pkg.eth).toFixed(4)} ETH`
    const note = pkg.alreadyCovered
      ? `${pkg.note} — already funded`
      : pkg.note
    button.innerHTML = `
      <span class="pk-top">
        <span class="pk-name">${pkg.label}</span>
        <span class="pk-price">${price}</span>
      </span>
      <span class="pk-note">${note}</span>`
    button.disabled = pkg.alreadyCovered

    button.addEventListener('click', async () => {
      for (const b of box.children) b.disabled = true
      status('pay-status', `Confirm ${Number(pkg.eth).toFixed(4)} ETH in your wallet…`)
      try {
        const hash = await sendFromWallet({ to: state.deployer, wei: pkg.wei })
        status('pay-status', `Sent. Waiting for it to land — ${hash.slice(0, 12)}…`, 'done')
        // The balance poll will pick it up; nudge it rather than waiting a cycle.
        clearTimeout(pollTimer)
        pollTimer = setTimeout(refresh, 4000)
      } catch (err) {
        // 4001 is the user closing the wallet, which is not an error worth shouting about.
        status('pay-status', err.code === 4001 ? '' : err.message, err.code === 4001 ? '' : 'error')
        for (const b of box.children) b.disabled = false
      }
    })

    box.append(button)
  }
}

/**
 * The wallet lives in the header rather than inside a step, because it is the
 * thing an operator checks repeatedly and the thing every step depends on.
 */
function renderWalletBar(state) {
  if (!state.deployer) {
    el('bar-wallet').hidden = true
    return
  }
  el('bar-wallet').hidden = false
  el('bar-address').textContent = `${state.deployer.slice(0, 10)}…${state.deployer.slice(-6)}`
  el('bar-address').title = state.deployer

  const eth = state.balance ? Number(state.balance.eth) : null
  el('bar-balance').textContent = eth === null ? 'balance unknown' : `${eth.toFixed(5)} ETH`
  el('bar-balance').className = `wc-balance${eth === 0 ? ' empty' : ''}`
}

/**
 * The node's wallet, which is on a different chain and holds different money.
 * Shown beside the server's so the two are never confused for one another.
 */
function renderNodeBar(bee) {
  const address = bee?.wallet?.address
  if (!address) {
    el('bar-node').hidden = true
    return
  }

  el('bar-node').hidden = false
  el('bar-node-address').textContent = `${address.slice(0, 10)}…${address.slice(-6)}`
  el('bar-node-address').title = address

  if (!bee.balancesKnown) {
    el('bar-node-balance').textContent = 'syncing…'
    el('bar-node-balance').className = 'wc-balance'
    return
  }

  const bzz = Number(bee.wallet.bzz?.formatted ?? 0)
  const xdai = Number(bee.wallet.xdai?.formatted ?? 0)
  el('bar-node-balance').textContent = `${bzz.toFixed(3)} BZZ · ${xdai.toFixed(4)} xDAI`
  el('bar-node-balance').className = `wc-balance${bzz === 0 || xdai === 0 ? ' empty' : ''}`
}

/**
 * The Swarm step, rendered from whatever the node is currently able to say.
 * A node that is starting, unfunded, or absent each need a different next
 * action, so the panel names which one it is.
 */
function renderBee(bee) {
  if (!bee || !bee.reachable) {
    el('b-status').textContent = 'not reachable'
    el('b-missing').hidden = false
    el('b-funding').hidden = true
    el('buy-postage').disabled = true
    return
  }

  el('b-missing').hidden = true
  el('b-status').textContent = bee.ready ? 'running' : `starting (${bee.status ?? 'wait'})`
  el('b-version').textContent = bee.version ?? '—'

  if (bee.wallet) {
    el('b-funding').hidden = false
    el('b-wallet').textContent = bee.wallet.address
    el('b-balances').textContent = bee.balancesKnown
      ? `${bee.wallet.bzz?.formatted ?? '?'} BZZ · ${bee.wallet.xdai?.formatted ?? '?'} xDAI`
      : 'balances available once the node has synced'
  }

  // Quote the batch before offering to buy it: lifetime and capacity are
  // purchases, not defaults, and the operator should see what they get.
  if (bee.quote) {
    el('stamp-quote').hidden = false
    el('q-ttl').textContent = `${bee.quote.ttlDays.toFixed(1)} days`
    el('q-capacity').textContent = `${(bee.quote.capacityBytes / 1024 / 1024).toFixed(0)} MB`
    el('q-cost').textContent = `${bee.quote.costBzz.toFixed(4)} BZZ`
  }

  const held = Number(bee.wallet?.bzz?.formatted ?? 0)
  const affordable = !bee.quote || held >= bee.quote.costBzz
  const funded = held > 0
  el('buy-postage').disabled = !(bee.ready && funded && affordable)

  if (!bee.ready) {
    // Funding can happen during the sync, and should: the node needs xDAI
    // before it can deploy its chequebook and finish starting.
    status(
      'swarm-status',
      'The node is syncing — this takes a few minutes on first boot. You can send it BZZ and xDAI now; it needs them to finish.',
    )
  } else if (!funded) {
    status('swarm-status', 'Send BZZ and xDAI on Gnosis to the node address above.')
  } else if (!affordable) {
    status('swarm-status', `This batch costs ${bee.quote.costBzz.toFixed(4)} BZZ and the node holds ${held.toFixed(4)}. Send more BZZ.`, 'error')
  } else {
    status('swarm-status', 'Funded. Ready to buy a batch.', 'done')
  }
}

function render(state) {
  latest = state
  el('bar-admin').hidden = !adminAddress
  if (adminAddress) el('bar-admin-address').textContent = `${adminAddress.slice(0, 6)}…${adminAddress.slice(-4)}`
  el('rpc').textContent = `RPC: ${state.rpcUrl}`
  renderWalletBar(state)
  renderNodeBar(state.bee)

  // A revisited step wins over the server's idea of what comes next.
  const step = viewing ?? state.step
  renderProgress(state.step, step)

  if (viewing && viewing !== state.step) {
    showOnly(`step-${viewing}`)

    if (viewing === 'name') {
      el('subtitle').textContent = `Currently ${state.parentName}. Change it if you like.`
      el('name').value = (state.parentName ?? '').replace(/\.eth$/, '')
      el('name-check').textContent = ''
      el('name-check').className = 'availability'
      el('save-name').disabled = true
      return
    }

    if (viewing === 'keys') {
      // A wallet already exists. Showing the button that makes one invites the
      // reasonable fear that looking back has destroyed it.
      el('subtitle').textContent = 'Already done.'
      el('gen-keys').hidden = Boolean(state.deployer)
      status(
        'keys-status',
        state.deployer
          ? `This server's wallet is ${state.deployer}. It cannot be replaced — the name and contract belong to it.`
          : '',
        state.deployer ? 'done' : '',
      )
      return
    }

    el('subtitle').textContent = 'Looking back.'
    return
  }

  // Leaving a revisited step restores the button for a genuinely fresh server.
  el('gen-keys').hidden = false

  if (state.step === 'name') {
    showOnly('step-name')
    el('subtitle').textContent = 'Nothing configured yet.'
    return
  }

  if (state.step === 'keys') {
    showOnly('step-keys')
    el('subtitle').textContent = `Issuing subnames under ${state.parentName}.`
    return
  }

  if (state.step === 'fund') {
    showOnly('step-fund')
    el('subtitle').textContent = 'Waiting for gas.'
    const eth = (v, digits = 6) => (v ? `${Number(v.eth).toFixed(digits)} ETH` : '—')

    el('fund-tip').hidden = Boolean(state.canRegisterName && state.fundedEnough)

    const b = state.budget
    renderPackages(state)
    el('gas-note').textContent = b ? `at ${b.gasPriceGwei} gwei, the current gas price` : 'at current gas'
    el('c-name').textContent = state.parentName ?? 'the name'
    el('c-domain').textContent = state.nameRegistered ? 'already registered' : 'gas only'
    // ENSv2 prices names in a token; on this testnet it is freely mintable, so
    // the fee costs the operator nothing but is worth showing plainly.
    el('c-fee').textContent = state.registrationFee
      ? `${state.registrationFee} — minted by the server, free on testnet`
      : '—'
    el('c-deploy').textContent = eth(b?.deploy)
    el('c-user').textContent = eth(b?.perUser)
    el('c-transfer').textContent = eth(b?.perTransfer)
    el('c-100users').textContent = eth(b?.hundredUsers, 4)
    el('c-100transfers').textContent = eth(b?.hundredTransfers, 4)
    el('c-suggested').textContent = b ? `${Number(b.suggested).toFixed(4)} ETH` : '—'

    // The name can be bought from here, so long as it is still free — but only
    // offered as clickable once there is enough to pay the registrar.
    // Registration is only offered where it can actually succeed.
    if (state.registrationAvailable === false) {
      status('deploy-status', state.registrationBlockedReason ?? 'Registration is unavailable on this network.', 'error')
    }
    const showRegister = state.nameAvailable && !state.nameRegistered && state.registrationAvailable !== false
    el('register-name').hidden = !showRegister
    el('register-name').disabled = !state.canRegisterName
    if (showRegister) {
      el('register-name').textContent = state.canRegisterName
        ? `Register ${state.parentName}`
        : `Need ${Number(state.registrationShortfall ?? 0).toFixed(4)} ETH more to register`
    }

    el('deploy').disabled = !state.fundedEnough || Boolean(state.receiptsAddress)
    el('deploy').textContent = state.receiptsAddress ? 'Contract deployed' : 'Deploy the contract'

    el('attach-resolver').hidden = !state.canAttachResolver
    el('resolver-hint').hidden = !state.canAttachResolver
    if (state.canAttachResolver) {
      el('attach-resolver').disabled = state.canAffordResolver === false
      el('attach-resolver').textContent = state.canAffordResolver === false
        ? `Need ${Number(state.resolverShortfall).toFixed(4)} ETH more for the resolver`
        : 'Attach the resolver'
    }

    const outstanding = []
    if (!state.nameRegistered) outstanding.push('register the name')
    if (state.canAttachResolver) outstanding.push('attach the resolver')
    if (!state.receiptsAddress) outstanding.push('deploy the contract')

    if (state.registrationAvailable === false) {
      // already reported above
    } else if (!state.fundedEnough) {
      status('deploy-status', 'Send Sepolia ETH to the address above.')
    } else if (outstanding.length) {
      status('deploy-status', `Funded. Still to do: ${outstanding.join(' and ')}.`, 'done')
    } else {
      status('deploy-status', 'Done.', 'done')
    }

    // Keep looking until the money lands, then stop.
    clearTimeout(pollTimer)
    if (!state.fundedEnough) pollTimer = setTimeout(refresh, 5000)
    return
  }

  if (state.step === 'swarm') {
    showOnly('step-swarm')
    el('subtitle').textContent = 'One thing left: storage.'
    renderBee(state.bee)
    clearTimeout(pollTimer)
    if (!state.bee?.reachable || !state.bee?.ready) pollTimer = setTimeout(refresh, 8000)
    return
  }

  showOnly('step-done')
  el('subtitle').textContent = 'Configured and running.'
  el('d-name').textContent = state.parentName
  el('d-registered').textContent = state.nameRegistered
    ? state.resolver ? `yes, resolver ${state.resolver.slice(0, 10)}…` : 'yes, no resolver'
    : 'no — names are local only'
  el('d-address').textContent = state.receiptsAddress
  el('d-tx').textContent = state.deployTx
  el('d-deployer').textContent = state.deployer
  el('d-storage').textContent = state.postageBatchId
    ? state.bee?.reachable ? 'swarm' : 'swarm (node unreachable)'
    : 'local folder'
  el('d-batch').textContent = state.postageBatchId
    ? `${state.postageBatchId.slice(0, 14)}…`
    : 'none'
  el('d-balance').textContent = state.balance
    ? `${Number(state.balance.eth).toFixed(5)} ETH`
    : 'balance unknown'

  // Turn the balance into the only number an operator really wants: how much
  // more use this server can pay for before it stops working.
  if (state.balance && state.budget) {
    const left = BigInt(state.balance.wei)
    const users = Number(left / BigInt(state.budget.perUser.wei))
    const transfers = Number(left / BigInt(state.budget.perTransfer.wei))
    el('d-runway').textContent =
      left === 0n
        ? 'Empty. Fund this wallet or the server cannot issue names or record receipts.'
        : `Enough for roughly ${users.toLocaleString()} more users, or ${transfers.toLocaleString()} more transfers, at ${state.budget.gasPriceGwei} gwei.`
  }
}

async function refresh() {
  try {
    // An unclaimed server is shown the claim screen first, even though the
    // console token would let us straight in: the point of the token is to
    // prove who may claim it, not to be the way in from then on.
    if (!adminAddress && !session) {
      const { adminAddress: owner } = await (await fetch('/api/setup/admin')).json()
      if (!owner) return showSignIn()
      adminAddress = owner
    }

    render(await api('/api/setup/status'))
  } catch (err) {
    if (err.status === 401) return showSignIn()
    el('subtitle').textContent = err.message
  }
}

/** Funding the node is two transfers on a different chain from everything else. */
async function fundNode(kind) {
  const to = el('b-wallet').textContent.trim()
  if (!to.startsWith('0x')) return

  const buttons = [el('send-xdai'), el('send-bzz')]
  for (const b of buttons) b.disabled = true
  status('node-fund-status', 'Confirm in your wallet — it will switch to Gnosis first…')

  try {
    const hash = kind === 'xdai'
      ? await sendXdai({ to, wei: 50000000000000000n }) // 0.05 xDAI
      : await sendToken({ token: BZZ_TOKEN, to, amount: 10n * 10n ** BZZ_DECIMALS })

    status('node-fund-status', `Sent — ${hash.slice(0, 12)}… The node picks it up within a minute.`, 'done')
    clearTimeout(pollTimer)
    pollTimer = setTimeout(refresh, 6000)
  } catch (err) {
    status('node-fund-status', err.code === 4001 ? '' : err.message, err.code === 4001 ? '' : 'error')
  } finally {
    for (const b of buttons) b.disabled = false
  }
}

el('send-xdai').addEventListener('click', () => fundNode('xdai'))
el('send-bzz').addEventListener('click', () => fundNode('bzz'))

/**
 * One click, both currencies, in the amounts a test actually needs.
 *
 * They cannot be batched — two tokens, two transactions — so this sends them in
 * order and waits for the first, since the node needs gas before anything else
 * it is given is of any use.
 */
el('fund-test').addEventListener('click', async () => {
  const to = el('b-wallet').textContent.trim()
  if (!to.startsWith('0x')) return

  const buttons = [el('fund-test'), el('send-xdai'), el('send-bzz')]
  for (const b of buttons) b.disabled = true

  try {
    status('node-fund-status', 'Confirm the first of two: 0.02 xDAI for gas…')
    await sendXdai({ to, wei: 20000000000000000n }) // 0.02 xDAI

    status('node-fund-status', 'Now the second: 1 BZZ for postage…')
    const hash = await sendToken({ token: BZZ_TOKEN, to, amount: 1n * 10n ** BZZ_DECIMALS })

    status('node-fund-status', `Both sent — ${hash.slice(0, 12)}… The node needs a minute to notice.`, 'done')
    clearTimeout(pollTimer)
    pollTimer = setTimeout(refresh, 6000)
  } catch (err) {
    status(
      'node-fund-status',
      err.code === 4001 ? 'Cancelled. Anything already sent has still arrived.' : err.message,
      err.code === 4001 ? '' : 'error',
    )
  } finally {
    for (const b of buttons) b.disabled = false
  }
})

el('b-copy').addEventListener('click', () => {
  navigator.clipboard.writeText(el('b-wallet').textContent)
  el('b-copy').textContent = 'Copied'
  setTimeout(() => (el('b-copy').textContent = 'Copy address'), 1200)
})

el('b-refresh').addEventListener('click', refresh)

el('buy-postage').addEventListener('click', async () => {
  el('buy-postage').disabled = true
  clearTimeout(pollTimer)
  status('swarm-status', 'Buying postage — the node is waiting on Gnosis…')
  try {
    render(await api('/api/setup/postage', { method: 'POST', body: JSON.stringify({}) }))
  } catch (err) {
    status('swarm-status', err.message, 'error')
    el('buy-postage').disabled = false
  }
})

el('bar-node-copy').addEventListener('click', () => {
  navigator.clipboard.writeText(el('bar-node-address').title)
  el('bar-node-copy').textContent = 'ok'
  setTimeout(() => (el('bar-node-copy').textContent = 'copy'), 1200)
})

el('bar-copy').addEventListener('click', () => {
  navigator.clipboard.writeText(el('bar-address').title)
  el('bar-copy').textContent = 'ok'
  setTimeout(() => (el('bar-copy').textContent = 'copy'), 1200)
})

el('d-copy').addEventListener('click', () => {
  navigator.clipboard.writeText(el('d-deployer').textContent)
  el('d-copy').textContent = 'Copied'
  setTimeout(() => (el('d-copy').textContent = 'Copy address'), 1200)
})

el('d-refresh').addEventListener('click', refresh)

async function showSignIn() {
  showOnly('locked')
  el('subtitle').textContent = 'Locked.'

  const { adminAddress: owner } = await (await fetch('/api/setup/admin')).json()
  const claimed = Boolean(owner)

  el('claim-block').hidden = claimed
  if (!claimed && token) el('token').value = token
  el('lock-title').textContent = claimed ? 'Sign in as administrator' : 'Claim this server'
  el('lock-hint').textContent = claimed
    ? `This server is administered by ${owner.slice(0, 10)}…${owner.slice(-6)}. Sign in with that wallet.`
    : 'Connect a wallet to become the administrator of this server.'

  if (!walletPresent()) {
    el('wallet-signin').disabled = true
    status('lock-status', 'No browser wallet found. Use the console token below instead.')
  } else {
    el('wallet-signin').textContent = `Sign in with ${walletName()}`
  }
}

el('wallet-signin').addEventListener('click', async () => {
  el('wallet-signin').disabled = true
  status('lock-status', 'Connecting…')
  try {
    const address = await connect()

    status('lock-status', 'Check your wallet for a message to sign…')
    const { nonce, message } = await (await fetch('/api/setup/admin/nonce', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ address }),
    })).json()

    const signed = await signMessage(message)

    const res = await fetch('/api/setup/admin/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        address: signed.address,
        nonce,
        signature: signed.signature,
        // Only consulted on a first run, to claim an unowned server.
        token: el('token').value.trim() || token,
      }),
    })
    const body = await res.json()
    if (!res.ok) throw new Error(body.error)

    session = body.session
    adminAddress = body.address
    // The token has done its one job; the wallet is the key from here.
    token = ''
    localStorage.removeItem('pinesign.setupToken')
    localStorage.setItem('pinesign.adminSession', session)
    status('lock-status', '')
    await refresh()
  } catch (err) {
    status('lock-status', err.code === 4001 ? 'Signature declined.' : err.message, 'error')
    el('wallet-signin').disabled = false
  }
})

el('bar-signout').addEventListener('click', async () => {
  await fetch('/api/setup/admin/signout', { method: 'POST', headers: { 'x-admin-session': session } })
  localStorage.removeItem('pinesign.adminSession')
  session = ''
  location.reload()
})

el('unlock').addEventListener('click', async () => {
  token = el('token-only').value.trim()
  localStorage.setItem('pinesign.setupToken', token)
  status('lock-status', 'Checking…')
  await refresh()
})

// ---- 1: name ----

let checkTimer = null
el('name').addEventListener('input', () => {
  // The field takes a label; the .eth is fixed beside it.
  const label = el('name').value.trim().toLowerCase().replace(/\.eth$/, '')
  const name = `${label}.eth`
  el('save-name').disabled = true
  el('name-check').textContent = ''
  el('name-check').className = 'availability'
  if (!/^[a-z0-9-]{3,}$/.test(label)) return

  clearTimeout(checkTimer)
  el('name-check').textContent = 'checking…'
  el('name-check').className = 'availability'
  checkTimer = setTimeout(async () => {
    try {
      const result = await api(`/api/setup/name/${name}`)
      // Available means free on both chains: a name taken on mainnet is one you
      // could never carry beyond the testnet.
      const free = result.available
      const onSepolia = result.sepolia?.available
      const onMainnet = result.mainnet?.available

      if (free) {
        el('name-check').textContent = `${name} is free on Sepolia and mainnet.`
        el('name-check').className = 'availability free'
      } else if (!onSepolia) {
        el('name-check').textContent = `${name} is already taken on Sepolia.`
        el('name-check').className = 'availability taken'
      } else if (onMainnet === false) {
        const until = result.mainnet.expires
          ? ` until ${result.mainnet.expires.slice(0, 10)}`
          : ''
        el('name-check').textContent =
          `${name} is free on Sepolia but owned on mainnet${until} — you could not keep it beyond the testnet.`
        el('name-check').className = 'availability taken'
      } else {
        el('name-check').textContent = `${name} is free on Sepolia; mainnet could not be checked.`
        el('name-check').className = 'availability'
      }
      el('save-name').disabled = false
    } catch (err) {
      el('name-check').textContent = err.message
      el('name-check').className = 'availability bad'
    }
  }, 400)
})

el('save-name').addEventListener('click', async () => {
  el('save-name').disabled = true
  viewing = null
  try {
    const label = el('name').value.trim().toLowerCase().replace(/\.eth$/, '')
    render(await api('/api/setup/name', { method: 'POST', body: JSON.stringify({ name: `${label}.eth` }) }))
  } catch (err) {
    el('name-check').textContent = err.message
    el('name-check').className = 'availability bad'
    el('save-name').disabled = false
  }
})

// ---- 2: keys ----

el('gen-keys').addEventListener('click', async () => {
  el('gen-keys').disabled = true
  status('keys-status', 'Generating…')
  try {
    render(await api('/api/setup/keys', { method: 'POST' }))
  } catch (err) {
    status('keys-status', err.message, 'error')
    el('gen-keys').disabled = false
  }
})

// ---- 3: fund and deploy ----

el('register-name').addEventListener('click', async () => {
  el('register-name').disabled = true
  clearTimeout(pollTimer)
  status('deploy-status', 'Registering — this takes two transactions and a minute between them…')
  try {
    render(await api('/api/setup/register-name', { method: 'POST' }))
  } catch (err) {
    status('deploy-status', err.message, 'error')
    el('register-name').disabled = false
  }
})

el('attach-resolver').addEventListener('click', async () => {
  el('attach-resolver').disabled = true
  clearTimeout(pollTimer)
  status('deploy-status', 'Deploying the resolver and attaching it to the name — two transactions…')
  try {
    render(await api('/api/setup/resolver', { method: 'POST' }))
  } catch (err) {
    status('deploy-status', err.message, 'error')
    el('attach-resolver').disabled = false
  }
})

el('deploy').addEventListener('click', async () => {
  el('deploy').disabled = true
  clearTimeout(pollTimer)
  status('deploy-status', 'Deploying — this takes a block or two…')
  try {
    render(await api('/api/setup/deploy', { method: 'POST' }))
  } catch (err) {
    status('deploy-status', err.message, 'error')
    el('deploy').disabled = false
  }
})

refresh()
