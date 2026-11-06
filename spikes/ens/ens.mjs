// Spike 7 — ENSv2, read only. Confirms the deployments have code, prices pinesign.eth,
// and tests whether wildcard (ENSIP-10) and offchain CCIP-Read resolution work through
// UniversalResolverV2. No transactions.
import { createPublicClient, http, parseAbi, formatEther, namehash } from 'viem'
import { mainnet, sepolia } from 'viem/chains'
import { normalize } from 'viem/ens'

const RPC = { mainnet: process.env.MAINNET_RPC || 'https://ethereum-rpc.publicnode.com', sepolia: process.env.SEPOLIA_RPC || 'https://ethereum-sepolia-rpc.publicnode.com' }
const ADDR = {
  mainnet: {
    v1Registry: '0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e',
    v1Controller: '0x59E16fcCd424Cc24e280Be16E11Bcd56fb0CE547',
    universalResolverProxy: '0xeEeEEEeE14D718C2B47D9923Deab1335E144EeEe',
    universalResolverV2: '0x06fdd07f007adac667177b46ab2eb9a75132cfd5',
    ethRegistry: '0xf60aba43e1f7f3dab1186ff03b561401c9df85e2',
    ethRegistrar: '0xd6d8369e55c94ae8afa714e6cf7ab5be54d5cc81',
    rootRegistry: '0x2553c09be6447beffdb86fa622ad41fb8f77a91e',
  },
  sepolia: {
    universalResolverProxy: '0xeEeEEEeE14D718C2B47D9923Deab1335E144EeEe',
    universalResolverV2: '0x24e1d8e068620b647ca097f961a61055f4f42d72',
    ethRegistry: '0xd4ebcbbdf463c9c45784603db0ddd499bc44a8b4',
    ethRegistrar: '0xf633e7fc17e2bbe0d0965d18ec1821dcb754a3d3',
    rootRegistry: '0xb458d6a3a77919449d03e7a6903c26827c1ec43f',
  },
}
const out = {}
const clients = {
  mainnet: createPublicClient({ chain: mainnet, transport: http(RPC.mainnet) }),
  sepolia: createPublicClient({ chain: sepolia, transport: http(RPC.sepolia) }),
}

// --- 1. do the published addresses actually have code?
for (const net of ['mainnet', 'sepolia']) {
  out[net] = { deployed: {} }
  for (const [name, address] of Object.entries(ADDR[net])) {
    const code = await clients[net].getCode({ address }).catch(() => undefined)
    out[net].deployed[name] = code && code !== '0x' ? `${(code.length - 2) / 2} bytes` : 'NO CODE'
  }
}

// --- 2. what would pinesign.eth cost on mainnet?
const CONTROLLER = parseAbi([
  'function available(string name) view returns (bool)',
  'function rentPrice(string name, uint256 duration) view returns (uint256 base, uint256 premium)',
])
const price = {}
for (const [label, address] of [['v1Controller', ADDR.mainnet.v1Controller], ['ethRegistrar', ADDR.mainnet.ethRegistrar]]) {
  const r = {}
  try { r.available = await clients.mainnet.readContract({ address, abi: CONTROLLER, functionName: 'available', args: ['pinesign'] }) } catch (e) { r.availableError = (e.shortMessage || e.message).slice(0, 90) }
  for (const years of [1, 5]) {
    try {
      const [base, premium] = await clients.mainnet.readContract({ address, abi: CONTROLLER, functionName: 'rentPrice', args: ['pinesign', BigInt(years * 31557600)] })
      r[`${years}yEth`] = formatEther(base + premium)
    } catch (e) { r[`${years}yError`] = (e.shortMessage || e.message).slice(0, 90) }
  }
  price[label] = r
}
out.pinesignEthPrice = price

// --- 3. resolution: onchain, offchain CCIP-Read, and a wildcard subname
const probe = async (net, name) => {
  const t = Date.now()
  try {
    const address = await clients[net].getEnsAddress({ name: normalize(name), universalResolverAddress: ADDR[net].universalResolverProxy })
    return { address, ms: Date.now() - t }
  } catch (e) { return { error: (e.shortMessage || e.message).split('\n')[0].slice(0, 120), ms: Date.now() - t } }
}
out.resolution = {
  mainnet_onchain_nick_eth: await probe('mainnet', 'nick.eth'),
  mainnet_offchain_ccip_read: await probe('mainnet', '1.offchainexample.eth'),
  mainnet_wildcard_subname: await probe('mainnet', 'anything-random-12345.offchainexample.eth'),
  mainnet_l2_subname_base_eth: await probe('mainnet', 'jesse.base.eth'),
}

out.PASS =
  Object.values(out.mainnet.deployed).every((v) => v !== 'NO CODE') &&
  !!out.resolution.mainnet_onchain_nick_eth.address &&
  !!out.resolution.mainnet_offchain_ccip_read.address
console.log(JSON.stringify(out, null, 2))
