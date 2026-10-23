/**
 * Rate limiting and input hygiene.
 *
 * On a public address the expensive endpoints are the ones that spend something
 * the server owns: postage, mail, gas. None of them should be reachable
 * at machine speed by anyone who finds the domain.
 *
 * Deliberately in-memory: a hackathon server does not need shared state, and a
 * limiter that fails open on restart is better than a dependency that fails.
 */

const buckets = new Map()

/** Fixed-window counter, keyed by client and route. */
export function rateLimit({ windowMs = 60_000, max = 30, key = 'default' } = {}) {
  return (req, res, next) => {
    const who = clientIp(req)
    const bucketKey = `${key}:${who}`
    const now = Date.now()

    const bucket = buckets.get(bucketKey)
    if (!bucket || now > bucket.resetAt) {
      buckets.set(bucketKey, { count: 1, resetAt: now + windowMs })
      return next()
    }

    bucket.count += 1
    if (bucket.count > max) {
      const retry = Math.ceil((bucket.resetAt - now) / 1000)
      res.set('Retry-After', String(retry))
      return res.status(429).json({ error: `too many requests — try again in ${retry}s` })
    }
    next()
  }
}

function clientIp(req) {
  // Behind a reverse proxy the socket address is the proxy's, so the forwarded
  // header is used when Express has been told to trust it.
  return req.ip ?? req.socket.remoteAddress ?? 'unknown'
}

/** Sweep expired buckets so a long-running server does not accumulate them. */
setInterval(() => {
  const now = Date.now()
  for (const [k, v] of buckets) if (now > v.resetAt) buckets.delete(k)
}, 60_000).unref()

const HEX = /^[0-9a-f]+$/i

/**
 * Identifiers that reach a lookup must be plain hex.
 *
 * Ids index plain objects and, in local storage mode, become path segments.
 * "__proto__" or "../.." reaching either is the kind of thing that is obvious
 * in hindsight, so the shape is checked rather than the symptoms.
 */
export function requireHexParam(name, { length } = {}) {
  return (req, res, next) => {
    const value = req.params[name]
    if (typeof value !== 'string' || !HEX.test(value) || (length && value.length !== length)) {
      return res.status(400).json({ error: `${name} must be a hex string` })
    }
    next()
  }
}

export function isHex(value, length) {
  return typeof value === 'string' && HEX.test(value) && (!length || value.length === length)
}
