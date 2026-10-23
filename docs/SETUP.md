# Setting up a deployment

Replace `example.com` throughout with your own domain. Nothing in the code
knows your domain; everything comes from `.env`.

You need three names:

| Name | Serves | Who issues the certificate |
|---|---|---|
| `example.com` | the lander and the API | Caddy, HTTP-01 |
| `www.example.com` | the same | Caddy, HTTP-01 |
| `*.id.example.com` | published sign-in pages | Caddy, **DNS-01** |

The sign-in pages are deliberately under `id.example.com` and not under the
apex. A passkey scoped to `id.example.com` can be asserted by that host and
anything below it, and **not** by `example.com`. That is what stops the lander —
which the gateway serves, and which could in principle serve something else —
from asking for an assertion and reading the derived key out of it. Putting the
sign-in page on the apex would hand the key to every page on the domain.

---

## 1. DNS, on Cloudflare

The wildcard certificate is why Cloudflare is here: a wildcard cannot be issued
over HTTP-01, only DNS-01, and DNS-01 needs an API the certificate tool can
write to. Cloudflare has one and a Caddy plugin for it.

1. Add the domain as a zone in Cloudflare and point the registrar's nameservers
   at the two Cloudflare gives you. Wait for the zone to go active.
2. Add these records. **Set the proxy to DNS only (grey cloud), not proxied.**
   Proxying terminates TLS at Cloudflare, which breaks DNS-01 issuance on your
   own box and puts a third party in front of the page that holds the key.

   | Type | Name | Content | Proxy |
   |---|---|---|---|
   | A | `@` | your server's IP | DNS only |
   | A | `www` | your server's IP | DNS only |
   | A | `*.id` | your server's IP | DNS only |

3. In **SSL/TLS → Overview**, set the mode to **Full (strict)**. With the
   records unproxied this is not on the request path, but it stops a later
   proxy toggle from silently downgrading anything.
4. Create a scoped API token: **My Profile → API Tokens → Create Token**, with
   permissions `Zone / DNS / Edit` and `Zone / Zone / Read`, limited to this one
   zone. Caddy needs nothing else. Keep it out of the repository.

Check it before going further:

```
dig +short example.com
dig +short anything.id.example.com
```

Both must return your server's IP, and neither may return a Cloudflare address.

## 2. Caddy, with the Cloudflare DNS plugin

The stock Caddy binary cannot do DNS-01: the provider modules are compiled in.
Build one that can, or install the package and replace the binary:

```
# on the server
curl -fsSL "https://caddyserver.com/api/download?os=linux&arch=amd64&p=github.com/caddy-dns/cloudflare" \
  -o /usr/local/bin/caddy-cf
chmod +x /usr/local/bin/caddy-cf
/usr/local/bin/caddy-cf list-modules | grep cloudflare   # must print dns.providers.cloudflare
systemctl stop caddy
mv /usr/local/bin/caddy-cf /usr/bin/caddy
```

Give the token to the service rather than the Caddyfile, so it is not in a file
you might later paste somewhere:

```
systemctl edit caddy
```

```ini
[Service]
Environment="CLOUDFLARE_API_TOKEN=your-token-here"
```

Then the Caddyfile. The gateway does the host routing and the Swarm fetching
itself, so Caddy's whole job is TLS and forwarding:

```caddyfile
example.com, www.example.com {
	reverse_proxy 127.0.0.1:8788
}

*.id.example.com, id.example.com {
	tls {
		dns cloudflare {env.CLOUDFLARE_API_TOKEN}
	}
	reverse_proxy 127.0.0.1:8788
}
```

```
caddy validate --config /etc/caddy/Caddyfile
systemctl restart caddy
journalctl -u caddy -f          # watch the DNS-01 challenge complete
```

The first wildcard issuance takes a minute or two: Caddy writes a TXT record,
waits for it to propagate, and deletes it afterwards.

## 3. Resend

The code emails are the first half of sign-in, so this is not optional.

1. Add your domain in Resend, **Domains → Add Domain**.
2. Resend gives you three records. Add them in Cloudflare, all **DNS only**:

   | Type | Name | Purpose |
   |---|---|---|
   | TXT | `send` (or as given) | SPF |
   | TXT | `resend._domainkey` | DKIM |
   | MX | `send` | bounce handling |

3. Wait for Resend to mark the domain **verified**. Until it does, mail is
   accepted and silently dropped.
4. Optional but worth it: a DMARC record at `_dmarc`, starting at
   `v=DMARC1; p=none; rua=mailto:you@example.com`, so you can see what is being
   rejected before you tighten it.
5. Create an API key and put it in `.env` as `RESEND_API_KEY`. Set `MAIL_FROM`
   to an address on the verified domain.

Without `RESEND_API_KEY` the gateway prints the message it would have sent to
its own log instead of failing. That is what makes local development work — and
it means a deployment with a missing key looks healthy while nobody can sign
in. Check the log after the first code request.

## 4. The Bee node

Swarm stores the ciphertext and the sign-in page. The node needs two balances,
on Gnosis, in its **own** wallet — not the server's Sepolia deployer:

- **xDAI** for gas.
- **BZZ** for postage and retrieval. Sixteen decimals, not eighteen.

```
docker compose up -d bee
docker compose logs -f bee        # wait for "node is ready"
curl -s localhost:1633/addresses | jq .ethereum
curl -s localhost:1633/wallet
```

Send both to that Ethereum address. The admin panel shows the balances and will
do the sending from a browser wallet if you prefer.

Syncing takes a while on a fresh node, and uploads fail until it is ready.

### A postage batch

Postage is prepaid storage, priced from the chain's current rate, and a batch
has a depth (how much it can hold) and an amount (how long it lasts).

The admin panel buys one and records it, which is the easy path. By hand:

```
curl -s localhost:1633/chainstate | jq
# amount = blocks x currentPrice, and 17280 blocks is the minimum
curl -s -XPOST "localhost:1633/stamps/<amount>/17"
```

Depth 17 is enough for the sign-in page and a few hundred transfers. A batch
that runs out stops serving what it was paying for, so check the TTL
occasionally — `/api/health` reports it.

Set `POSTAGE_BATCH_ID` in `.env` only to reuse a batch you already own; a batch
bought in the admin panel is recorded in `.storage/config.json` and picked up
without a restart.

## 5. Fill in .env

Copy `.env.example` and work through it. The ones this guide produced:

```
PUBLIC_ORIGIN=https://example.com
PASSKEY_RP_ID=id.example.com
SIGNIN_DOMAIN=id.example.com
SIGNIN_ORIGINS=https://v1.id.example.com
SIGNIN_PAGE_URL=https://v1.id.example.com/
APP_ORIGINS=https://example.com,https://www.example.com
RESEND_API_KEY=...
MAIL_FROM=PineSign <noreply@example.com>
```

Generate the two HMAC keys rather than letting them be created on disk, so they
survive a lost machine:

```
openssl rand -hex 32   # PASSKEY_CHALLENGE_SECRET
openssl rand -hex 32   # EMAIL_HASH_KEY
```

Losing `EMAIL_HASH_KEY` makes every email hash already published on chain
unmatchable, and there is no recovering it from the hashes.

## 6. Publish the sign-in page

```
npm run publish-page
```

It builds the page, uploads it to Swarm as a collection with `index.html` as the
index document, and records the reference in `.storage/pages.json` under the
next version name. A published version is never repointed — a change becomes
v2 — because a version whose contents could change is a version whose name
means nothing.

The script prints the URL. Set `SIGNIN_PAGE_URL` and `SIGNIN_ORIGINS` to match
and rebuild, so the app opens the version you just published:

```
npm run build
systemctl restart pinesign      # or however the gateway is run
```

## 7. Admin setup, in the browser

```
https://example.com/setup.html?token=<printed in the gateway's log on boot>
```

The token is the only way in and is printed on every boot. Sign in with
MetaMask to claim the server, then work through: choose the parent name,
generate the deployer key, fund it, register the name, attach the resolver,
deploy the receipts contract, buy postage.

The deployer key is generated on the box and never leaves it. Back it up from
the panel — if the machine goes, the name goes with it.

## 8. Check it

```
curl -s https://example.com/api/health | jq
```

`configured` should be true, `signInPage` should name the version you published,
and `swarm.usable` should be true. Then walk `docs/TESTING.md`, which is the
part no automated suite can do for you.
