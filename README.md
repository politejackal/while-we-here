# While We Here

A chat room that only exists while someone is in it.

One person creates a room and gets a code like `KX7M-42QA`. They pick how many people the room holds (2 to 6, or any custom number, including them), and anyone with the code can take an open seat. The chat survives people coming and going as long as at least one person stays. When the room is empty, it's gone: the messages, the code, and any sign it existed.

## Run it

```bash
npm install
npm start
```

Then open http://localhost:3000. Set `PORT` to change the port, `MAX_ROOM_SIZE` to change the largest custom room (default 50), `REPO_URL` to show a "Source code" link in the footer, and `TRUST_PROXY=1` if you're behind a reverse proxy (so guess limits use the real client address).

## Where the chat lives

Not on the server. Messages exist only in the memory of the browsers in the room.

- Several people in the room: every browser holds the conversation.
- People leave: the browsers still inside keep it. With one left, that browser holds the only copy.
- Someone joins: the person who has been inside longest sends them the history, encrypted.
- The last browser closes: the only copy goes with it.

The server is a matchmaker and a relay. It never stores anything to disk and has no request logging.

| The server knows | The server never sees |
| --- | --- |
| A room ID: a slow hash (PBKDF2, 150k rounds) of the code, made in the browser | The code itself |
| How many people are in a room, and its size | Any message (end-to-end encrypted) |
| Whether the room is locked / shares history | Names, accounts, cookies |

## Encryption

- The browser derives two values from the code: the **room ID** (sent to the server) and a **code secret** (never leaves the browser).
- Each page load makes a fresh ECDH P-256 key pair. Every pair of people in the room agrees its own session key with ECDH, then HKDF salted with the code secret, giving an AES-256-GCM key.
- Because the server doesn't have the code secret, it can't man-in-the-middle the key exchange. If it tried, every message would fail to decrypt, and the room shows a warning.
- Each sealed message is bound to its sender's public key, so the relay can't bounce your own messages back at you.
- **Length hiding.** Before encryption, every payload is padded with spaces to a fixed bucket (512 B, 1 KB, 2 KB, ... then 64 KB steps). "ok" and a paragraph produce the same ciphertext size. WebSocket compression is turned off, since compressed sizes leak hints too.

## Anonymity

The site says "Anonymous by design", and here is exactly what that means:

- **No identity.** No accounts, names, phone numbers, emails, cookies, analytics or third-party requests (fonts are self-hosted; the CSP allows only this origin). Each visit gets a new random ID.
- **IP hidden from the room.** See below.
- **No logs.** The server writes nothing to disk. It necessarily sees a connected client's IP in order to reply; the only derived value it keeps is a salted hash for guess limiting, in memory, for at most 10 minutes.
- **IP hidden from us, optionally.** The site works in Tor Browser, because it never uses WebRTC (which Tor blocks). Over Tor, the server never learns the user's real IP.

What it deliberately does *not* claim: that use of the site is invisible to a user's ISP or network, or that the server never sees IPs when Tor isn't used.

## IP privacy

Encrypted traffic always goes through the server's relay. Browsers never connect to each other directly, so nobody learns anyone else's IP address. (This works like a TURN relay in WebRTC: the relay only forwards ciphertext. Swapping in WebRTC data channels with a relay-only TURN server is a possible future change. The privacy properties are the same.)

## Design choices

- **Room size.** Picked by the creator from presets or a custom number (2 up to `MAX_ROOM_SIZE`), fixed for the life of the room. Messages are encrypted separately for each person. In rooms bigger than two, each person's messages get a colored dot (derived from an anonymous per-visit ID) so you can tell people apart without names.

- **History for new joiners.** Always shared in 2-person rooms (the choice isn't shown). In bigger rooms it's on by default. Any person in the room can turn it off ("fresh start"), and then new joiners see only what's said after they arrive. This is enforced by the browser that holds the history, since the server never has it.
- **Codes.** 8 characters from a 31-character alphabet with no look-alikes (no 0/O, 1/I/L): about 850 billion combinations. Each client gets 8 wrong guesses per 10 minutes. Guess counters are keyed by a salted hash of the address; the salt is random, lives in memory only, and rotates every window.
- **Lock.** Anyone in the room can lock it. Nobody new can take an open seat, even with the code.
- **Refresh grace.** If the last person refreshes, the room is held for 10 seconds for that same tab only (via a random rejoin token). While the page reloads, the conversation is parked in `sessionStorage` and deleted the instant the page comes back. Closing the tab discards it. Leaving on purpose destroys the room immediately.
- **No timestamps.** Only "just now" and "earlier". No typing indicators, no read receipts.
- **One number.** The homepage counter of rooms that vanished today (resets at midnight UTC) is the only thing the server counts.
- **No third parties.** Fonts (Google Sans, Material Symbols) are self-hosted, so loading the page doesn't contact Google or anyone else. The Content-Security-Policy only allows this origin.

## Honest limits

- **Screenshots.** The promise is "this site keeps no record," not "nobody can ever keep anything."
- **A malicious server could serve different JavaScript.** Open source lets people audit the code; it doesn't prove what a given server runs. Self-hosting is the strongest guarantee.
- **Anyone with the code is in.** The code is the key. Share it the way you'd share a key.
- **Abuse.** With zero records, there's nothing to investigate. Rooms need a code, and any room can be locked.
- **Local law.** Anonymous messaging is regulated in many places, including Saudi Arabia. Check before launching publicly.

## Files

- `server.js`: matchmaking, relay, guess limits, static files. About 200 lines, no database.
- `public/app.js`: everything that touches messages: codes, key derivation, encryption, history handoff.
- `public/index.html`, `public/styles.css`: Material Design 3 interface, light and dark.

## Deploying

The page and the relay are hosted separately:

- **Page:** GitHub Pages, served from the `gh-pages` branch (a copy of `public/`). Publish updates with:
  `git subtree push --prefix public origin gh-pages`
- **Relay:** Render, from `render.yaml`. In Render: **New → Blueprint**, pick this repo, deploy. It runs `npm start` on the free plan with `TRUST_PROXY=1`.

`public/config.js` points pages served from `github.io` at the relay (`https://while-we-here.onrender.com`). If Render gives the service a different URL, change it there **and** in the Content-Security-Policy meta tag in `public/index.html`.

The Render URL also serves the full site on its own. Free Render instances sleep when idle, so the first visit after a quiet spell can take ~30 seconds to connect. A sleeping or restarted relay ends every open room. That fits the design, but it's worth knowing.
