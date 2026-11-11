# Tap Proof

A checkout button can look fine while a transparent element intercepts taps at just a few widths. Tap Proof measures who receives the center hit at each integer CSS viewport width, identifies the blocking element, and saves screenshots at the boundaries. After a fix, replay the same check by ID.

**0.1.0 · Local Windows Hermes backend · Hermes 0.23.1+ · [MIT](LICENSE)**

## Install

Install Node.js 20 or newer, with Node and npm on PATH, and Microsoft Edge. From a public release or the Hermes catalog, install into the profile where you want to run the tool.

```powershell
hermes plugins install https://github.com/ladyFaye1998/hermes-tap-proof --enable
# Once listed, the equivalent catalog command is:
# hermes plugins install tap-proof --enable
```

From a committed local checkout, run this from the checkout root.

```powershell
$tapProofSource = ([Uri]((Resolve-Path .).Path)).AbsoluteUri
hermes plugins install $tapProofSource --enable
```

Before the first run, install the locked browser dependency in the **installed plugin copy**. For the default Windows profile:

```powershell
$tapProofHome = if ($env:HERMES_HOME) { $env:HERMES_HOME } else { Join-Path $env:LOCALAPPDATA 'hermes' }
npm.cmd ci --prefix (Join-Path $tapProofHome 'plugins/tap-proof/browser')
```

For a named profile, use that profile's Hermes home, typically `%LOCALAPPDATA%\hermes\profiles\<name>`, and pass `-p <name>` to Hermes. Run the dependency step again if a plugin update replaces the installed copy. Start a new Hermes chat after enabling it. If that profile previously disabled the Tap Proof toolset, re-enable it with `hermes tools`.

## Scan and replay

Serve your own page over HTTP on `127.0.0.1`, `localhost`, or `[::1]` and include the port explicitly in the URL. Ask Hermes to call `tap_proof` with a selector that identifies one element.

```json
{
  "mode": "scan",
  "url": "http://127.0.0.1:8765/checkout.html",
  "selector": "#place-order",
  "min_width": 700,
  "max_width": 780,
  "height": 760
}
```

Width endpoints are inclusive. Scan at most 800 widths per check. Height defaults to 760 CSS pixels and stays fixed across the sweep. For a page that renders asynchronously, set `ready_selector` to an element that becomes visible when the state is ready.

Fix the page at the same URL and ask Hermes to replay the saved `check_id`.

```json
{"mode": "replay", "check_id": "<check_id from scan>"}
```

Replay compares the baseline and current verdict at each width. For matching witness widths, it compares SHA-256 hashes and reports whether the PNG bytes match.

Tap Proof measures the rendered DOM and the receiver at the target's center. A covered center is reported with the blocker and width band. An absent, ambiguous, or otherwise unmeasurable target is inconclusive. The probe does not send clicks, scroll the target into view, exercise handlers, or follow a user journey.

## Try the fixtures

From the checkout root, serve the fictional examples.

```powershell
python -m http.server 8765 --bind 127.0.0.1 --directory examples
```

The checkout example is visibly unchanged across the sweep, but its center hit is blocked from **721 through 759 CSS pixels**. The second example has two separate blocked bands. The [fixture guide](examples/README.md) gives both selectors and a same-URL fix for replay.

## Data and runtime

Each check runs a bounded Node subprocess and launches headless Microsoft Edge in a fresh browser context. The probe serves page traffic through same-origin loopback HTTP GET and HEAD requests and refuses redirects, cross-origin requests, and other HTTP methods. Use a local development page whose resources are available on that origin. The probe uses no browser login or stored browser profile.

Receipts and witness PNGs are written under the active Hermes profile's plugin data directory. The tool returns the receipt and witness paths for each successful run. These files can contain local URLs, selectors, rendered page content, and observed element details. Tap Proof makes no model calls or telemetry requests. Normal Hermes chat uses its configured model. The manual npm setup fetches the locked Playwright Core dependency, which drives the installed Edge browser.

## Validate

```powershell
node --check browser/probe.cjs
hermes plugins validate . --install-deps
```
