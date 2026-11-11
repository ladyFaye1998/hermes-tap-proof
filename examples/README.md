# Tap Proof fixtures

These self-contained pages use fictional products and make no external requests. Their buttons only update an on-page status and increment their `data-click-count` attribute.

Serve the folder locally with `python -m http.server 8765 --bind 127.0.0.1 --directory examples` from the repository root.

| Route | Target | Blocker | Blocked CSS viewport widths |
| --- | --- | --- | --- |
| `/checkout.html` | `#place-order` | `#delivery-hit-area`, an absolutely positioned transparent element | 721–759 px |
| `/preset-library.html` | `#download-pack` | `#preview-controls::after`, a transparent pseudo-element | 641–659 px and 801–819 px |

Ranges include both endpoints. Chromium reports the pseudo-element's originating element, `#preview-controls`, as the hit-test result. Check a width just outside each endpoint to confirm the boundary.

Append `?fixed=1` to either route to apply the fix. The page sets `data-fixed` on the document element before rendering and CSS disables pointer events on the blocker. This preserves the visible layout and does not change the target's handler.

For a replay at the identical URL, serve a copy of this folder and insert the matching line immediately before `</style>` in the served copy, then replay without adding a query parameter.

- `checkout.html`: `#delivery-hit-area { pointer-events: none; }`
- `preset-library.html`: `#preview-controls::after { pointer-events: none; }`
