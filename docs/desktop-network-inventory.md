# Desktop network report rendering

The existing server-administrator network adapter page shows agent-reported DNS
servers and the DNS domain as visible, labeled text. IPv4/IPv6 strings, domain
names, markup-like text and long values are preserved with normal template
escaping. The table scrolls inside a keyboard-focusable region on narrow screens.
No DNS value is passed to an HTML tooltip or another markup interpreter.

The previous page escaped the tooltip attribute during server rendering, but the
bundled UI library subsequently interpreted its value as HTML. An owned browser
fixture reproduced this second interpretation: before showing the tooltip there
were no injected elements or executed marker; afterwards two synthetic elements
were present and their harmless error handler had run. The fixture used an inert
data URI and never read credentials or contacted a device or external service.

The regression renders the actual network adapter page and loads the repository's
production UI assets. Ordinary, injected, long and empty reports are checked at
390, 768 and 1440 pixels. Reported values remain literal readable text, no injected
elements or script marker appear, narrow tables remain reachable and the page
does not overflow. Before the layout correction, ordinary and long reports made
the 390-pixel page 810 pixels wide and the 768-pixel page 874 pixels wide. All twelve
network cases now pass, and the complete browser suite passes 333 cases. The
computer-view race tests also pass.

This change does not alter the route's server-administrator requirement or make
reports current observations. Scoped network inventory for delegated roles and
the remaining legacy detail/action authorization work are still part of SEC-01.
See [access control](access-control.md), [scoped desktop reports](desktop-console.md)
and the [implementation ledger](implementation-status.md).
