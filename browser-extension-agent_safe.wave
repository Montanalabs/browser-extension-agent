#! Browser-extension agent — untrusted the page DOM can only ever become one of a fixed set of decisions over a
#! closed type, never a tool argument. An injected instruction cannot be represented in the
#! closed type, so it is rejected at the trust boundary (and re-clamped at run time by extract).
#! @requires operate — the browser-extension agent sink
#! @effect io
#! @taint bridge — extract<Action> turns the tainted input into a trusted decision
grant operate

type Target = Submit | Cancel | Next
type Action = Click(Target) | Fill | Abort

let raw = fetch<web>  # UNTRUSTED the page DOM — tainted
quarantined { let d = extract<Action>(raw) }  # only a fixed Action (payloads too) crosses
privileged { operate(d) }  # act on the trusted decision only
