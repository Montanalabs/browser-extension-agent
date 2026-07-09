#! VULNERABLE browser-extension-agent — feeds the untrusted input straight to the tool, no extraction.
#! check -> UNSAFE: tainted data cannot reach a capability.
grant operate

let raw = fetch<web>
privileged { operate(raw) }  # tainted -> tool: REJECTED
