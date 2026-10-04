#!/bin/zsh
# Double-click for the judge demo: the single-user workspace, no sign-in.
# The multi-analyst workspace (sign-in, dispositions, two-person sign-off) is "Start Shockwave.command".
export SHOCKWAVE_MULTI=0
exec "${0:A:h}/Start Shockwave.command" "$@"
