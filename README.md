# pocketful — a Purple-Team AI Dark Factory

A band of coding agents that builds a Venmo-style wallet/payments service and **attacks its own work** for double-spends and race conditions before accepting it. Built in BAND Desktop for the WeAreDevelopers x BAND "Dark Factory" hackathon (pocketful track).

## Repository layout
```
mandates/          the four generic seat mandates (Architect, Builder, Breaker, Verifier)
KICKOFF-BRIEF.md   the task pasted into the BAND room (all track-specific detail lives here)
FACTORY.md         how the factory works, its design, and measured results
stages/
  stage-1/ ... stage-4/   one complete, buildable service per completed stage
band-room-export/  the exported BAND Desktop room the band worked in (add before submitting)
```

## How to run the factory
1. Install **Claude Code** and **BAND Desktop**; complete BAND readiness (CLI + band-peer plugin), then restart Claude Code and Recheck.
2. Open **four Claude Code sessions**. Give each one the matching file in `mandates/` as its standing instruction, and run `/jam` in each to connect it to BAND.
3. Start the **Architect** session first ("Start a Band session as the architect"); it creates the room and invites the others.
4. Paste **KICKOFF-BRIEF.md** into the room. Let the band run the stages; step in only for a genuine product decision. Record the room for your submission video.

## Submission checklist
- [ ] `stage-1/` … (only the stages you completed), each builds and serves from a clean container with no network
- [ ] `mandates/` present and generic (no track-specific names — this is a disqualifier if violated)
- [ ] `FACTORY.md` filled in, including measured costs and a caught exploit
- [ ] `band-room-export/` included
- [ ] Video includes the BAND Desktop room recording + a walkthrough (no room recording = disqualified)
- [ ] Public GitHub repo a judge can clone

## License
MIT
