# Timing evidence for the pre-registration

This file records when the pre-registration was fixed, using GitHub's own
records, so that the timing can be checked independently of the local clock.
The raw API responses are saved under `docs/timing/`.

## 1. Pre-registration commit

| | |
|---|---|
| Commit SHA | `3499fcb9219f502defd964b7c854625f9a713599` |
| Message | `Pre-registration: question, parsers, corpus, classification rules, predictions` |
| Author | Rahul Chaudhary <raahulchaudhary07@gmail.com>, **2026-10-17T08:44:16Z** |
| Committer | Rahul Chaudhary <raahulchaudhary07@gmail.com>, **2026-10-17T08:44:16Z** |

Source: `gh api repos/raahulkurmi/parser-differential-pilot/commits/3499fcb9219f502defd964b7c854625f9a713599`.

Author and committer dates are set on the local machine. On their own they do
not prove when the commit existed. The push record in section 2 is GitHub's
server-side timestamp.

## 2. Push record (`/activity` endpoint)

| | |
|---|---|
| Activity id | `46803640140` |
| Type | `branch_creation` |
| Ref | `refs/heads/main` |
| before → after | `0000000000000000000000000000000000000000` → `3499fcb9219f502defd964b7c854625f9a713599` |
| Actor | `raahulkurmi` (user id 132373350) |
| Timestamp | **2026-10-17T08:57:22Z** |

Raw response: [`docs/timing/activity.json`](timing/activity.json), from
`gh api repos/raahulkurmi/parser-differential-pilot/activity`, retrieved
2026-10-17T09:12:32Z. When it was retrieved, it held exactly this one entry.

## 3. Repository record (`/repos` endpoint)

| | |
|---|---|
| Repository id | `1423133702` |
| created_at | **2026-10-17T08:57:17Z** |
| pushed_at | **2026-10-17T08:57:22Z** |
| private | `true` |

Raw response: [`docs/timing/repo.json`](timing/repo.json), from
`gh api repos/raahulkurmi/parser-differential-pilot`, retrieved
2026-10-17T09:12:32Z. `pushed_at` is a live field, and pushing this file moves
it forward. The saved snapshot shows its value before this file was pushed.
The `temp_clone_token` value in this snapshot was redacted to `<redacted>` after the fact
(2026-10-23); it was a short-lived clone token from when the repository was private and had
expired. No other field was changed.

## 4. Events endpoint

`gh api repos/raahulkurmi/parser-differential-pilot/events` returned an empty
list `[]` right after the push (about 2026-10-17T08:57Z). It was queried again
at 2026-10-17T09:12:32Z and was **still empty**, so no `docs/timing/events.json`
is saved. GitHub fills the events feed with a delay and does not guarantee to
fill it at all. The `/activity` record in section 2 is the push evidence used
here.

## 5. Tie to the frozen corpus

SHA-256 of `corpus/SHA256SUMS` (the hash list covering all 137 payloads, all
137 tokens and `MANIFEST.csv`):

`11ea1ce31135e20ff31119a8f1c74dde10d8f3a09c5fd6254521a954e71247c9`

This value matches Appendix A of `docs/PREREGISTRATION.md` and the file as
committed in `3499fcb9219f502defd964b7c854625f9a713599`. Corpus v1 is unchanged
since that commit.

## 6. Data-collection status

When this file was written, no harness had been run on the corpus.
`results/raw/` holds only `.gitkeep`.
