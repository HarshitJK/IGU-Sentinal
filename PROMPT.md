Read CLAUDE.md in full.

Run `git log -1 --stat` to see the last commit and what it touched.

Read TASKS.md. Find the first unchecked `- [ ]` item, in order — do not skip ahead even if a later task looks easier.

Do that one task only:
1. Write the test(s) for it first, against the fixtures/contracts defined in CLAUDE.md.
2. Implement the minimum code needed to pass those tests.
3. Run the tests. If they fail, fix the implementation, not the test, unless the test itself is wrong per CLAUDE.md's contracts.
4. Only once tests pass, check the box for this task in TASKS.md (change `- [ ]` to `- [x]`).
5. Commit with a message naming exactly which task was completed.

If every task in TASKS.md is already checked, do nothing and state that the task list is complete.

Do not work on more than one task this pass. Do not add new files, modules, or abstractions beyond what CLAUDE.md specifies — if you think something's missing, add a note under "## Open questions" at the bottom of CLAUDE.md instead of improvising.
