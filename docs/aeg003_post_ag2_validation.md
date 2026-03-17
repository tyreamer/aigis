# AEG003 Post-AG2 Fix Validation

## What Changed

Added file-level budget detection for AG2 standalone orchestration functions:
- `initiate_group_chat(max_rounds=N)`
- `a_initiate_group_chat(max_rounds=N)`
- `a_run_group_chat(max_rounds=N)`
- `run_group_chat(max_rounds=N)`

When these functions are called with a `max_rounds` or `max_turns` kwarg, Aigis now treats it as a file-level execution budget — applying the budget to all entry points in the same file.

## Impact

| Repo | Before | After | Delta |
|------|--------|-------|-------|
| build-with-ag2 | 129 | 36 | **-93** |
| All others | 701 | 701 | 0 |
| **Total** | **830** | **737** | **-93** |

The reduction is entirely in build-with-ag2, where `initiate_group_chat(max_rounds=N)` was the concentrated false positive pattern identified in the previous audit.

## Precision Improvement

Previous random-sample audit found 4/20 false positives, of which 3 were AG2 `initiate_group_chat` patterns. After this fix:

- 3 of 4 false positive types are now resolved
- Remaining FP type: AG2 `nested_chats` config dicts (arguable, not actionable)
- **Estimated precision: ~85-90%** (up from ~80%)

## Remaining AEG003 Ambiguity Clusters

1. **CrewAI Crew() without max_iter** (31 findings in crewAI-examples): Correct findings — CrewAI convention doesn't use `max_iter`, but the governance gap is real.

2. **OpenAI Agent() without max_turns** (136 in openai-agents-python, ~400 in agents): Correct findings — most `Runner.run()` calls genuinely lack `max_turns`.

3. **AG2 nested_chats budget** (~2 findings): Arguable — budget on nested conversation config, not the agent itself.

## Conclusion

The concentrated AG2 false positive cluster is resolved. AEG003 precision is now materially higher on the repo that had the worst noise. The remaining findings across all repos appear to be genuinely unbounded execution patterns.
