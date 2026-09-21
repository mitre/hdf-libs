# Subagent definitions

Each file here defines a named subagent: what it is for, which tools it may use,
and which model it runs on. The point of naming them is cost — most delegated
work in this repo is bounded retrieval or mechanical assembly that a smaller
model does just as well, and only some of it needs the expensive one.

## Which model, and why

The dividing line is **not** difficulty. It is whether a wrong answer gets
caught.

- **Sonnet** — a wrong answer is obvious the moment the report is read: counts,
  file lists, hash comparisons, "which card covers this issue". If the work is
  *measure and tabulate*, the numbers either reconcile or they don't.
- **Opus** — a wrong answer would be believed and written into a card, a commit
  or an ADR. Anything that must push back on the brief it was given belongs
  here. In practice the most valuable subagent output in this repo has been a
  correction: *"no single field discriminates everywhere — I measured five"*,
  *"that converter's id minting never actually fires"*, *"the fidelity guard
  blocks this whole epic"*. Each overturned an instruction that was wrong.

So: if the task is to *find out*, Sonnet. If the task is to *decide*, *review*,
*implement*, or *write something durable from claims it must verify first*,
Opus.

## Using them

Pass the name as `subagent_type`. Override the model per call only with a
reason — a `carder` handed a brief whose claims are already verified can run on
Sonnet; an `inventory` sweep whose result will be quoted in an ADR should not.
