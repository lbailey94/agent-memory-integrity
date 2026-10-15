# Adding a row

CONTRIBUTING.md gives the rules a row has to satisfy. This is the practical
path: what to answer before any code is written, what to write, and how to
know it is right.

Four rows so far have come in from outside, and the same questions came up
every time. They are here so nobody has to be asked them twice.

---

## Step 1. Answer five questions first

Every row rests on these. Answer them in the issue or the PR description
before writing an adapter, because the answers decide what the row measures
and a row that measures the wrong thing is worse than no row.

**1. What exactly is the store?**

Name the thing on disk, in the database or behind the API that holds the
memories. Not the product, the store. "The G7 directory, one signed envelope
per authorization record." "A zlib-compressed JSON container under one HMAC."
"The event plane of a managed service, reached through its data-plane API."

**2. What is one record?**

The unit the nine edits apply to. A row of a table, a file, a stored token, an
entry in a log. If a container holds many records, say whether a record is the
container or the thing inside it. This is the question that most often has two
defensible answers; pick the one the library itself draws a boundary around,
because that is the boundary its own checks defend.

**3. Where does the attacker stand?**

What they can read and write, and what they cannot. "Reads and writes the
store directory, holds no key." "Holds the data-plane permissions outside the
agent's session." A row speaks only for the attacker it names; a different
attacker is a different row.

**4. What is the read path?**

The call an agent actually makes to get its memory back before acting, and
whether a fresh process is involved. Not an audit command, not a verify
helper, unless that is genuinely what runs before every use. If detection
happens only in a separate audit the operator has to run, say so: that is a
real answer and the scorecard records it as a different detection point.

**5. What exactly do we pin?**

The version and the commit, plus the runtime if it matters (Node 22, Python
3.12). The row is measured at that point and the test fails the day behaviour
changes. If the package is not on a public index, say where the checkout comes
from and the row will be gated behind an environment variable.

**A sixth, if the tool has configurations**

If a deployment choice changes the answer, that is two rows, not one. Say
which configuration ships by default, because the default row always stands
on its own. Recallspection is the example: the same store, the anchor on or
off the same disk, identical on eight edits and opposite on the ninth.

---

## Step 2. Write the adapter

Copy `agmi/adapters/_template.py` and work through it. It implements the whole
`MemoryAdapter` contract with a comment on every method explaining what it is
for and what gets it wrong.

The three that decide whether a row is honest:

- `verify()` returns what the **tool** says, never what the adapter thinks.
  If the tool loads the tampered store without complaint, that is an accepted
  cell, however obvious the tampering looks from outside.
- `owner_of()` derives the context from where the record actually sits, not
  from a field inside the record. An attacker who can write records can write
  that field too, so trusting it would let a moved record look at home.
- `delete_raw()` raises when there is nothing at that position. Silently doing
  nothing turns a failed attack into a passing one.

## Step 3. Run it and look at the nine lines

```
PYTHONPATH=. python -c "
from agmi.adapters.your_store import YourAdapter
from agmi.attacks.at_rest import AT_REST_ATTACKS_WITH_SNAPSHOT as X
for c in X:
    r = c().run(YourAdapter())
    print(f'{r.attack:20} {r.status:11} {(r.guard or r.detail or r.error or \"\")[:90]}')
"
```

Read every line before going further.

`error` with a guard message means the edit did not land the way the attack
intended, and the suite refuses to score it. That is the control doing its
job and it is almost always the adapter, not the store. The usual causes:
both contexts seeded with the same values, so a crossed record cannot be told
from a coincidence; a position index stored inside the record, so deleting one
record looks like every later record changing; an edit written to a key that
the read path never looks at.

`n/a` means the edit cannot apply to this store. That is a real result and the
cell must carry its own reason in the tool's own terms, never a blank. "No
update call exists in the API." "A record is plain text with no metadata field
to change."

## Step 4. Pin it in a test

Add `tests/test_your_store.py` asserting the verdicts you just saw, and the
version and commit from question five. The point is not coverage. The point is
that the day the library changes its behaviour, the test fails and you
re-measure instead of publishing a stale cell.

If the store needs a checkout or credentials that CI will not have, skip the
module when the environment variable is missing, as the Recallspection and HDP
tests do.

## Step 5. Register the row

- `agmi/full_runner.py`, so a full pass includes it
- `agmi/agent/at_rest_hunt.py`, so the agent can target it by name
- `CHANGELOG.md`, with what the row measured and what it means

## Step 6. Open the PR

Include the nine-line print from step 3, the five answers from step 1, and the
exact commands you ran. A reviewer should be able to repeat your run without
asking you anything.

Expect to be asked to change something. Every row so far, including the ones
written by the maintainer of agmi, has been through at least one round where
the adapter was doing the store's job for it.

---

## What happens next

The row is reproduced independently before it lands. A row submitted by a
tool's own maintainer is marked as such on the scorecard and the accepted
cells are left exactly as measured.

Before the row is published, the row text and the page copy go to whoever
submitted it, for a check on the facts: the description of their own system,
the attacker scope, the mechanisms named. Not for approval of the verdicts.
Those are the measurement.
