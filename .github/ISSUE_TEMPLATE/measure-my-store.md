---
name: Measure my store
about: Ask for a row, or offer one you have measured yourself
title: "Row request: "
labels: row-request
---

Answer these five before any code. They decide what the row measures, and a
row that measures the wrong thing is worse than no row. There is more on each
in docs/adding-a-row.md.

**1. What exactly is the store?**
The thing that holds the memories: the file, the table, the directory, the
API surface. Not the product, the store.

**2. What is one record?**
The unit the nine edits apply to. If a container holds many records, say
whether a record is the container or the thing inside it.

**3. Where does the attacker stand?**
What they can read and write, and what they cannot. A row speaks only for the
attacker it names.

**4. What is the read path?**
The call an agent makes to get its memory back before acting, and whether a
fresh process is involved. If detection only happens in a separate audit the
operator runs, say so. That is a real answer and the scorecard records it.

**5. What exactly do we pin?**
Version, commit, and the runtime if it matters. If the package is not on a
public index, say where the checkout comes from.

**If a deployment choice changes the answer**
Say which configuration ships by default. A choice that changes the result is
two rows, and the default row always stands on its own.

---

**Have you measured it yourself?**
If so, paste the nine-line print and the commands you ran. The row is still
reproduced independently before it lands, and it will be marked as submitted
by the tool's maintainer.

**Anything that looks like a live vulnerability** goes to the maintainers
privately first, not here. See SECURITY.md.
