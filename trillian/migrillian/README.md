Migrillian Tool
===============

*Migrillian* is a tool that transfers data from Certificate Transparency logs to
Trillian *PREORDERED_LOG* trees.

It can be used for:
 - One-off data migrations, e.g. from legacy CT implementation to the new
   Trillian-based solution which is this repository.
 - Continuous migration for keeping the copy up-to-date with the remote log,
   i.e. log mirroring.

TODO(pavelkalinnikov):
 - Factor out transport guts to make it pluggable.
 - Use config files to create a multi-tenant set up.
 - Distributed version with master election, master does all work for one tree.
 - Store CT STHs in Trillian or make this tool stateful on its own.
 - Make fetching stateful to reduce master resigning aftermath.
 - Distributed fetch scheduling for a tree to increase throughput.
