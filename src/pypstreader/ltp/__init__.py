"""Lists, Tables and Properties — the layer between raw node data and MAPI.

`prop_type` (P22) is the leaf: the property type codes and one pure decoder
per type. `heap` (P04) lays the Heap-on-Node over a node's blocks and `tree`
(P04) the BTree-on-Heap over that; `prop_context` and `table_context` build
on those and feed `prop_type`.
"""
