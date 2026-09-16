"""The messaging layer — the message store, its folders and its messages.

`store` (P07) is the entry point: `Store.open(path)` reads the header, the
two B-trees and the property context of `NID_MESSAGE_STORE` (0x21), and
gives the display name, the store's record key and the entry ids of the
IPM subtree, the wastebasket and the finder. `named_prop` (P07) reads
`NID_NAME_TO_ID_MAP` (0x61), which translates the 0x8000+ property ids
into (GUID, name-or-number) pairs — without it a reader silently cannot
see any Outlook-specific property.

`folder` (P08) and `message`/`attachment` (P09) are not built yet.
"""
