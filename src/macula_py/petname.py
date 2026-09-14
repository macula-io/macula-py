"""Petnames: a deterministic, human-readable label for a mesh node id —
Docker's adjective_color_animal convention with a four-digit suffix
(e.g. "happy_green_rabbit_4831"). A pure function of the node id
itself, not random per process: the same identity gets the same
petname across restarts, across every tool that shows it, and on every
other agent's roster too.

The suffix exists because the mesh is expected to host THOUSANDS of
agents: the word trio alone (64,000 combinations) collides visibly
under the birthday problem at a few hundred identities; the trio plus
a 4-digit hash group (640,000,000 combinations) stays effectively
collision-free at fleet scale while remaining scannable.

The word lists and derivation are shared verbatim with macula-mcp's
petname.ts, macula-rust's petname() and macula-go's identity.Petname:
same sha256 of the lowercased hex id, same 16-bit reads modulo the
list lengths, plus the suffix group.
"""

import hashlib

ADJECTIVES_A = [
    "bold", "bouncy", "brave", "breezy", "calm", "cheerful", "clever", "curious",
    "daring", "eager", "elegant", "fierce", "gentle", "graceful", "humble", "jolly",
    "jovial", "keen", "kind", "lively", "lucky", "mellow", "merry", "nimble",
    "noble", "plucky", "proud", "quiet", "quirky", "radiant", "silly", "sleepy",
    "spry", "sturdy", "tranquil", "upbeat", "vivid", "wise", "witty", "zealous",
]

ADJECTIVES_B = [
    "amber", "azure", "bronze", "coral", "crimson", "cyan", "emerald", "golden",
    "green", "indigo", "ivory", "jade", "lavender", "lilac", "magenta", "maroon",
    "mauve", "navy", "olive", "orange", "peach", "pink", "plum", "purple",
    "red", "rust", "ruby", "sage", "salmon", "scarlet", "sienna", "silver",
    "slate", "tan", "teal", "turquoise", "violet", "yellow", "blue", "copper",
]

NOUNS = [
    "antelope", "badger", "beetle", "bison", "cricket", "dolphin", "eagle", "elk",
    "falcon", "ferret", "flamingo", "fox", "gazelle", "gecko", "hare", "heron",
    "ibex", "iguana", "lynx", "marten", "mongoose", "moose", "narwhal", "orca",
    "otter", "owl", "panther", "pelican", "penguin", "rabbit", "raven", "salamander",
    "seal", "sparrow", "tiger", "toucan", "walrus", "weasel", "wolf", "wombat",
]


def petname(node_id: str) -> str:
    """The stable "adjective_color_animal_0000" label for a node id:
    same input, same output, on every tool and every machine."""
    digest = hashlib.sha256(node_id.lower().encode("utf-8")).digest()
    a = ADJECTIVES_A[int.from_bytes(digest[0:2], "big") % len(ADJECTIVES_A)]
    b = ADJECTIVES_B[int.from_bytes(digest[2:4], "big") % len(ADJECTIVES_B)]
    n = NOUNS[int.from_bytes(digest[4:6], "big") % len(NOUNS)]
    suffix = int.from_bytes(digest[6:8], "big") % 10_000
    return f"{a}_{b}_{n}_{suffix:04d}"
