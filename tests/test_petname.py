from macula_py.petname import petname


def test_petname_deterministic_and_shaped():
    nid = "7374b0cfab4eea68e271c3815a0f78e21e913397f67345f337ddba7a3a88ab3a"
    first = petname(nid)
    assert petname(nid) == first
    parts = first.split("_")
    assert len(parts) == 4
    assert len(parts[3]) == 4
    assert parts[3].isdigit()


def test_petname_matches_reference():
    # Shared fixtures across the SDKs: one label everywhere. The second
    # is proven against the live roster (gentle_maroon_flamingo before
    # the suffix shipped).
    assert (
        petname("7374b0cfab4eea68e271c3815a0f78e21e913397f67345f337ddba7a3a88ab3a")
        == "calm_navy_narwhal_3381"
    )
    assert (
        petname("d4b24382f4e033ad9e895070c914c8125c315f243c5a3713183352f65c322b03")
        == "gentle_maroon_flamingo_3490"
    )
