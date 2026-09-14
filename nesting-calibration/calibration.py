"""The shared nesting calibration shapes."""


def flat(x):
    """S1: no control structure."""
    return x + 1


def one_branch(x):
    """S2: one control structure."""
    if x == 0:
        return "zero"
    return "other"


def branch_in_branch(x, y):
    """S3: a control structure inside one."""
    if x == 0:
        if y == 0:
            return "both"
        return "first_only"
    return "neither"


def three_deep(x, y, z):
    """S4: three control structures deep."""
    if x == 0:
        if y == 0:
            if z == 0:
                return "all"
            return "two"
        return "one"
    return "none"


def closure_in_body(xs):
    """S5: a closure in the function body."""
    return list(map(lambda x: x + 1, xs))


def closure_in_branch(xs):
    """S6: a closure inside a branch."""
    if xs:
        return list(map(lambda x: x + 1, xs))
    return []


def branch_in_closure(xs):
    """S7: a control structure inside a closure."""

    def label(x):
        if x == 0:
            return "zero"
        return "other"

    return [label(x) for x in xs]
