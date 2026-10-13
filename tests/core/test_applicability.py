"""Applicability: three-valued evaluation of expression trees.

Every expected value comes from docs/explanation/architecture.md, section 5. The truth tables
below are written by hand from the Kleene rules that the section states.
"""

from __future__ import annotations

import itertools
import operator
from collections.abc import Callable, Sequence
from datetime import date
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from dppce.applicability import ApplicabilityError, evaluate, fact_paths, facts_from
from dppce.models import All, AnyOf, Compare, Const, Expr, Not, Op, Tri
from tests.core import builders as b

T, F, U = Tri.TRUE, Tri.FALSE, Tri.UNKNOWN

# Section 5: "`all` is Kleene conjunction: false wins, then unknown, then true."
ALL_TABLE = {
    (T, T): T,
    (T, F): F,
    (T, U): U,
    (F, T): F,
    (F, F): F,
    (F, U): F,
    (U, T): U,
    (U, F): F,
    (U, U): U,
}
# Section 5: "`any` is Kleene disjunction: true wins, then unknown, then false."
ANY_TABLE = {
    (T, T): T,
    (T, F): T,
    (T, U): T,
    (F, T): T,
    (F, F): F,
    (F, U): U,
    (U, T): T,
    (U, F): U,
    (U, U): U,
}
# Section 5: "`not unknown` is unknown."
NOT_TABLE = {T: F, F: T, U: U}

PROPERTY = settings(max_examples=200, deadline=None, derandomize=True)


def const(value: Tri) -> Const:
    return Const(const=value)


def compare(fact: str, op: str, value: Any) -> Compare:
    return Compare.model_validate({"fact": fact, "op": op, "value": value})


def negate(expr: Expr) -> Not:
    return Not(operand=expr)


def value_of(expr: Expr, facts: dict[str, Any] | None = None) -> Tri:
    return evaluate(expr, facts or {}).value


def from_fact(value: Tri) -> tuple[Compare, dict[str, Any]]:
    """An operand whose outcome comes from a declared fact. Unknown is a fact that is missing."""
    facts: dict[str, Any] = {"ics": {} if value is U else {"flag": value is T}}
    return compare("ics.flag", "eq", True), facts


# --- Kleene truth tables -----------------------------------------------------------------


@pytest.mark.parametrize(("operands", "expected"), list(ALL_TABLE.items()))
def test_all_follows_the_kleene_table_for_all_nine_pairs(operands: tuple[Tri, Tri], expected: Tri) -> None:
    assert value_of(All(all=tuple(const(v) for v in operands))) is expected


@pytest.mark.parametrize(("operands", "expected"), list(ANY_TABLE.items()))
def test_any_follows_the_kleene_table_for_all_nine_pairs(operands: tuple[Tri, Tri], expected: Tri) -> None:
    assert value_of(AnyOf(any=tuple(const(v) for v in operands))) is expected


@pytest.mark.parametrize(("operand", "expected"), list(NOT_TABLE.items()))
def test_not_follows_the_table_for_all_three_values(operand: Tri, expected: Tri) -> None:
    assert value_of(negate(const(operand))) is expected


@pytest.mark.parametrize(("left", "right"), list(itertools.product(Tri, repeat=2)))
def test_the_tables_hold_when_the_operands_come_from_facts(left: Tri, right: Tri) -> None:
    # The right operand is a constant, so that the two operands can differ on one fact.
    node, facts = from_fact(left)
    assert value_of(All(all=(node, const(right))), facts) is ALL_TABLE[left, right]
    assert value_of(AnyOf(any=(node, const(right))), facts) is ANY_TABLE[left, right]
    assert value_of(negate(node), facts) is NOT_TABLE[left]


def kleene_all(values: Sequence[Tri]) -> Tri:
    return F if F in values else U if U in values else T


def kleene_any(values: Sequence[Tri]) -> Tri:
    return T if T in values else U if U in values else F


@pytest.mark.parametrize("size", [1, 3, 4])
def test_all_and_any_take_any_number_of_operands(size: int) -> None:
    for values in itertools.product(Tri, repeat=size):
        parts = tuple(const(v) for v in values)
        assert value_of(All(all=parts)) is kleene_all(values), values
        assert value_of(AnyOf(any=parts)) is kleene_any(values), values


def test_evaluation_gives_a_readable_reason_for_each_node_shape() -> None:
    facts = {"ics": {"flag": True}}
    leaf = compare("ics.flag", "eq", True)
    for expr in (const(T), leaf, negate(leaf), All(all=(leaf, const(U))), AnyOf(any=(leaf, const(F)))):
        assert evaluate(expr, facts).reason.strip(), expr


# --- Missing information -----------------------------------------------------------------

WELL_TYPED_OPERANDS = {
    "eq": 5,
    "ne": 5,
    "gt": 5,
    "ge": 5,
    "lt": 5,
    "le": 5,
    "in": [5, 6],
    "not_in": [5, 6],
    "contains": "a",
}


@pytest.mark.parametrize("op", [o.value for o in Op])
@pytest.mark.parametrize(
    "facts",
    [{}, {"ics": {}}, {"ics": {"other": 5}}, {"ics": {"x": "unknown"}}, {"profile": {"x": 5}}],
    ids=["no-facts", "empty-ics", "other-fact", "value-unknown", "other-root"],
)
def test_a_missing_fact_and_the_value_unknown_give_unknown(op: str, facts: dict[str, Any]) -> None:
    assert WELL_TYPED_OPERANDS.keys() == {o.value for o in Op}
    assert value_of(compare("ics.x", op, WELL_TYPED_OPERANDS[op]), facts) is U


def test_a_path_below_a_scalar_fact_is_a_missing_fact() -> None:
    assert value_of(compare("ics.x.deeper", "eq", 5), {"ics": {"x": 5}}) is U


def test_missing_information_never_becomes_false() -> None:
    missing = compare("ics.x", "eq", 5)
    assert value_of(missing) is U
    assert value_of(negate(missing)) is U, "the negation of unknown is not true and not false"
    assert value_of(All(all=(const(T), missing))) is U
    assert value_of(AnyOf(any=(const(F), missing))) is U
    assert value_of(negate(AnyOf(any=(missing, compare("ics.y", "ne", 5))))) is U


def test_a_known_decisive_operand_still_decides_next_to_a_missing_fact() -> None:
    missing = compare("ics.x", "eq", 5)
    assert value_of(All(all=(missing, const(F)))) is F
    assert value_of(AnyOf(any=(missing, const(T)))) is T


# --- Operators ---------------------------------------------------------------------------

ORDERING_CASES = [
    # (fact value, operator, operand, expected) at and around the boundary
    (5, "gt", 4, T),
    (5, "gt", 5, F),
    (5, "gt", 6, F),
    (5, "ge", 4, T),
    (5, "ge", 5, T),
    (5, "ge", 6, F),
    (5, "lt", 6, T),
    (5, "lt", 5, F),
    (5, "lt", 4, F),
    (5, "le", 6, T),
    (5, "le", 5, T),
    (5, "le", 4, F),
    (-1, "lt", 0, T),
    (0, "gt", -1, T),
    (10, "gt", 9, T),  # numeric order, not text order
    ("2027-02-18", "gt", "2027-02-17", T),
    ("2027-02-18", "gt", "2027-02-18", F),
    ("2027-02-18", "gt", "2027-02-19", F),
    ("2027-02-18", "ge", "2027-02-17", T),
    ("2027-02-18", "ge", "2027-02-18", T),
    ("2027-02-18", "ge", "2027-02-19", F),
    ("2027-02-18", "lt", "2027-02-19", T),
    ("2027-02-18", "lt", "2027-02-18", F),
    ("2027-02-18", "lt", "2027-02-17", F),
    ("2027-02-18", "le", "2027-02-19", T),
    ("2027-02-18", "le", "2027-02-18", T),
    ("2027-02-18", "le", "2027-02-17", F),
    ("2026-12-31", "lt", "2027-01-01", T),
    ("2028-02-29", "lt", "2028-03-01", T),  # a leap day is a calendar date
]


@pytest.mark.parametrize(("actual", "op", "operand", "expected"), ORDERING_CASES)
def test_ordering_on_integers_and_on_iso_dates(actual: Any, op: str, operand: Any, expected: Tri) -> None:
    assert value_of(compare("ics.x", op, operand), {"ics": {"x": actual}}) is expected


EQUALITY_CASES = [
    ("widget", "eq", "widget", T),
    ("widget", "eq", "gadget", F),
    ("widget", "ne", "gadget", T),
    ("widget", "ne", "widget", F),
    (7, "eq", 7, T),
    (7, "eq", 8, F),
    (7, "ne", 8, T),
    (True, "eq", True, T),
    (True, "eq", False, F),
    (False, "ne", True, T),
    ("widget", "in", ["gadget", "widget"], T),
    ("widget", "in", ["gadget"], F),
    ("widget", "in", [], F),
    ("widget", "not_in", ["gadget"], T),
    ("widget", "not_in", ["gadget", "widget"], F),
    (7, "in", [6, 7], T),
    (7, "not_in", [6, 7], F),
    (["qr", "nfc"], "contains", "qr", T),
    (["qr", "nfc"], "contains", "rfid", F),
    ([], "contains", "qr", F),
]


@pytest.mark.parametrize(("actual", "op", "operand", "expected"), EQUALITY_CASES)
def test_equality_membership_and_contains(actual: Any, op: str, operand: Any, expected: Tri) -> None:
    assert value_of(compare("ics.x", op, operand), {"ics": {"x": actual}}) is expected


def test_true_never_equals_one() -> None:
    """bool is not int. A defect report is acceptable; the answer `true` is not."""
    cases = [
        (True, "eq", 1),
        (1, "eq", True),
        (False, "eq", 0),
        (True, "in", [1]),
        (1, "in", [True]),
        ([1], "contains", True),
        ([True], "contains", 1),
    ]
    for actual, op, operand in cases:
        try:
            outcome = value_of(compare("ics.x", op, operand), {"ics": {"x": actual}})
        except ApplicabilityError:
            continue
        assert outcome is F, (actual, op, operand)
    assert value_of(compare("ics.x", "ne", True), {"ics": {"x": False}}) is T


# --- Defects -----------------------------------------------------------------------------

DEFECTS = [
    # a type mismatch
    ("widget", "eq", 5),
    (5, "eq", "5"),
    (5, "ne", "5"),
    (True, "eq", 1),
    (1, "ne", True),
    (5, "eq", [5]),
    # ordering needs two integers or two ISO dates
    ("alpha", "gt", "beta"),
    ("2027-02-18", "lt", "tomorrow"),
    ("soon", "le", "2027-02-18"),
    ("2027-02-30", "ge", "2027-02-18"),  # the pattern of a date, but not a calendar date
    ("2027-02-18T00:00:00Z", "gt", "2027-02-17"),  # a time stamp is not a date
    (5, "gt", "2027-02-18"),
    ("2027-02-18", "gt", 5),
    (True, "gt", 0),
    (5, "lt", True),
    ([1, 2], "ge", 1),
    # `in` and `not_in` need a list operand
    ("widget", "in", "widget"),
    ("widget", "not_in", "widget"),
    (5, "in", 5),
    # `contains` needs a list-valued fact
    ("widget", "contains", "w"),
    (5, "contains", 5),
    (True, "contains", True),
]


@pytest.mark.parametrize(("actual", "op", "operand"), DEFECTS)
def test_each_defect_raises_an_applicability_error(actual: Any, op: str, operand: Any) -> None:
    with pytest.raises(ApplicabilityError, match=r"ics\.x"):
        evaluate(compare("ics.x", op, operand), {"ics": {"x": actual}})


DEFECT = compare("ics.x", "gt", "not-a-date")
DEFECT_FACTS = {"ics": {"x": 5}}


@pytest.mark.parametrize(
    "build",
    [
        lambda defect: All(all=(const(F), defect)),
        lambda defect: All(all=(defect, const(F))),
        lambda defect: AnyOf(any=(const(T), defect)),
        lambda defect: AnyOf(any=(defect, const(T))),
        lambda defect: negate(AnyOf(any=(const(T), negate(defect)))),
        lambda defect: All(all=(const(F), AnyOf(any=(const(T), All(all=(const(F), defect)))))),
    ],
    ids=["all-false-first", "all-false-last", "any-true-first", "any-true-last", "under-not", "nested"],
)
def test_a_decided_operand_does_not_short_circuit_a_defect(build: Callable[[Expr], Expr]) -> None:
    with pytest.raises(ApplicabilityError, match=r"ics\.x"):
        evaluate(build(DEFECT), DEFECT_FACTS)


# --- Fact paths and the fact tree --------------------------------------------------------


def test_fact_paths_lists_every_fact_that_an_expression_reads() -> None:
    tree = All(
        all=(
            compare("ics.a", "eq", 1),
            AnyOf(any=(compare("ics.b.c", "ne", 2), negate(compare("profile.d", "gt", 3)))),
            const(U),
            negate(negate(compare("ics.a", "lt", 9))),
        )
    )
    assert sorted(fact_paths(tree)) == ["ics.a", "ics.a", "ics.b.c", "profile.d"]
    assert list(fact_paths(const(T))) == []
    assert list(fact_paths(compare("ics.only", "eq", 1))) == ["ics.only"]


def test_facts_are_addressed_under_ics_and_profile() -> None:
    declared = b.ics(
        product_category="widget",
        carriers=["qr", "nfc"],
        characteristics={"capacity_wh": 2500, "placed_on_market_date": "2027-03-01"},
        features={"export": True, "audit": "unknown"},
    )
    selected = b.profile(constants={"threshold_wh": 2000, "cutoff_date": "2027-02-18"})
    facts = facts_from(declared, selected)

    def holds(fact: str, op: str, operand: Any) -> Tri:
        return evaluate(compare(fact, op, operand), facts).value

    assert holds("ics.product_category", "eq", "widget") is T
    assert holds("ics.characteristics.capacity_wh", "gt", 2000) is T
    assert holds("ics.characteristics.capacity_wh", "le", 2499) is F
    assert holds("ics.characteristics.placed_on_market_date", "ge", "2027-02-18") is T
    assert holds("ics.features.export", "eq", True) is T
    assert holds("ics.carriers", "contains", "nfc") is T
    assert holds("ics.carriers", "contains", "rfid") is F
    assert holds("profile.id", "eq", b.PROFILE_ID) is T
    assert holds("profile.product_category", "in", ["widget"]) is T
    assert holds("profile.threshold_wh", "eq", 2000) is T
    assert holds("profile.cutoff_date", "lt", "2027-03-01") is T
    # Declared as "unknown", left at its default of "unknown", or not declared at all.
    assert holds("ics.features.audit", "eq", True) is U
    assert holds("ics.sut.version", "eq", "1.0") is U
    assert holds("ics.granularity", "eq", "item") is U
    assert holds("ics.features.never_declared", "eq", True) is U
    assert holds("ics.characteristics.never_declared", "gt", 1) is U
    assert holds("profile.never_declared", "eq", 1) is U


# --- Properties over random expression trees ---------------------------------------------

FACT_VALUES: dict[str, st.SearchStrategy[Any]] = {
    "ics.count": st.integers(-3, 3),
    "ics.flag": st.booleans(),
    "ics.word": st.sampled_from(["red", "green", "blue"]),
    "ics.day": st.dates(date(2026, 1, 1), date(2026, 1, 5)).map(date.isoformat),
    "ics.tags": st.lists(st.sampled_from(["a", "b", "c"]), max_size=3),
}
EQUALITY = [Op.EQ, Op.NE]
ORDERING = [*EQUALITY, Op.GT, Op.GE, Op.LT, Op.LE]


def well_typed(fact: str, ops: list[Op]) -> st.SearchStrategy[Compare]:
    """Comparisons whose operand has the type of the fact, so that no tree holds a defect."""
    values = FACT_VALUES[fact]
    single = st.builds(Compare, fact=st.just(fact), op=st.sampled_from(ops), value=values)
    several = st.builds(
        Compare,
        fact=st.just(fact),
        op=st.sampled_from([Op.IN, Op.NOT_IN]),
        value=st.lists(values, max_size=3).map(tuple),
    )
    return single | several


COMPARISONS = st.one_of(
    well_typed("ics.count", ORDERING),
    well_typed("ics.flag", EQUALITY),
    well_typed("ics.word", EQUALITY),
    well_typed("ics.day", ORDERING),
    st.builds(
        Compare, fact=st.just("ics.tags"), op=st.just(Op.CONTAINS), value=st.sampled_from(["a", "b", "c"])
    ),
)
EXPRESSIONS: st.SearchStrategy[Expr] = st.recursive(
    st.sampled_from([const(v) for v in Tri]) | COMPARISONS,
    lambda inner: st.one_of(
        st.lists(inner, min_size=1, max_size=3).map(lambda parts: All(all=tuple(parts))),
        st.lists(inner, min_size=1, max_size=3).map(lambda parts: AnyOf(any=tuple(parts))),
        inner.map(negate),
    ),
    max_leaves=10,
)


def fact_tree(flat: dict[str, Any]) -> dict[str, Any]:
    return {"ics": {name.removeprefix("ics."): value for name, value in flat.items()}}


@st.composite
def knowledge(draw: st.DrawFn) -> tuple[dict[str, Any], dict[str, Any]]:
    """Partial facts, and the same facts with a value for each fact that was not known."""
    full = {name: draw(values) for name, values in FACT_VALUES.items()}
    partial: dict[str, Any] = {}
    for name, value in full.items():
        state = draw(st.sampled_from(["known", "missing", "unknown"]))
        if state != "missing":
            partial[name] = value if state == "known" else "unknown"
    return fact_tree(partial), fact_tree(full)


HOLDS: dict[Op, Callable[[Any, Any], bool]] = {
    Op.EQ: operator.eq,
    Op.NE: operator.ne,
    Op.GT: operator.gt,
    Op.GE: operator.ge,
    Op.LT: operator.lt,
    Op.LE: operator.le,
    Op.IN: lambda actual, operand: actual in operand,
    Op.NOT_IN: lambda actual, operand: actual not in operand,
    Op.CONTAINS: lambda actual, operand: operand in actual,
}


def reference(expr: Expr, facts: dict[str, Any]) -> Tri:
    """Section 5 written again, for well-typed trees only. ISO dates order as their text does."""
    match expr:
        case Const():
            return expr.const
        case Not():
            return NOT_TABLE[reference(expr.operand, facts)]
        case All():
            return kleene_all([reference(part, facts) for part in expr.all])
        case AnyOf():
            return kleene_any([reference(part, facts) for part in expr.any])
        case Compare():
            actual = facts["ics"].get(expr.fact.removeprefix("ics."), "unknown")
            if actual == "unknown":
                return U
            return T if HOLDS[expr.op](actual, expr.value) else F


@PROPERTY
@given(expr=EXPRESSIONS, facts=knowledge())
def test_property_evaluation_agrees_with_a_reference_written_from_the_contract(
    expr: Expr, facts: tuple[dict[str, Any], dict[str, Any]]
) -> None:
    partial, full = facts
    assert evaluate(expr, partial).value is reference(expr, partial)
    assert evaluate(expr, full).value is reference(expr, full)


@PROPERTY
@given(expr=EXPRESSIONS, facts=knowledge())
def test_property_knowledge_is_monotonic(expr: Expr, facts: tuple[dict[str, Any], dict[str, Any]]) -> None:
    partial, full = facts
    before = evaluate(expr, partial).value
    if before is not U:
        assert evaluate(expr, full).value is before, "a new fact changed a decided result"


@PROPERTY
@given(expr=EXPRESSIONS, facts=knowledge())
def test_property_double_negation(expr: Expr, facts: tuple[dict[str, Any], dict[str, Any]]) -> None:
    for known in facts:
        assert evaluate(negate(negate(expr)), known).value is evaluate(expr, known).value


@PROPERTY
@given(parts=st.lists(EXPRESSIONS, min_size=1, max_size=4), facts=knowledge())
def test_property_de_morgan(parts: list[Expr], facts: tuple[dict[str, Any], dict[str, Any]]) -> None:
    negated = tuple(negate(part) for part in parts)
    for known in facts:
        assert (
            evaluate(negate(All(all=tuple(parts))), known).value is evaluate(AnyOf(any=negated), known).value
        )
        assert (
            evaluate(negate(AnyOf(any=tuple(parts))), known).value is evaluate(All(all=negated), known).value
        )
