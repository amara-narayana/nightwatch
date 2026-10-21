"""
NIGHTWATCH — SPL Abstract Syntax Tree (AST) Node Definitions
"""

from typing import Any, Dict, List, Optional, Tuple


class ASTNode:
    pass


class SearchFilter(ASTNode):
    def __init__(self, field: str, op: str, value: Any):
        self.field = field.lower()
        self.op = op
        self.value = value

    def __repr__(self):
        return f"SearchFilter({self.field} {self.op} {self.value!r})"


class TermFilter(ASTNode):
    def __init__(self, term: str):
        self.term = term

    def __repr__(self):
        return f"TermFilter({self.term!r})"


class SearchStage(ASTNode):
    def __init__(self):
        self.filters: List[SearchFilter] = []
        self.terms: List[str] = []

    def __repr__(self):
        return f"SearchStage(terms={self.terms}, filters={self.filters})"


class PipelineCommand(ASTNode):
    pass


class WhereCommand(PipelineCommand):
    def __init__(self, expression: str):
        self.expression = expression

    def __repr__(self):
        return f"WhereCommand({self.expression!r})"


class FieldsCommand(PipelineCommand):
    def __init__(self, fields: List[str], mode: str = "+"):
        self.fields = fields
        self.mode = mode  # "+" or "-"

    def __repr__(self):
        return f"FieldsCommand({self.mode}{self.fields})"


class TableCommand(PipelineCommand):
    def __init__(self, fields: List[str]):
        self.fields = fields

    def __repr__(self):
        return f"TableCommand({self.fields})"


class AggregationSpec:
    def __init__(self, func: str, field: Optional[str] = None, as_name: Optional[str] = None):
        self.func = func.lower()
        self.field = field
        self.as_name = as_name or (f"{self.func}({field})" if field else self.func)

    def __repr__(self):
        return f"Agg({self.func}, {self.field} AS {self.as_name})"


class StatsCommand(PipelineCommand):
    def __init__(self, aggregations: List[AggregationSpec], group_by: Optional[List[str]] = None):
        self.aggregations = aggregations
        self.group_by = group_by or []

    def __repr__(self):
        return f"StatsCommand(aggs={self.aggregations}, by={self.group_by})"


class TopCommand(PipelineCommand):
    def __init__(self, field: str, limit: int = 10, by_fields: Optional[List[str]] = None):
        self.field = field
        self.limit = limit
        self.by_fields = by_fields or []

    def __repr__(self):
        return f"TopCommand({self.field}, limit={self.limit}, by={self.by_fields})"


class RareCommand(PipelineCommand):
    def __init__(self, field: str, limit: int = 10, by_fields: Optional[List[str]] = None):
        self.field = field
        self.limit = limit
        self.by_fields = by_fields or []

    def __repr__(self):
        return f"RareCommand({self.field}, limit={self.limit}, by={self.by_fields})"


class SortCommand(PipelineCommand):
    def __init__(self, fields: List[Tuple[str, int]]):
        # direction: 1 for ascending, -1 for descending
        self.fields = fields

    def __repr__(self):
        return f"SortCommand({self.fields})"


class HeadCommand(PipelineCommand):
    def __init__(self, count: int = 10):
        self.count = count

    def __repr__(self):
        return f"HeadCommand({self.count})"


class TailCommand(PipelineCommand):
    def __init__(self, count: int = 10):
        self.count = count

    def __repr__(self):
        return f"TailCommand({self.count})"


class DedupCommand(PipelineCommand):
    def __init__(self, fields: List[str], consecutive: bool = False):
        self.fields = fields
        self.consecutive = consecutive

    def __repr__(self):
        return f"DedupCommand({self.fields})"


class EvalCommand(PipelineCommand):
    def __init__(self, target_field: str, expression: str):
        self.target_field = target_field
        self.expression = expression

    def __repr__(self):
        return f"EvalCommand({self.target_field} = {self.expression})"


class RexCommand(PipelineCommand):
    def __init__(self, pattern: str, field: str = "_raw"):
        self.pattern = pattern
        self.field = field

    def __repr__(self):
        return f"RexCommand(field={self.field}, regex={self.pattern!r})"


class SpathCommand(PipelineCommand):
    def __init__(self, path: str, input_field: str = "_raw", output_field: Optional[str] = None):
        self.path = path
        self.input_field = input_field
        self.output_field = output_field or path.split(".")[-1]

    def __repr__(self):
        return f"SpathCommand({self.input_field} -> {self.path} AS {self.output_field})"


class TimechartCommand(PipelineCommand):
    def __init__(self, span: str, agg: AggregationSpec, by_field: Optional[str] = None):
        self.span = span
        self.agg = agg
        self.by_field = by_field

    def __repr__(self):
        return f"TimechartCommand(span={self.span}, agg={self.agg}, by={self.by_field})"


class ChartCommand(PipelineCommand):
    def __init__(self, agg: AggregationSpec, over_field: str, by_field: Optional[str] = None):
        self.agg = agg
        self.over_field = over_field
        self.by_field = by_field

    def __repr__(self):
        return f"ChartCommand(agg={self.agg}, over={self.over_field}, by={self.by_field})"


class BinCommand(PipelineCommand):
    def __init__(self, field: str, span: str, as_name: Optional[str] = None):
        self.field = field
        self.span = span
        self.as_name = as_name or field

    def __repr__(self):
        return f"BinCommand({self.field}, span={self.span})"


class RenameCommand(PipelineCommand):
    def __init__(self, mappings: Dict[str, str]):
        self.mappings = mappings

    def __repr__(self):
        return f"RenameCommand({self.mappings})"


class FillnullCommand(PipelineCommand):
    def __init__(self, value: Any = "NULL", fields: Optional[List[str]] = None):
        self.value = value
        self.fields = fields or []

    def __repr__(self):
        return f"FillnullCommand(val={self.value!r}, fields={self.fields})"


class EventstatsCommand(PipelineCommand):
    def __init__(self, aggregations: List[AggregationSpec], group_by: Optional[List[str]] = None):
        self.aggregations = aggregations
        self.group_by = group_by or []

    def __repr__(self):
        return f"EventstatsCommand(aggs={self.aggregations}, by={self.group_by})"


class StreamstatsCommand(PipelineCommand):
    def __init__(self, aggregations: List[AggregationSpec], window: Optional[int] = None):
        self.aggregations = aggregations
        self.window = window

    def __repr__(self):
        return f"StreamstatsCommand(aggs={self.aggregations}, window={self.window})"


class TransactionCommand(PipelineCommand):
    def __init__(self, fields: List[str], maxspan_seconds: Optional[int] = None, maxpause_seconds: Optional[int] = None):
        self.fields = fields
        self.maxspan_seconds = maxspan_seconds
        self.maxpause_seconds = maxpause_seconds

    def __repr__(self):
        return f"TransactionCommand({self.fields}, maxspan={self.maxspan_seconds})"
