"""
NIGHTWATCH — Pipeline Execution Engine
Sequentially routes in-memory event streams through chained SPL transformation stages.
"""

from typing import Any, Dict, List
from app.search.ast_nodes import (
    BinCommand, ChartCommand, DedupCommand, EvalCommand, EventstatsCommand,
    FieldsCommand, FillnullCommand, HeadCommand, PipelineCommand, RareCommand,
    RenameCommand, RexCommand, SortCommand, SpathCommand, StatsCommand,
    StreamstatsCommand, TableCommand, TailCommand, TimechartCommand, TopCommand,
    TransactionCommand, WhereCommand
)
from app.search.commands.advanced import (
    execute_eventstats, execute_fillnull, execute_rename, execute_streamstats,
    execute_transaction
)
from app.search.commands.eval import execute_eval
from app.search.commands.fields import execute_fields, execute_table
from app.search.commands.head_tail import execute_dedup, execute_head, execute_tail
from app.search.commands.rex import execute_rex, execute_spath
from app.search.commands.sort import execute_sort
from app.search.commands.stats import execute_stats
from app.search.commands.timechart import execute_bin, execute_timechart
from app.search.commands.top import execute_top_rare
from app.search.commands.where import execute_where


class PipelineExecutor:
    def execute(self, records: List[Dict[str, Any]], commands: List[PipelineCommand]) -> List[Dict[str, Any]]:
        curr = records

        for cmd in commands:
            if isinstance(cmd, WhereCommand):
                curr = execute_where(curr, cmd.expression)

            elif isinstance(cmd, FieldsCommand):
                curr = execute_fields(curr, cmd.fields, cmd.mode)

            elif isinstance(cmd, TableCommand):
                curr = execute_table(curr, cmd.fields)

            elif isinstance(cmd, StatsCommand):
                curr = execute_stats(curr, cmd.aggregations, cmd.group_by)

            elif isinstance(cmd, TopCommand):
                curr = execute_top_rare(curr, cmd.field, cmd.limit, cmd.by_fields, is_top=True)

            elif isinstance(cmd, RareCommand):
                curr = execute_top_rare(curr, cmd.field, cmd.limit, cmd.by_fields, is_top=False)

            elif isinstance(cmd, SortCommand):
                curr = execute_sort(curr, cmd.fields)

            elif isinstance(cmd, HeadCommand):
                curr = execute_head(curr, cmd.count)

            elif isinstance(cmd, TailCommand):
                curr = execute_tail(curr, cmd.count)

            elif isinstance(cmd, DedupCommand):
                curr = execute_dedup(curr, cmd.fields, cmd.consecutive)

            elif isinstance(cmd, EvalCommand):
                curr = execute_eval(curr, cmd.target_field, cmd.expression)

            elif isinstance(cmd, RexCommand):
                curr = execute_rex(curr, cmd.pattern, cmd.field)

            elif isinstance(cmd, SpathCommand):
                curr = execute_spath(curr, cmd.path, cmd.input_field, cmd.output_field)

            elif isinstance(cmd, TimechartCommand):
                curr = execute_timechart(curr, cmd.span, cmd.agg, cmd.by_field)

            elif isinstance(cmd, ChartCommand):
                # Map chart to stats with group-by [over_field, by_field]
                group_by = [cmd.over_field]
                if cmd.by_field:
                    group_by.append(cmd.by_field)
                curr = execute_stats(curr, [cmd.agg], group_by)

            elif isinstance(cmd, BinCommand):
                curr = execute_bin(curr, cmd.field, cmd.span, cmd.as_name)

            elif isinstance(cmd, RenameCommand):
                curr = execute_rename(curr, cmd.mappings)

            elif isinstance(cmd, FillnullCommand):
                curr = execute_fillnull(curr, cmd.value, cmd.fields)

            elif isinstance(cmd, EventstatsCommand):
                curr = execute_eventstats(curr, cmd.aggregations, cmd.group_by)

            elif isinstance(cmd, StreamstatsCommand):
                curr = execute_streamstats(curr, cmd.aggregations, cmd.window)

            elif isinstance(cmd, TransactionCommand):
                curr = execute_transaction(curr, cmd.fields, cmd.maxspan_seconds, cmd.maxpause_seconds)

        return curr
