"""
NIGHTWATCH — SPL Parser
Parses SPL query strings into structured AST search stages and pipeline commands.
"""

import re
from typing import Any, List, Optional, Tuple

from app.search.ast_nodes import (
    AggregationSpec, BinCommand, ChartCommand, DedupCommand, EvalCommand,
    EventstatsCommand, FieldsCommand, FillnullCommand, HeadCommand,
    PipelineCommand, RareCommand, RenameCommand, RexCommand, SearchFilter,
    SearchStage, SortCommand, SpathCommand, StatsCommand, StreamstatsCommand,
    TableCommand, TailCommand, TermFilter, TimechartCommand, TopCommand, TransactionCommand,
    WhereCommand
)
from app.search.lexer import Lexer, LexerError
from app.search.tokens import Token, TokenType


class ParseError(Exception):
    pass


class SPLParser:
    def parse(self, query: str) -> Tuple[SearchStage, List[PipelineCommand]]:
        """Parses a full SPL query into an initial SearchStage and list of PipelineCommands."""
        clean_query = query.strip()
        if not clean_query:
            return SearchStage(), []

        # Split on pipeline symbol '|'
        # We need to respect quoted strings so '|' inside quotes is not split
        pipe_stages = self._split_pipes(clean_query)
        if not pipe_stages:
            return SearchStage(), []

        # First stage is initial search stage
        initial_stage_str = pipe_stages[0].strip()
        search_stage = self._parse_search_stage(initial_stage_str)

        # Remaining stages are pipeline commands
        commands: List[PipelineCommand] = []
        for cmd_str in pipe_stages[1:]:
            cmd = self._parse_pipeline_command(cmd_str.strip())
            if cmd:
                commands.append(cmd)

        return search_stage, commands

    def _split_pipes(self, text: str) -> List[str]:
        """Splits query on '|' while ignoring pipes inside quotes."""
        stages = []
        current = []
        in_quote = None
        i = 0
        while i < len(text):
            c = text[i]
            if c in ('"', "'"):
                if in_quote is None:
                    in_quote = c
                elif in_quote == c:
                    in_quote = None
                current.append(c)
            elif c == '|' and in_quote is None:
                stages.append("".join(current))
                current = []
            else:
                current.append(c)
            i += 1
        if current:
            stages.append("".join(current))
        return stages

    def _parse_search_stage(self, stage_str: str) -> SearchStage:
        stage = SearchStage()
        if not stage_str:
            return stage

        # Strip optional leading "search "
        if stage_str.lower().startswith("search "):
            stage_str = stage_str[7:].strip()

        lexer = Lexer(stage_str)
        tokens = lexer.tokenize()
        idx = 0

        while idx < len(tokens):
            tok = tokens[idx]
            if tok.type == TokenType.EOF:
                break

            # Skip explicit AND / OR / NOT keywords in top-level search terms
            if tok.type in (TokenType.AND, TokenType.OR, TokenType.NOT):
                idx += 1
                continue

            # Check for field filter: IDENTIFIER ( = | != | > | < | >= | <= ) VALUE
            if tok.type == TokenType.IDENTIFIER and idx + 1 < len(tokens):
                next_tok = tokens[idx + 1]
                if next_tok.type in (TokenType.EQUALS, TokenType.NOT_EQUALS, TokenType.GT, TokenType.LT, TokenType.GTE, TokenType.LTE):
                    op = next_tok.value
                    if idx + 2 < len(tokens):
                        val_tok = tokens[idx + 2]
                        if val_tok.type in (TokenType.IDENTIFIER, TokenType.STRING, TokenType.NUMBER):
                            stage.filters.append(SearchFilter(tok.value, op, val_tok.value))
                            idx += 3
                            continue

            # Otherwise, treat as term / phrase search
            if tok.type == TokenType.STRING:
                stage.terms.append(tok.value)
            elif tok.type == TokenType.IDENTIFIER:
                stage.terms.append(tok.value)
            elif tok.type == TokenType.NUMBER:
                stage.terms.append(str(tok.value))

            idx += 1

        return stage

    def _parse_pipeline_command(self, cmd_str: str) -> Optional[PipelineCommand]:
        if not cmd_str:
            return None

        # Extract command name
        parts = cmd_str.split(None, 1)
        cmd_name = parts[0].lower()
        args_str = parts[1].strip() if len(parts) > 1 else ""

        if cmd_name == "where":
            return WhereCommand(args_str)

        elif cmd_name == "fields":
            return self._parse_fields(args_str)

        elif cmd_name == "table":
            cols = [c.strip() for c in args_str.replace(",", " ").split() if c.strip()]
            return TableCommand(cols)

        elif cmd_name == "stats":
            return self._parse_stats(args_str)

        elif cmd_name == "top":
            return self._parse_top_rare(args_str, is_top=True)

        elif cmd_name == "rare":
            return self._parse_top_rare(args_str, is_top=False)

        elif cmd_name == "sort":
            return self._parse_sort(args_str)

        elif cmd_name == "head":
            count = 10
            if args_str:
                try:
                    count = int(args_str.split()[0])
                except Exception:
                    pass
            return HeadCommand(count)

        elif cmd_name == "tail":
            count = 10
            if args_str:
                try:
                    count = int(args_str.split()[0])
                except Exception:
                    pass
            return TailCommand(count)

        elif cmd_name == "dedup":
            fields = [f.strip() for f in args_str.replace(",", " ").split() if f.strip()]
            return DedupCommand(fields)

        elif cmd_name == "eval":
            return self._parse_eval(args_str)

        elif cmd_name == "rex":
            return self._parse_rex(args_str)

        elif cmd_name == "spath":
            return self._parse_spath(args_str)

        elif cmd_name == "timechart":
            return self._parse_timechart(args_str)

        elif cmd_name == "chart":
            return self._parse_chart(args_str)

        elif cmd_name == "bin" or cmd_name == "bucket":
            return self._parse_bin(args_str)

        elif cmd_name == "rename":
            return self._parse_rename(args_str)

        elif cmd_name == "fillnull":
            return self._parse_fillnull(args_str)

        elif cmd_name == "eventstats":
            stats_cmd = self._parse_stats(args_str)
            return EventstatsCommand(stats_cmd.aggregations, stats_cmd.group_by)

        elif cmd_name == "streamstats":
            return self._parse_streamstats(args_str)

        elif cmd_name == "transaction":
            return self._parse_transaction(args_str)

        else:
            raise ParseError(f"Unsupported or unrecognized SPL command: '{cmd_name}'")

    def _parse_fields(self, args_str: str) -> FieldsCommand:
        mode = "+"
        s = args_str.strip()
        if s.startswith("-"):
            mode = "-"
            s = s[1:].strip()
        elif s.startswith("+"):
            s = s[1:].strip()

        fields = [f.strip() for f in s.replace(",", " ").split() if f.strip()]
        return FieldsCommand(fields, mode)

    def _parse_stats(self, args_str: str) -> StatsCommand:
        # e.g.: count, avg(bytes) as avg_b, dc(user) by host, sourcetype
        group_by = []
        aggs_str = args_str

        # Check for "by"
        by_match = re.search(r"\bby\b", args_str, re.IGNORECASE)
        if by_match:
            aggs_str = args_str[:by_match.start()].strip()
            by_str = args_str[by_match.end():].strip()
            group_by = [f.strip() for f in by_str.replace(",", " ").split() if f.strip()]

        aggregations = []
        # Split aggs by comma (ignoring commas inside parentheses)
        agg_tokens = self._split_agg_tokens(aggs_str)
        for token in agg_tokens:
            agg_spec = self._parse_single_agg(token.strip())
            if agg_spec:
                aggregations.append(agg_spec)

        if not aggregations:
            aggregations.append(AggregationSpec("count"))

        return StatsCommand(aggregations, group_by)

    def _split_agg_tokens(self, text: str) -> List[str]:
        tokens = []
        current = []
        parens = 0
        for c in text:
            if c == '(':
                parens += 1
                current.append(c)
            elif c == ')':
                parens -= 1
                current.append(c)
            elif c == ',' and parens == 0:
                tokens.append("".join(current))
                current = []
            else:
                current.append(c)
        if current:
            tokens.append("".join(current))
        return tokens

    def _parse_single_agg(self, text: str) -> Optional[AggregationSpec]:
        if not text:
            return None
        # Check for "as" alias
        as_match = re.search(r"\bas\b", text, re.IGNORECASE)
        as_name = None
        func_expr = text
        if as_match:
            func_expr = text[:as_match.start()].strip()
            as_name = text[as_match.end():].strip()

        # Parse func(field) or simple func (like count)
        m = re.match(r"^([a-zA-Z_]+)(?:\((.*)\))?$", func_expr)
        if m:
            func = m.group(1).lower()
            field = m.group(2).strip() if m.group(2) else None
            return AggregationSpec(func=func, field=field, as_name=as_name)
        return AggregationSpec(func="count", field=None, as_name=as_name)

    def _parse_top_rare(self, args_str: str, is_top: bool = True) -> PipelineCommand:
        # e.g.: top 10 username by host
        limit = 10
        field = ""
        by_fields = []

        tokens = args_str.split()
        idx = 0
        if idx < len(tokens) and tokens[idx].isdigit():
            limit = int(tokens[idx])
            idx += 1

        if idx < len(tokens):
            field = tokens[idx].rstrip(",")
            idx += 1

        # Check for by
        while idx < len(tokens):
            if tokens[idx].lower() == "by":
                idx += 1
                break
            idx += 1

        while idx < len(tokens):
            by_fields.append(tokens[idx].rstrip(","))
            idx += 1

        if is_top:
            return TopCommand(field=field, limit=limit, by_fields=by_fields)
        return RareCommand(field=field, limit=limit, by_fields=by_fields)

    def _parse_sort(self, args_str: str) -> SortCommand:
        # e.g.: sort - timestamp, + host
        tokens = [t.strip() for t in args_str.replace(",", " ").split() if t.strip()]
        fields = []
        for tok in tokens:
            direction = 1
            f_name = tok
            if tok.startswith("-"):
                direction = -1
                f_name = tok[1:].strip()
            elif tok.startswith("+"):
                direction = 1
                f_name = tok[1:].strip()
            if f_name:
                fields.append((f_name, direction))
        return SortCommand(fields)

    def _parse_eval(self, args_str: str) -> EvalCommand:
        # e.g.: eval speed = bytes / 1024
        if "=" not in args_str:
            raise ParseError(f"Malformed eval syntax. Expected 'eval target = expr', got: '{args_str}'")
        target, expr = args_str.split("=", 1)
        return EvalCommand(target.strip(), expr.strip())

    def _parse_rex(self, args_str: str) -> RexCommand:
        # e.g.: rex field=_raw "user=(?<usr>\w+)"
        field = "_raw"
        pattern = ""

        # Extract field= if present
        m_field = re.search(r"field=([a-zA-Z0-9_\-]+)", args_str, re.IGNORECASE)
        if m_field:
            field = m_field.group(1)

        # Extract quoted pattern
        m_pat = re.search(r'["\'](.*)["\']', args_str)
        if m_pat:
            pattern = m_pat.group(1)
        else:
            # Fall back to remaining tokens
            parts = args_str.split()
            pattern = parts[-1] if parts else ""

        return RexCommand(pattern=pattern, field=field)

    def _parse_spath(self, args_str: str) -> SpathCommand:
        # e.g.: spath input=raw path=alert.signature output=sig
        inp = "_raw"
        path = ""
        out = None

        m_inp = re.search(r"input=([a-zA-Z0-9_\-]+)", args_str, re.IGNORECASE)
        if m_inp:
            inp = m_inp.group(1)

        m_path = re.search(r"path=([a-zA-Z0-9_\-\.]+)", args_str, re.IGNORECASE)
        if m_path:
            path = m_path.group(1)

        m_out = re.search(r"output=([a-zA-Z0-9_\-]+)", args_str, re.IGNORECASE)
        if m_out:
            out = m_out.group(1)

        return SpathCommand(path=path, input_field=inp, output_field=out)

    def _parse_timechart(self, args_str: str) -> TimechartCommand:
        # e.g.: timechart span=5m count by host
        span = "1h"
        m_span = re.search(r"span=([0-9]+[smhd])", args_str, re.IGNORECASE)
        if m_span:
            span = m_span.group(1)

        # Remove span parameter to parse aggregation and by_field
        rem = re.sub(r"span=[0-9]+[smhd]", "", args_str, flags=re.IGNORECASE).strip()

        by_field = None
        by_match = re.search(r"\bby\b", rem, re.IGNORECASE)
        if by_match:
            agg_part = rem[:by_match.start()].strip()
            by_field = rem[by_match.end():].strip().split()[0]
        else:
            agg_part = rem.strip()

        agg = self._parse_single_agg(agg_part) or AggregationSpec("count")
        return TimechartCommand(span=span, agg=agg, by_field=by_field)

    def _parse_chart(self, args_str: str) -> ChartCommand:
        # e.g.: chart count over host by severity
        over_field = "host"
        by_field = None
        agg_part = "count"

        m_over = re.search(r"\bover\b", args_str, re.IGNORECASE)
        m_by = re.search(r"\bby\b", args_str, re.IGNORECASE)

        if m_over:
            agg_part = args_str[:m_over.start()].strip()
            if m_by:
                over_field = args_str[m_over.end():m_by.start()].strip()
                by_field = args_str[m_by.end():].strip()
            else:
                over_field = args_str[m_over.end():].strip()

        agg = self._parse_single_agg(agg_part) or AggregationSpec("count")
        return ChartCommand(agg=agg, over_field=over_field, by_field=by_field)

    def _parse_bin(self, args_str: str) -> BinCommand:
        # e.g.: bin _time span=10m as time_bin
        tokens = args_str.split()
        field = "_time"
        span = "1h"
        as_name = None

        if tokens:
            field = tokens[0]

        m_span = re.search(r"span=([0-9]+[smhd]?)", args_str, re.IGNORECASE)
        if m_span:
            span = m_span.group(1)

        m_as = re.search(r"\bas\b\s+([a-zA-Z0-9_]+)", args_str, re.IGNORECASE)
        if m_as:
            as_name = m_as.group(1)

        return BinCommand(field=field, span=span, as_name=as_name)

    def _parse_rename(self, args_str: str) -> RenameCommand:
        # e.g.: rename src_ip as source, dest_ip as target
        mappings = {}
        pairs = args_str.split(",")
        for pair in pairs:
            if " as " in pair.lower():
                parts = re.split(r"\bas\b", pair, flags=re.IGNORECASE)
                old_k = parts[0].strip()
                new_k = parts[1].strip()
                if old_k and new_k:
                    mappings[old_k] = new_k
        return RenameCommand(mappings)

    def _parse_fillnull(self, args_str: str) -> FillnullCommand:
        # e.g.: fillnull value="N/A" user, host
        val = "NULL"
        m_val = re.search(r'value=["\']?([^"\']+)["\']?', args_str, re.IGNORECASE)
        if m_val:
            val = m_val.group(1)

        rem = re.sub(r'value=["\']?[^"\']+["\']?', '', args_str, flags=re.IGNORECASE).strip()
        fields = [f.strip() for f in rem.replace(",", " ").split() if f.strip()]
        return FillnullCommand(value=val, fields=fields)

    def _parse_streamstats(self, args_str: str) -> StreamstatsCommand:
        window = None
        m_win = re.search(r"window=(\d+)", args_str, re.IGNORECASE)
        if m_win:
            window = int(m_win.group(1))

        rem = re.sub(r"window=\d+", "", args_str, flags=re.IGNORECASE).strip()
        stats_cmd = self._parse_stats(rem)
        return StreamstatsCommand(stats_cmd.aggregations, window=window)

    def _parse_transaction(self, args_str: str) -> TransactionCommand:
        # e.g.: transaction src_ip, user maxspan=30m maxpause=5m
        maxspan = None
        maxpause = None

        m_span = re.search(r"maxspan=([0-9]+[smhd]?)", args_str, re.IGNORECASE)
        if m_span:
            maxspan = self._parse_duration(m_span.group(1))

        m_pause = re.search(r"maxpause=([0-9]+[smhd]?)", args_str, re.IGNORECASE)
        if m_pause:
            maxpause = self._parse_duration(m_pause.group(1))

        rem = re.sub(r"maxspan=[0-9]+[smhd]?", "", args_str, flags=re.IGNORECASE)
        rem = re.sub(r"maxpause=[0-9]+[smhd]?", "", rem, flags=re.IGNORECASE)
        fields = [f.strip() for f in rem.replace(",", " ").split() if f.strip()]
        return TransactionCommand(fields=fields, maxspan_seconds=maxspan, maxpause_seconds=maxpause)

    @staticmethod
    def _parse_duration(dur_str: str) -> int:
        dur_str = dur_str.strip().lower()
        if not dur_str:
            return 0
        unit = dur_str[-1]
        if unit in ('s', 'm', 'h', 'd'):
            val = int(dur_str[:-1])
            if unit == 's':
                return val
            elif unit == 'm':
                return val * 60
            elif unit == 'h':
                return val * 3600
            elif unit == 'd':
                return val * 86400
        return int(dur_str)
