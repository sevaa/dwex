from elftools.dwarf.locationlists import LocationParser, LocationExpr, BaseAddressEntry
from elftools.common.exceptions import ELFParseError
from elftools.dwarf.callframe import FDE

from .exprdlg import ExpressionTableModel
from .details import GenericTableModel
from .dwarfutil import *
from .ranges import lowlevel_v5_tooltips, one_of
from .exprutil import format_offset, is_parsed_expression

def parse_location(self, attr):
    di = self.die.dwarfinfo
    if di._locparser is None:
        di._locparser = LocationParser(di.location_lists())

    # Patch for #1620: attribute is loclist pointer, but no loclists section
    if LocationParser._attribute_is_loclistptr_class(attr) and LocationParser._attribute_has_loc_list(attr, self.die.cu['version']) and not di._locparser.location_lists:
        return None
    
    try:
        return di._locparser.parse_from_attribute(attr, self.die.cu['version'], die = self.die)
    except ELFParseError as exc:
        from .__main__ import version
        from .crash import report_crash
        from inspect import currentframe

        die = self.die
        header = die.cu.header
        dwarf_version = die.cu.header.version
        di = die.cu.dwarfinfo
        ctxt = {'attr': attr,
                'die': die,
                'cu_header': header,
                'LE': di.config.little_endian,
                'dwarf_version': dwarf_version}
        try:
            if LocationParser._attribute_has_loc_list(attr, self.die.cu['version']):
                tb = exc.__traceback__
                tracebacks = []
                while tb.tb_next:
                    tracebacks.insert(0, tb) # Innermost in the beginning of the list
                    tb = tb.tb_next
                loc_section = di.debug_loclists_sec if dwarf_version >= 5 else di.debug_loc_sec
                if loc_section:
                    buf = loc_section.stream.getbuffer()
                    ctxt['loc_section_len'] = len(buf)
                    if len(tracebacks) > 1 and 'entry_offset' in tracebacks[1].tb_frame.f_locals:
                        fail_entry_offset = tracebacks[1].tb_frame.f_locals['entry_offset']
                        llend = fail_entry_offset + 8*2+2 if fail_entry_offset - attr.value <= 1024 else attr.value + 1024
                        llbytes = buf[attr.value:llend]
                        ctxt['llbytes'] = ' '.join("%02x" % b for b in llbytes)
                        for (k, v) in tracebacks[1].tb_frame.f_locals.items():
                            ctxt['_pllfs_' + k] = v
                        ctxt['llparser_addr_size'] = tracebacks[1].tb_frame.f_locals['self'].structs.address_size
        except:
            pass

        report_crash(exc, tb, version, currentframe(), ctxt)
        return None

# Returns a TableModel for the details table
# Usually a GenericTableModel
# Logically in DIETableModel class
def show_location(self, attr):
# Expression is a list of ints
# TODO: clickable expression maybe?
# TODO: truncate long expressions?
    ll = self.parse_location(attr)
    if ll is None:
        return None
    elif isinstance(ll, LocationExpr): # Location expression: spell out the commands in the details window
        if ll.loc_expr == [156] and has_code_location(self.die): # Special case of a single call_frame_cfa instruction
            def desc_CFA_rule(rule):
                if rule.expr is not None:
                    return self.dump_expr(rule.expr)
                else:
                    return self.expr_formatter.format_regoffset(rule.reg, rule.offset)

            rules = [(r['pc'], r['cfa']) for r in get_frame_rules_for_die(self.die) if 'cfa' in r]
            rules = [(pc, r) for (i, (pc, r)) in enumerate(rules) if i == 0 or rules[i-1][1] != r.reg or rules[i-1][1].offset != r.offset or rules[i-1][1].expr != r.expr]
            lines = [(f"0x{pc:x}", desc_CFA_rule(cfa_rule)) for (pc, cfa_rule) in rules]
            return GenericTableModel(("Address", "CFA expression"), lines)
        else:
            return ExpressionTableModel(self.parse_expr(ll.loc_expr), self.expr_formatter)
    else: # Loclist - location lines in the details window, double-click navigates to expression
        return self.show_loclist(ll, attr.value)
    
def show_loclist(self, ll, ll_offset):
    # Returns a table model for a loclist
    cu_base = None
    def base_for_entry(l): # May throw NoBaseException
        nonlocal cu_base
        if l.is_absolute:
            return 0
        else:
            if cu_base is None:
                cu_base = get_cu_base(self.die) # Throws here
            return cu_base

    values = list()
    lowlevel = self.lowlevel
    if lowlevel:
        ver5 = self.die.cu['version'] >= 5
        if ver5:
            headers = ("Entry offset", "Type", "Start/Index/Base", "End/Index/Length", "Start address", "End address", "Expr bytes", "Expression")
            raw_ll = self.die.dwarfinfo.location_lists().get_location_lists_at_offset_ex(ll_offset, self.die)
        else:
            headers = ("Entry offset", "Type", "Start address", "End address", "Expr bytes", "Expression")
        for (i, l) in enumerate(raw_ll if ver5 else ll):
            if ver5: #l is raw
                raw = l
                l = ll[i] # Translated entry

            if isinstance(l, BaseAddressEntry):
                cu_base = l.base_address
                if ver5:
                    (raw_base_type, raw_base) = one_of(raw, ('index','address'))
                    values.append((hex(l.entry_offset),
                        raw.entry_type if self.prefix else raw.entry_type[7:],
                        hex(raw_base) if raw_base_type == 1 else str(raw_base),
                        '',
                        hex(l.base_address),
                        '', '', ''))
                else:
                    values.append((hex(l.entry_offset), 'Base', hex(l.base_address), '', '', ''))
            else:
                try: # Catching #1609
                    expr = self.parse_expr(l.loc_expr)
                    expr_dump = self.format_expr(expr, 5)
                except KeyError as exc:
                    expr = None
                    expr_dump = "<unrecognized expression>"
                    from .__main__ import version
                    from .crash import report_crash
                    from inspect import currentframe
                    report_crash(exc, exc.__traceback__, version, currentframe())
                base = base_for_entry(l)
                if ver5:
                    is_def_loc = raw.entry_type == 'DW_LLE_default_location'
                    (raw_start_type, raw_start) = one_of(raw, ('index', 'start_index', 'start_offset', 'start_address'))
                    (raw_end_type, raw_end) = one_of(raw, ('end_index', 'length', 'end_offset', 'end_address'))
                    values.append((hex(l.entry_offset),
                        raw.entry_type if self.prefix else raw.entry_type[7:],
                        '' if is_def_loc else (hex(raw_start) if raw_start_type >= 2 else str(raw_start)),
                        '' if is_def_loc else (hex(raw_end) if raw_end_type >= 2 or (raw_end_type == 1 and self.hex) else str(raw_end)),
                        hex(base + l.begin_offset),
                        hex(base + l.end_offset),
                        ' '.join("%02x" % b for b in l.loc_expr),
                        expr_dump,
                        expr))
                else:
                    values.append((hex(l.entry_offset),
                        'Range',
                        hex(base + l.begin_offset),
                        hex(base + l.end_offset),
                        ' '.join("%02x" % b for b in l.loc_expr),
                        expr_dump,
                        expr))
    else: # Not low level
        headers = ("Start address", "End address", "Expression")
        for l in ll:
            if 'base_address' in l._fields:
                cu_base = l.base_address
            else:
                try: # Catching #1609
                    expr = self.parse_expr(l.loc_expr)
                    expr_dump = self.format_expr(expr, 5)
                except KeyError as exc:
                    expr = None
                    expr_dump = "<unrecognized expression>"
                    from .__main__ import version
                    from .crash import report_crash
                    from inspect import currentframe
                    report_crash(exc, exc.__traceback__, version, currentframe())
                base = base_for_entry(l)
                values.append((hex(base + l.begin_offset),
                    hex(base + l.end_offset),
                    expr_dump,
                    expr))
                
    def get_tooltip(row, col, entry):
        if len(entry) >= 2 and is_parsed_expression(entry[-1]):
            return 'Double-click for details'
        elif lowlevel and ver5:
            return lowlevel_v5_tooltips(raw_ll[row], col-2)

    return GenericTableModel(headers, values, get_tooltip=get_tooltip)
    
def resolve_cfa(self):
    rules = get_frame_rules_for_die(self.die)
    if not rules: # Shorting out 1747
        return None
    rules = [r['cfa'] for r in rules if 'cfa' in r]
    rules = [r for (i, r) in enumerate(rules) if i == 0 or rules[i-1].reg != r.reg or rules[i-1].offset != r.offset]
    if len(rules) == 1:
        rule = rules[0]
        if rule.expr is None:
            return self.expr_formatter.regname(rule.reg) + format_offset(rule.offset)
    return None