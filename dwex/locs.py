from elftools.dwarf.locationlists import LocationParser, LocationExpr, BaseAddressEntry
from .details import GenericTableModel
from .dwarfutil import *
from .ranges import one_of, lowlevel_v5_tooltips

def parse_location(self, attr):
    di = self.die.dwarfinfo
    if di._locparser is None:
        di._locparser = LocationParser(di.location_lists())
    return di._locparser.parse_from_attribute(attr, self.die.cu['version'], die = self.die)

def show_location(self, attr):
# Expression is a list of ints
# TODO: clickable expression maybe?
# TODO: truncate long expressions?
    ll = self.parse_location(attr)
    if isinstance(ll, LocationExpr):
        # TODO: low level maybe
        # Spell out args?
        # Opcode tooltips?
        return GenericTableModel(("Command",), ((cmd,) for cmd in self.dump_expr(ll.loc_expr)))
    else: # Loclist
        cu_base = get_cu_base(self.die)
        values = list()
        if self.lowlevel:
            ver5 = self.die.cu['version'] >= 5
            if ver5:
                headers = ("Entry offset", "Type", "Start/Index/Base", "End/Index/Length", "Start address", "End address", "Expr bytes", "Expression")
                raw_ll = self.die.dwarfinfo.location_lists().get_location_lists_at_offset_ex(attr.value)
            else:
                headers = ("Entry offset", "Type", "Start address", "End address", "Expr bytes", "Expression")
            for (i, l) in enumerate(raw_ll if ver5 else ll):
                if ver5: #l is raw
                    raw = l
                    l = ll[i] # Translated entry

                if isinstance(l, BaseAddressEntry):
                    cu_base = l.base_address
                    if ver5:
                        values.append((hex(l.entry_offset),
                            raw.entry_type if self.prefix else raw.entry_type[7:],
                            one_of(raw, ('address', 'index')),
                            '',
                            l.base_address,
                            '', '', ''))
                    else:
                        values.append((hex(l.entry_offset), 'Base', hex(l.base_address), '', '', ''))
                else:
                    try: # Catching #1609
                        expr_dump = '; '.join(self.dump_expr(l.loc_expr))
                    except KeyError as exc:
                        expr_dump = "<unrecognized expression>"
                        from .__main__ import version
                        from .crash import report_crash
                        from inspect import currentframe
                        report_crash(exc, exc.__traceback__, version, currentframe())
                    base = 0 if l.is_absolute else cu_base
                    if ver5:
                        is_def_loc = raw.entry_type == 'DW_LLE_default_location'
                        values.append((hex(l.entry_offset),
                            raw.entry_type if self.prefix else raw.entry_type[7:],
                            '' if is_def_loc else one_of(raw, ('start_offset', 'start_address', 'index', 'start_index')),
                            '' if is_def_loc else one_of(raw, ('end_offset', 'end_address', 'length', 'end_index')),
                            hex(base + l.begin_offset),
                            hex(base + l.end_offset),
                            ' '.join("%02x" % b for b in l.loc_expr),
                            expr_dump))
                    else:
                        values.append((hex(l.entry_offset),
                            'Range',
                            hex(base + l.begin_offset),
                            hex(base + l.end_offset),
                            ' '.join("%02x" % b for b in l.loc_expr),
                            expr_dump))
        else: # Not low level
            headers = ("Start address", "End address", "Expression")
            for l in ll:
                if 'base_address' in l._fields:
                    cu_base = l.base_address
                else:
                    try: # Catching #1609
                        expr_dump = '; '.join(self.dump_expr(l.loc_expr))
                    except KeyError as exc:
                        expr_dump = "<unrecognized expression>"
                        from .__main__ import version
                        from .crash import report_crash
                        from inspect import currentframe
                        report_crash(exc, exc.__traceback__, version, currentframe())
                    values.append((hex(cu_base + l.begin_offset),
                        hex(cu_base + l.end_offset),
                        expr_dump))
                    
        return GenericTableModel(headers, values,
            get_tooltip=lambda row, col: lowlevel_v5_tooltips(raw_ll[row], col-2) if self.lowlevel and ver5 else None)