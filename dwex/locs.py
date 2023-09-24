from elftools.dwarf.locationlists import LocationParser, LocationExpr
from .details import GenericTableModel
from .dwarfutil import *

def show_location(self, attr):
# Expression is a list of ints
    ll = self.parse_location(attr)
    if isinstance(ll, LocationExpr):
        return GenericTableModel(("Command",), ((cmd,) for cmd in self.dump_expr(ll.loc_expr)))
    else:
        cu_base = get_cu_base(self.die)
        values = list()
        if self.lowlevel:
            headers = ("Start offset", "End offset", "Expr bytes", "Expression")
            for l in ll:
                if 'base_address' in l._fields:
                    cu_base = l.base_address
                    values.append(("(base)", hex(cu_base), '', ''))
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
                        ' '.join("%02x" % b for b in l.loc_expr),
                        expr_dump))
        else: # Not low level
            headers = ("Start offset", "End offset", "Expression")
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

        return GenericTableModel(headers, values)    