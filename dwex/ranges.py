from .die import GenericTableModel
from elftools.dwarf.ranges import BaseAddressEntry as RangeBaseAddressEntry, RangeEntry
from .dwarfutil import get_cu_base, NoBaseError
from .details import GenericTableModel

def one_of(o, attrs):
    return next(((i, o[attr]) for (i,attr) in enumerate(attrs) if attr in o), (None, None))

def lowlevel_v5_tooltips(entry, col):
    type = entry.entry_type[7:]
    if col == 0: # Start
        if type == 'base_address':
            return 'Base address for entries below'
        elif type == 'offset_pair':
            return 'Starting offset relative to the current base'
        elif type == 'start_end' or type == 'start_length':
            return 'Starting address, absolute'
        elif type == 'base_addressx':
            return 'Index into the address table, resolving to absolute address'
        elif type == 'startx_endx' or type == 'startx_length':
            return 'Index into the address table, resolving to absolute address'
    elif col == 1: # End
        if type == 'offset_pair':
            return 'Ending offset relative to the current base'
        elif type == 'start_end':
            return 'Ending address, absolute'
        elif type == 'start_length' or type == 'startx_length':
            return 'Length of the range'
        elif type == 'startx_endx':
            return 'Index into the address table, resolving to absolute address'

# This is a method of DIETableModel
def show_ranges(self, attr):
    di = self.die.dwarfinfo
    if not di._ranges:
        di._ranges = di.range_lists()
    if not di._ranges: # Absent in the DWARF file
        return None
    v5 = self.die.cu['version'] >= 5
    ll = self.lowlevel

    if v5 and ll: # Dump untranslated v5 entries
        ranges = di._ranges.get_range_list_at_offset_ex(attr.value, cu = self.die.cu)
        has_relative_entries = next((r for r in ranges if r.entry_type == 'DW_RLE_offset_pair'), False)
    else:
        ranges = di._ranges.get_range_list_at_offset(attr.value, cu = self.die.cu)
        has_relative_entries = next((r for r in ranges if isinstance(r, RangeEntry) and not r.is_absolute), False)

    warn = None
    lines = []
    if len(ranges):
        cu_base = 0
        # Do we need the base address? We might not.
        if has_relative_entries and not isinstance(ranges[0], RangeBaseAddressEntry):
            try:
                cu_base = get_cu_base(self.die)
            except NoBaseError:
                warn = "Base address not found, assuming 0"

        for r in ranges:
            if v5 and ll: # Dump untranslated v5 entries
                # see _create_rnglists_parsers in elftools/dwarf/structs to see what can be in there
                (start_type, start) = one_of(r, ('index', 'start_index', 'start_offset', 'address', 'start_address'))
                (end_type, end) = one_of(r, ('end_index', 'length', 'end_offset', 'end_address'))
                translated = di._ranges.translate_v5_entry(r, self.die.cu)
                base = 0 if isinstance(translated, RangeEntry) and translated.is_absolute else cu_base
                lines.append((hex(r.entry_offset),
                    r.entry_type if self.prefix else r.entry_type[7:],
                    str(start) if start_type <= 1 else hex(start),
                    (str(end) if end_type == 0 or (end_type == 1 and not self.hex) else hex(end)) if end is not None else '',
                    hex(base + translated.begin_offset if isinstance(translated, RangeEntry) else translated.base_address), 
                    hex(base + translated.end_offset) if isinstance(translated, RangeEntry) else ''
                    ))
                if isinstance(translated, RangeBaseAddressEntry):
                    cu_base = translated.base_address
            else: # V4 or highlevel V5
                if isinstance(r, RangeEntry):
                    base = 0 if r.is_absolute else cu_base
                    if ll: # V4, low level
                        lines.append((hex(r.entry_offset),
                            "Range",
                            hex(r.begin_offset),
                            hex(r.end_offset),
                            hex(base + r.begin_offset),
                            hex(base + r.end_offset),
                            ))
                    else: # V4 high level or translated V5
                        lines.append((hex(base + r.begin_offset),
                                      hex(base + r.end_offset)))
                else: # Base entry
                    if ll:
                        lines.append((hex(r.entry_offset), "Base", hex(r.base_address), '', '', ''))
                    cu_base = r.base_address
    else:
        warn = "Empty range list"

    if v5 and ll:
        headers = ("Entry offset", "Type", "Start/Index/Base", "End/Index/Length", "Start address", "End address")
    elif ll: #Low level and V4
        headers = ("Entry offset", "Type", "Start offset/Base", "End offset", "Start address", "End address")
    else: 
        headers = ("Start address", "End address")
        
    return GenericTableModel(headers, lines, warn,
        get_tooltip=lambda row, col, _: lowlevel_v5_tooltips(ranges[row], col-2) if v5 and ll else None)
