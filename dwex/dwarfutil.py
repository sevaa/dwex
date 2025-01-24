from bisect import bisect_left
from elftools.dwarf.ranges import BaseAddressEntry as RangeBaseAddressEntry, RangeEntry
from elftools.dwarf.locationlists import LocationExpr
from elftools.dwarf.dwarf_expr import DWARFExprParser
from elftools.dwarf.callframe import FDE

from dwex.dwarfone import DWARFExprParserV1

class NoBaseError(Exception):
    pass

def has_code_location(die):
    attr = die.attributes
    return 'DW_AT_ranges' in attr or ('DW_AT_low_pc' in attr and 'DW_AT_high_pc' in attr)

class CodeLocationSimple:
    def __init__(self, attr):
        self.low = attr['DW_AT_low_pc'].value
        self.hi = attr['DW_AT_high_pc'].value
        if not attr['DW_AT_high_pc'].form == 'DW_FORM_addr':
            self.hi += self.low

    def start_address(self):
        return self.low
    
    def in_range(self, ip):
        return self.low <= ip < self.hi

    def intersects_fde(self, fde):
        fde_begin = fde.header.initial_location
        fde_end = fde_begin + fde.header.address_range
        return fde_begin < self.hi and self.low < fde_end

class CodeLocationRanges:
    def __init__(self, die):
        cu_base = None
        rl = get_die_ranges(die)
        l = []
        for r in rl:
            if isinstance(r, RangeEntry):
                if not r.is_absolute and cu_base is None:
                    cu_base = get_cu_base(die) # This may throw
                if r.is_absolute:
                    r = (r.begin_offset, r.end_offset)
                else:
                    r = (cu_base + r.begin_offset, cu_base + r.end_offset)
                l.append(r)
            else: # Base entry
                cu_base = r.base_address
        self.ranges = l

    def start_address(self):
        return min(*(low for (low, hi) in self.ranges))
    
    def in_range(self, ip):
        return any(1 for (low, hi) in self.ranges if low <= ip < hi)

    def intersects_fde(self, fde):
        fde_begin = fde.header.initial_location
        fde_end = fde_begin + fde.header.address_range        
        return any(1 for (low, hi) in self.ranges if fde_begin < hi and low < fde_end)

# Returns a code location object - range or ranges
# May throw a NoBaseError
def get_code_location(die):
    attr = die.attributes
    if 'DW_AT_ranges' in attr:
        return CodeLocationRanges(die)
    else:
        return CodeLocationSimple(attr)

# Respects caching. None if no ranges section. Returns the raw ranges
def get_die_ranges(die):
    di = die.dwarfinfo
    if not di._ranges:
        di._ranges = di.range_lists()
    if not di._ranges:
        return None
    return di._ranges.get_range_list_at_offset(die.attributes['DW_AT_ranges'].value, cu=die.cu)

# Doesn't return None, returns False if not found
def get_di_frames(di):
    if di._frames is None:
        has_cfi = di.has_CFI()
        if di.has_EH_CFI():
            if has_cfi:
                di._frames = di.EH_CFI_entries() + di.CFI_entries()
            else:
                di._frames = di.EH_CFI_entries()
        elif has_cfi:
            di._frames = di.CFI_entries()
        else:
            di._frames = False
    return di._frames

def get_frame_rules_for_die(die):
    """
       Returns a list of dictionaries with 'pc', 'cfa' and other registers, as found in DecodedCallFrameTable.table
       for the FDE entries that overlap with the range or ranges of the provided DIE.
    """
    frames = get_di_frames(die.dwarfinfo)
    if not frames:
        return None
    try:
        code_loc = get_code_location(die)
    except NoBaseError:
        return None
    entries = [f for f in frames if isinstance(f, FDE) and code_loc.intersects_fde(f)]
    return [de for e in entries for de in e.get_decoded().table]    

def is_inline(func):
    return 'DW_AT_inline' in func.attributes and func.attributes['DW_AT_inline'].value != 0

def DIE_type(die):
    return die.get_DIE_from_attribute("DW_AT_type")

def is_int_list(val):
    return isinstance(val, list) and len(val) > 0 and isinstance(val[0], int)

def is_block(form):
    return form in ('DW_FORM_block', 'DW_FORM_block1', 'DW_FORM_block2', 'DW_FORM_block4')

def DIE_name(die):
    return die.attributes['DW_AT_name'].value.decode('utf-8', errors='ignore')

# Supports both / and \ - current system separator might not match the system the file came from
# so os.path.basename won't do
def strip_path(filename):
    p = filename.rfind("/")
    pbsl = filename.rfind("\\")
    if pbsl >= 0 and (p < 0 or pbsl > p):
        p = pbsl
    return filename[p+1:] if p >= 0 else filename

def top_die_file_name(die, Default = 'N/A'):
    if DIE_has_name(die):
        source_name = DIE_name(die)
        return strip_path(source_name)
    elif 'DW_AT_decl_file' in die.attributes:
        val = die.attributes['DW_AT_decl_file'].value
        if val > 0:
            if die.cu._lineprogram is None:
                die.cu._lineprogram = die.dwarfinfo.line_program_for_CU(die.cu)
            delta = 1 if die.cu.version < 5 else 0
            return strip_path(die.cu._lineprogram.header.file_entry[val-delta].name.decode('utf-8', errors='ignore'))
    return Default

 # See #1742
def DIE_has_name(die):
    """DIE object has a name attribute and the name is bytes or compatible
    """
    return 'DW_AT_name' in die.attributes and die.attributes['DW_AT_name'].value is not None and hasattr(die.attributes['DW_AT_name'].value, 'decode')

def safe_DIE_name(die, default = ''):
    return die.attributes['DW_AT_name'].value.decode('utf-8', errors='ignore') if 'DW_AT_name' in die.attributes and die.attributes['DW_AT_name'].value is not None and hasattr(die.attributes['DW_AT_name'].value, 'decode') else default

def follow_ref_if_present(die, attr_name):
    return die.get_DIE_from_attribute(attr_name) if attr_name in die.attributes else die

def subprogram_name(die, default=''):
    """
        Gets name of a DIE. If not available, drills back to abstract_origin, then specification
    """
    if 'DW_AT_name' in die.attributes:
        return die.attributes['DW_AT_name'].value.decode('UTF-8')
    die = follow_ref_if_present(die, 'DW_AT_abstract_origin')
    if 'DW_AT_name' in die.attributes:
        return die.attributes['DW_AT_name'].value.decode('UTF-8')
    die = follow_ref_if_present(die, 'DW_AT_specification')
    if 'DW_AT_name' in die.attributes:
        return die.attributes['DW_AT_name'].value.decode('UTF-8')
    return default

def DIE_is_ptr_to_member_struct(type_die):
    if type_die.tag == 'DW_TAG_structure_type':
        members = tuple(die for die in type_die.iter_children() if die.tag == "DW_TAG_member")
        return len(members) == 2 and safe_DIE_name(members[0]) == "__pfn" and safe_DIE_name(members[1]) == "__delta"
    return False

class ClassDesc(object):
    def __init__(self):
        self.scopes = ()
        self.const_member = False

class TypeDesc(object):
    def __init__(self):
        self.name = None
        self.modifiers = () # Reads left to right
        self.scopes = () # Reads left to right
        self.tag = None   

# Address is relative to the preferred loading address
# Not generally applicable for pyelftools clients - relies on CU caching by dwex
def find_cu_by_address(di, address):
    if di._aranges:
        cuoffset = di._aranges.cu_offset_at_addr(address)
        if cuoffset is not None:
            cu = di._unsorted_CUs[bisect_left(di._CU_offsets, cuoffset)]
            if cu.cu_offset == cuoffset:
                return cu
    return next((cu for cu in di._unsorted_CUs if ip_in_range(cu.get_top_DIE(), address)), None)

# May return None or raise NoBaseError
def get_cu_base(die):
    top_die = die.cu.get_top_DIE()
    if 'DW_AT_low_pc' in top_die.attributes:
        return top_die.attributes['DW_AT_low_pc'].value
    elif 'DW_AT_entry_pc' in top_die.attributes:
        return top_die.attributes['DW_AT_entry_pc'].value
    elif 'DW_AT_ranges' in top_die.attributes:
        rl = get_die_ranges(top_die)
        if rl is None:
            raise NoBaseError()
        base = None
        for r in rl:
            if isinstance(r, RangeEntry) and r.is_absolute and (base is None or r.begin_offset < base):
                base = r.begin_offset
            elif isinstance(r, RangeBaseAddressEntry) and (base is None or r.base_address < base):
                base = r.base_address
        if base is None:
            raise NoBaseError()
        return base
    else:
        raise NoBaseError()

# Returns a list of DIEs objects for top level functions that contain the address
# Inlines analyzed later
# TODO: namespaces
def find_funcs_at_address(cu, address):
    funcs = []
    top_die = cu.get_top_DIE()
    di = cu.dwarfinfo
    first_die = next(top_die.iter_children())
    if first_die is None:
        return []
        
    has_siblings = "DW_AT_sibling" in first_die.attributes 
    if has_siblings:
        die_list = (die for die in cu.iter_DIE_children(top_die))
    else:
        die_list = (die for die in cu.iter_DIEs())

    for die in die_list:
        if die.tag in ('DW_TAG_subprogram', 'DW_TAG_global_subroutine') and has_code_location(die):
            if 'DW_AT_range' in die.attributes:
                cu_base = top_die.attributes['DW_AT_low_pc'].value
                rl = di._ranges.get_range_list_at_offset(die.attributes['DW_AT_ranges'].value, cu = die.cu)
                for r in rl:
                    if r.begin_offset <= address - cu_base < r.end_offset:
                        funcs.append(die)
            else:
                l = die.attributes['DW_AT_low_pc'].value
                h = die.attributes['DW_AT_high_pc'].value
                if not die.attributes['DW_AT_high_pc'].form == 'DW_FORM_addr':
                    h += l
                if address >= l and address < h:
                    funcs.append(die)
    return funcs

# Find helper:
# Returns true if the specified IP is in [low_pc, high_pc)
# Or in ranges
# TODO: rewrite with CodeLocation objects
def ip_in_range(die, ip):
    if 'DW_AT_ranges' in die.attributes:
        di = die.dwarfinfo
        if not di._ranges:
            di._ranges = di.range_lists()
        if not di._ranges: # Absent in the DWARF file
            return False
        # TODO: handle base addresses. Never seen those so far...
        cu_base = None
        rl = di._ranges.get_range_list_at_offset(die.attributes['DW_AT_ranges'].value, cu = die.cu)
        for r in rl:
            if isinstance(r, RangeBaseAddressEntry):
                cu_base = r.base_address
            else: # r is RangeEntry, which in DWARF5 can be absolute
                if not r.is_absolute and cu_base is None:
                    cu_base = get_cu_base(die)
                if r.begin_offset <= ip - (0 if r.is_absolute else cu_base) < r.end_offset:
                    return True
    if 'DW_AT_low_pc' in die.attributes and 'DW_AT_high_pc' in die.attributes:
        l = die.attributes['DW_AT_low_pc'].value
        h = die.attributes['DW_AT_high_pc'].value
        if die.attributes['DW_AT_high_pc'].form != 'DW_FORM_addr':
            h += l
        if l <= ip < h:
            return True
    return False

# returns (origin, spec)
def follow_function_spec(func_die):
    origin = func_die.get_DIE_from_attribute('DW_AT_abstract_origin') if 'DW_AT_abstract_origin' in func_die.attributes else func_die
    spec = origin.get_DIE_from_attribute('DW_AT_specification') if 'DW_AT_specification' in origin.attributes else origin
    return (origin, spec)

# Line program navigation - A2L core
# DWEX aware caching
def get_source_line(die, address):
    cu = die.cu
    if cu._lineprogram is None:
        cu._lineprogram = die.dwarfinfo.line_program_for_CU(cu)
    lp = cu._lineprogram
    v5 = cu.header.version >= 5
    file_and_line = None
    prevstate = None
    for entry in lp.get_entries():
        state = entry.state
        # We're interested in those entries where a new state is assigned
        if state is None:
            continue

        # Looking for a range of addresses in two consecutive states that
        # contain the required address.
        if prevstate and prevstate.address <= address < state.address and not file_and_line:
            file = (die.cu.get_top_DIE().attributes['DW_AT_name'].value if not v5 and prevstate.file == 0 else lp['file_entry'][prevstate.file + (0 if v5 else -1)].name).decode('UTF-8')
            line = prevstate.line
            file_and_line = (file, line)

        if state.end_sequence:
            prevstate = None
        else:
            prevstate = state
    return file_and_line

# Resolves source file number in an attribute to a file name
# None if no such attribute or no such file
# DWEX caching aware
def get_source_file_name_from_attr(die, attr_name):
    cu = die.cu
    if cu._lineprogram is None:
        cu._lineprogram = die.dwarfinfo.line_program_for_CU(cu)
    lp = cu._lineprogram
    if attr_name in die.attributes:
        file_no = die.attributes[attr_name].value
        if cu.header.version < 5:
            file_no -= 1
        file_entries = lp['file_entry']
        if file_no >= 0 and file_no < len(file_entries):
            return file_entries[file_no].name.decode('UTF-8')

# Returns (name, mangled_name)
def retrieve_function_names(func_spec, the_func):
    attr = func_spec.attributes
    func_name = DIE_name(func_spec)
    module = the_func.cu.get_top_DIE()
    lang = module.attributes['DW_AT_language'].value if 'DW_AT_language' in module.attributes else None
    if 'DW_AT_MIPS_linkage_name' in attr:
        mangled_func_name = func_spec.attributes['DW_AT_MIPS_linkage_name'].value.decode('UTF-8', errors='ignore')
    elif 'DW_AT_linkage_name' in attr:
        mangled_func_name = func_spec.attributes['DW_AT_linkage_name'].value.decode('UTF-8', errors='ignore')
    else: # Could be a plain-C function...
        mangled_func_name = func_name
        if lang in (0x1, 0x2, 0xc, 0x1d) or (has_code_location(func_spec) and "DW_AT_external" in attr) or "DW_AT_external" in the_func.attributes:
            return (func_name, func_name)
    # Sometimes addr2line spits without even (). Extern "C" maybe? 

    # TODO: augment func name with arguments for ones where it's relevant. External? cdecl?
    if lang in (0x4, 0x19,0x1a, 0x21): # C++
        func_name = generate_full_function_name(func_spec, the_func) 
    # TODO: Pascal, ObjC
    return (func_name, mangled_func_name)

def generate_full_function_name(func_spec, the_func):
    func_name = DIE_name(func_spec)

    spec_params = tuple(ps for ps in func_spec.iter_children() if ps.tag in ("DW_TAG_formal_parameter", "DW_TAG_unspecified_parameters") and 'DW_AT_artificial' not in ps.attributes)
    func_params = tuple(p for p in the_func.iter_children() if p.tag in ("DW_TAG_formal_parameter", "DW_TAG_unspecified_parameters") and 'DW_AT_artificial' not in p.attributes)
    params = tuple(format_function_param(*pp) for pp in zip(spec_params, func_params))
    class_spec = get_class_spec_if_member(func_spec, the_func)
    class_prefix = "::".join(class_spec.scopes) + "::" if class_spec and class_spec.scopes else ""
    class_postfix = " const" if class_spec and class_spec.const_member else ""
    # I've seen const marker on the this parameter that wasn't const in the source
    return class_prefix + func_name + "(" + ", ".join(params) + ")" + class_postfix

def format_function_param(param_spec, param):
    if param_spec.tag == 'DW_TAG_formal_parameter':
        if 'DW_AT_name' in param.attributes:
            name = DIE_name(param)
        elif 'DW_AT_name' in param_spec.attributes:
            name = DIE_name(param_spec)
        else:
            name = None
        type = parse_datatype(param_spec)
        type_name = type.name
        if type.scopes:
            scopes = "::".join(type.scopes) # Are there any case where namespace and class scopes vary?
            type_name = f"{scopes}::{type_name}"

        mods = type.modifiers
        cpp_symbols = {"pointer": "*", "reference" : "&", "const" : " const"}
        #Ad-hoc fixes
        if mods and len(mods) >= 2 and mods[-1] == "const": # const-ref-const to const-ref # mods[0] == "const" and 
            mods = mods[0:-1]
        # TODO: check if typedef matters            
        return type_name + "".join(cpp_symbols[mod] for mod in mods)
 
    else: #unspecified_parameters AKA variadic
        return "..."

# Follows the modifier chain
# Returns an object:
def parse_datatype(var):
    t = TypeDesc()
    if not 'DW_AT_type' in var.attributes:
        t.tag = ''
        return t

    type_die = var.get_DIE_from_attribute('DW_AT_type')

    mods = []
    last_typedef = None
    while type_die.tag in ('DW_TAG_typedef', 'DW_TAG_array_type', 'DW_TAG_const_type', 'DW_TAG_pointer_type', 'DW_TAG_reference_type'):
        if type_die.tag != 'DW_TAG_typedef':
            mods.insert(0, type_die.tag[7:-5])
            if not 'DW_AT_type' in type_die.attributes and "pointer" in mods:
                t.name = "void"
                t.modifiers = tuple(mods)
                t.tag = None
                return t
        else: # typedef
            last_typedef = DIE_name(type_die)
        type_die = type_die.get_DIE_from_attribute('DW_AT_type')
    t.modifiers = tuple(mods)

    if type_die.tag in ('DW_TAG_ptr_to_member_type', 'DW_TAG_subroutine_type'):
        t.tag = type_die.tag[7:-5]
        if t.tag == 'ptr_to_member':
            ptr_prefix = DIE_name(type_die.get_DIE_from_attribute('DW_AT_containing_type')) + "::"
            type_die = type_die.get_DIE_from_attribute('DW_AT_type')
        elif "DW_AT_object_pointer" in type_die.attributes: # Older compiler... Subroutine, but with an object pointer
            ptr_prefix = DIE_name(DIE_type(DIE_type(type_die.get_DIE_from_attribute('DW_AT_object_pointer')))) + "::"
        else: # Function pointer. Expect a pointer as the final modifier
            mods.pop()
            t.modifiers = tuple(mods)
            ptr_prefix = ''

        if t.tag == 'subroutine':
            params = tuple(format_function_param(p, p) for p in type_die.iter_children() if p.tag in ("DW_TAG_formal_parameter", "DW_TAG_unspecified_parameters") and 'DW_AT_artificial' not in p.attributes)
            params = ", ".join(params)
            if 'DW_AT_type' in type_die.attributes:
                retval_type = parse_datatype(type_die)
                retval_type = retval_type.name # TODO: modifiers...
            else:
                retval_type = "void"
            #class_spec = get_class_spec_if_member(func_spec, the_func)
            #class_prefix = class_spec.name + "::" if class_spec else ""
            #class_postfix = " const" if class_spec and class_spec.const_member else ""
            t.name = f"{retval_type} ({ptr_prefix}*)({params})"
            return t
    elif DIE_is_ptr_to_member_struct(type_die):
        dt =  parse_datatype(next(type_die.iter_children())) # The first element is pfn, a function pointer with a this
        dt.modifiers = tuple(dt.modifiers[:-1]) # Pop the extra pointer
        dt.tag = "ptr_to_member_type" # Not a function pointer per se
        return dt

    type_name = safe_DIE_name(type_die, last_typedef)
    
    # This only for compatibility with addr2line. Debugged on ARM64/Android, might have different encodings on different arches
    if type_die.tag == 'DW_TAG_base_type':
        if type_name.endswith(" int") and type_name != "unsigned int":
            type_name = type_name[:-4]
        if type_name.endswith(" unsigned"):
            type_name = "unsigned " + type_name[:-9]
    t.name = type_name

    # Check the nesting
    parent = type_die.get_parent()
    scopes = list()
    while parent.tag in ('DW_TAG_class_type', 'DW_TAG_structure_type', 'DW_TAG_namespace'):
        scopes.insert(0, DIE_name(parent))
        parent = parent.get_parent()
    t.scopes = tuple(scopes)
    
    return t

def get_class_spec_if_member(func_spec, the_func):
    if 'DW_AT_object_pointer' in the_func.attributes:
        this_param = the_func.get_DIE_from_attribute('DW_AT_object_pointer')
        this_type = parse_datatype(this_param)
        class_spec = ClassDesc()
        class_spec.scopes = this_type.scopes + (this_type.name,)
        class_spec.const_member = any(("const", "pointer") == this_type.modifiers[i:i+2]
            for i in range(len(this_type.modifiers))) # const -> pointer -> const for this arg of const 
        return class_spec

    # Check the parent element chain - could be a class
    parent = func_spec.get_parent()

    scopes = []
    while parent.tag in ("DW_TAG_class_type", "DW_TAG_structure_type", "DW_TAG_namespace"):
        scopes.insert(0, DIE_name(parent))
        parent = parent.get_parent()
    if scopes:
        cs = ClassDesc()
        cs.scopes = tuple(scopes)
        return cs

    return None


# scope is a function DIE with a code address
# returns (locals, next_scope)
# where locals is a list of (name, location)
# and next_scope is a inlined function DIE to examine next
# For now, local datatype is not returned
# location is a list of parsed DWARF operations or an empty list
# if the var has no matching location record for the given address
def scan_scope(scope, address):
    locals = []
    next_scope = None
    if 'DW_AT_frame_base' in scope.attributes:
        locals.append(('__frame_base', parse_location(scope.attributes['DW_AT_frame_base'], scope.cu, address), scope))
        #'Type': {'name': 'void', 'modifiers' : ("pointer",), "scopes": (), "tag": None}}
    
    for die in scope.iter_children():
        if die.tag == 'DW_TAG_variable' or die.tag == 'DW_TAG_formal_parameter':
            (k, v) = resolve_local(die, address)
            locals.append((k, v, die))
        elif die.tag == 'DW_TAG_lexical_block' and ip_in_range(die, address):
            (block_locals, next_scope) = scan_scope(die, address)
            locals += block_locals
        elif die.tag ==  'DW_TAG_inlined_subroutine' and ip_in_range(die, address):
            next_scope = die
    return (locals, next_scope)

# returns (name, location_expression)
def resolve_local(p, address):
    loc = False
    if 'DW_AT_abstract_origin' in p.attributes: # Inlined sub formal param
        if 'DW_AT_location' in p.attributes:
            loc = p.attributes['DW_AT_location']
            loc_cu = p.cu
        p = p.get_DIE_from_attribute('DW_AT_abstract_origin')

    #type = parse_datatype(p)
    if not loc and 'DW_AT_location' in p.attributes:
        loc = p.attributes['DW_AT_location']
        loc_cu = p.cu

    if loc:
        expr = parse_location(loc, loc_cu, address)
    else:
        expr = False

    name = safe_DIE_name(p, "(no name attribute)")
    return (name, expr)


def parse_location(loc, cu, address):
    # TODO: check v5 loclists
    ll = cu.dwarfinfo._locparser.parse_from_attribute(loc, cu['version']) # Either a list or a LocationExpr

    # Find the expression blob
    if isinstance(ll, LocationExpr):
        loc_expr = ll.loc_expr
    else: 
        top_die = cu.get_top_DIE()
        base = top_die.attributes['DW_AT_low_pc'].value
        loc_expr = False
        for l in ll:
            if 'base_address' in l._fields:
                base = l.base_address
            elif l.begin_offset <= address - base < l.end_offset:
                loc_expr = l.loc_expr
                break
            
    # Translate to usable format
    if loc_expr:
        # TODO: cache expr parser. Make sure CUs are cached in the dwarfinfo first.
        return list((DWARFExprParser(cu.structs) if cu['version'] > 1 else DWARFExprParserV1(cu.structs)).parse_expr(loc_expr))
    else:
        return []

def quote_filename(fn):
    return f'"{fn}"' if ' ' in fn else fn