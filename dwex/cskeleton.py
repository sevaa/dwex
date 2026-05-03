from .dwarfutil import parse_datatype, safe_DIE_name, subprogram_name, DIE_has_name
from .tree import load_children


def get_die_c_type_str(die):
    """Resolves a DIE's type into a C-style type string."""

    def format_td(td):
        if not td.name:
            return "void"

        if td.tag in ('subroutine', 'ptr_to_member_type', 'ptr_to_member'):
            return td.name

        base_name = td.name
        scopes_str = "::".join(td.scopes) + "::" if td.scopes else ""

        post_modifiers = []
        pre_modifiers = []

        # Process modifiers from right-to-left (inner-to-outer) to build C-style declarations
        for mod in reversed(list(td.modifiers)):
            if mod == 'pointer':
                post_modifiers.append('*')
            elif mod == 'reference':
                post_modifiers.append('&')
            elif mod == 'const':
                # Heuristic: if a pointer/ref is already present, this 'const' applies to it.
                if any(m in ['*', '&'] for m in post_modifiers):
                    post_modifiers.append('const')
                else:
                    pre_modifiers.append('const')
            else:  # Other modifiers like volatile, etc.
                pre_modifiers.append(mod)

        pre_str = " ".join(pre_modifiers)
        post_str = " ".join(post_modifiers)

        # Assemble and clean up whitespace
        full_str = f"{pre_str} {scopes_str}{base_name}{post_str}"
        return " ".join(full_str.split())

    try:
        td = parse_datatype(die)
        return format_td(td)
    except Exception:
        return "/*<error_resolving_type>*/"


def traverse_and_generate_c_skeleton(die, depth, lines, sortdies=False):
    """Recursively traverses the DIE tree and generates C skeleton lines."""
    indent = '\t' * depth
    tag = die.tag

    # Skip tags handled by their parents (e.g., parameters are part of the function signature)
    if tag == 'DW_TAG_formal_parameter':
        return

    if tag in ('DW_TAG_structure_type', 'DW_TAG_class_type', 'DW_TAG_union_type'):
        keyword = tag.replace('DW_TAG_', '').replace('_type', '')
        name = safe_DIE_name(die, '')
        lines.append(f"{indent}{keyword} {name} {{")

        load_children(die, sortdies)
        if die._children:
            for child in die._children:
                traverse_and_generate_c_skeleton(child, depth + 1, lines, sortdies)

        lines.append(f"{indent}}};")

    elif tag == 'DW_TAG_member':
        type_str = get_die_c_type_str(die)
        name = safe_DIE_name(die, '?')
        bitsize_str = ""
        if 'DW_AT_bit_size' in die.attributes:
            bitsize = die.attributes['DW_AT_bit_size'].value
            bitsize_str = f" : {bitsize}"
        lines.append(f"{indent}{type_str} {name}{bitsize_str};")

    elif tag == 'DW_TAG_subprogram':
        ret_type_str = get_die_c_type_str(die)
        name = subprogram_name(die, '?')

        params = []
        load_children(die, sortdies)
        children_to_process = die._children or []

        for child in children_to_process:
            if child.tag == 'DW_TAG_formal_parameter':
                param_type_str = get_die_c_type_str(child)
                param_name = safe_DIE_name(child, '')
                params.append(f"{param_type_str} {param_name}".strip())
            elif child.tag == 'DW_TAG_unspecified_parameters':
                params.append('...')

        params_str = ", ".join(params) if params else "void"
        lines.append(f"{indent}{ret_type_str} {name}({params_str}) {{")

        for child in children_to_process:
            if child.tag not in ('DW_TAG_formal_parameter', 'DW_TAG_unspecified_parameters'):
                traverse_and_generate_c_skeleton(child, depth + 1, lines, sortdies)

        lines.append(f"{indent}}}")

    elif tag == 'DW_TAG_variable':
        type_str = get_die_c_type_str(die)
        name = safe_DIE_name(die, '?')
        lines.append(f"{indent}{type_str} {name};")

    elif tag == 'DW_TAG_lexical_block':
        lines.append(f"{indent}{{ // Lexical Block")
        load_children(die, sortdies)
        if die._children:
            for child in die._children:
                traverse_and_generate_c_skeleton(child, depth + 1, lines, sortdies)
        lines.append(f"{indent}}}")

    else:
        # Fallback for other DIE types: print original text and recurse
        text = f"{tag}: {safe_DIE_name(die, '')}" if DIE_has_name(die) else tag
        lines.append(indent + "// " + text)
        load_children(die, sortdies)
        if die._children:
            for child in die._children:
                traverse_and_generate_c_skeleton(child, depth + 1, lines, sortdies)
