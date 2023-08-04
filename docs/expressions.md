# About Python expressions in DWEX

The "search by condition" and "highlight by condition" features of DWEX invite the user
to provide a Python expression to search or highlight the DIEs in the tree.
The expression has to be written in the Python 3, and **it should evaluate to some kind of an object**. Python distinguishes between expressions and statements. The `return` in the expression is not allowed - that would make it a statement. The result of the expression will be interpreted as a boolean according to the Python rules - if it evaluates to `True`, the respective DIE will be found or highlighted. If the expression raises an error, that is interpreted as a `False`, and the respective DIE won't be found or highlighted.

# Expression execution environment

During search or checking for highlighting, the exression is evaluated against every DIE in the tree. During execution, the expression receives a set of current DIE's properties to examine as global scope variables.

The `tag` object contains the DIE tag's full name as a string, as provided in the DWARF spec, with the `DW_TAG_` prefix and with the same capitalization as in the spec, e. g. `DW_TAG_variable` or `DW_TAG_subprogram`.

Each DIE attribute is provided as a separate object, their names being full attribute names, with the `DW_AT_` prefix, and with the same capitalization as in the spec, e. g. `DW_AT_name` or `DW_AT_type`,
and their values are attribute values, somewhat translated by pyelftools for usability. DIE attribute values that are logically strings are stored as `bytes` objects, not as proper Python strings. One may use `.decode('utf-8')` to convert them to strings. Enum-type attributes such as `DW_AT_language` are provided as `int`s.

For deeper examination, DWEX also provides a dictionary of all attributes in an object called `attr`,
and the DIE itself as the `die` object. You can use `die` to get to the parent/child/sibling DIEs, you can get to the containing CU and to other CUs. This guide is not meant to be a complete reference, especially considering that it's someone else's API; refer to the [pyelftools](https:/github.com/eliben/pyelftools/) docs and/or sources for more.
 
The expression can use Python's built-ins in the default global scope, but can't import modules.