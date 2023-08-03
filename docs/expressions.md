# About Python expressions in DWEX

The "search by condition" and "highlight by condition" features of DWEX invite the user
to provide a Python expression to search or highlight the DIEs in the tree.
The expression has to be written in the Python 3, and **it should evaluate to some kind of an object**. Python distinguishes between expressions and statements. The `return` in the expression is not needed - that would make it a statement. The result of the expression will be interpreted as a boolean according to the Python rules.

The exression receives a `die`
object to work with. The object comes from the [pyelftools](https:/github.com/eliben/pyelftools/)
library, and is properly documented there, but here are the basics.

The expression can use Python's built-ins in the default global scope, but can't import modules.

## The DIE object
The `die` object contains a string field called `tag` and a dictionary called `attributes`.
The `tag` is the DIE tag's full name, as provided in the DWARF spec, with the `DW_TAG_` prefix
and with the same capitalization as in the spec, e. g. `DW_TAG_variable` or `DW_TAG_subprogram`.
Since Python's string comparison is case sensitive, capitalization might matter.

The `attributes` field is a dictionary (a `dict`). The keys are the full attribute names, with the `DW_AT_` prefix, and with the same capitalization as in the spec, e. g. `DW_AT_name` or `DW_AT_type`. The values in the dictionary are objects with the following properties:

 - `name` (string)
 - `form` (string)
 - `value`
 - `raw_value`

DIE attribute values that are logically strings are stored as `bytes` objects, not as proper Python strings. Use `decode()` to convert them to strings.

The distinction between `value` and `raw_value` can be seen in DWEX if one enables the low level view. Note that the DIE value that DWEX displays is somewhat translated further; this mostly goes for enum-type values like `DW_AT_language`. For DIE attributes of that nature, the `value` that the user expression works with is a number.

There is more to the `die` object that this; you can get to the parent/child/sibling DIEs from it, you can get to the containing CU and to other CUs. This guide is not meant to be a complete reference, especially considering that it's someone else's API; refer to the [pyelftools](https:/github.com/eliben/pyelftools/) docs and/or sources for more.
