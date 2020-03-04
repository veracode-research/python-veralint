"""utility functions used by more than one Veralint checker"""
import astroid
import os

__DEBUG__ = False
# noinspection PyUnresolvedReferences
if os.getenv('DEBUG'):
    from pprint import pprint, pformat
    __DEBUG__ = True
else:
    pprint = print
    pformat = str


def full_function_path(node):
    if isinstance(node.func, astroid.node_classes.Name):
        reportname = node.func.name
    elif isinstance(node.func, astroid.node_classes.Attribute):
        reportname = '{module}.{function}'.format(
            module=node.func.expr.as_string(),
            function=node.func.attrname)
    else:
        return None

    return reportname


def import_function_map(modname, name):
    realname = '{module}.{function}'.format(
        module=modname, function=name[0]
    )

    if name[1] is None:
        importname = name[0]
    else:
        importname = name[1]

    __DEBUG__ and print("  {:s} as {:s}".format(realname, importname))

    return importname, realname
