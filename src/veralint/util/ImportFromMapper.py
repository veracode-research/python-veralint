from veralint.util import __DEBUG__, import_function_map


class ImportFromMapper(object):
    """A checker support class to build qualified ``import from`` maps

    A checker than inherits from this *in addition to* ``BaseChecker`` will get a map of
    fully-qualified function names imported. That is, such checkers will have a dict named
    ``_imports`` that can map an imported function name to where it was imported from

    See checkers/cwe330_insecure_random.py for an implementation example
    """
    def __init__(self):
        self._imports = {}

    def visit_importfrom(self, node):
        __DEBUG__ and print(node.as_string())
        importnames = []
        for name in node.names:
            (importname, realname) = import_function_map(node.modname, name)
            importnames.append(importname)
            self._imports[importname] = realname

        return importnames
