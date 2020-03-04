from veralint.util import __DEBUG__, import_function_map, full_function_path


class ImportFromMapper(object):
    """A checker support class to build qualified ``import from`` maps

    A checker than inherits from this *in addition to* ``BaseChecker`` will get a map of
    fully-qualified function names imported. That is, such checkers will have a dict named
    ``_imports`` that can map an imported function name to where it was imported from

    See checkers/cwe330_insecure_random.py for an implementation example
    """
    _unsafe_func_names = tuple()
    _unsafe_func_message = ''

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

    def visit_call(self, node):
        reportname = full_function_path(node)
        realname = reportname
        if reportname in self._imports:
            realname = self._imports[reportname]

        __DEBUG__ and print("Visit call '{}'".format(realname))

        if realname in self._unsafe_func_names:
            __DEBUG__ and print("  Unsafe call")
            self.add_message(self._unsafe_func_message, node=node)