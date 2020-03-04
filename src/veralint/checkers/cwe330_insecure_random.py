from veralint.util import __DEBUG__, full_function_path, import_function_map
from pylint.checkers import BaseChecker
from pylint.interfaces import IAstroidChecker


class CWE330_InsecureRandom_Checker(BaseChecker):
    __implements__ = IAstroidChecker

    name = 'cwe0330-insecure-random'
    priority = -1
    msgs = {
        'W3301': (
            'Uses a predictable random number generator',
            'veralint-cwe330-insecure-random',
            '(CWE-330) Generates random values using an RNG that is not '
            'sufficiently random. Do not use for any security, safety, or '
            'other important purpose.'
        ),
        'W3302': (
            'Imports * from an unsafe RNG module',
            'veralint-cwe330-insecure-random-import-star',
            '(CWE-330) Imports all names from an unsafe random number '
            'generator module. Do not use imported RNG functions for any '
            'security, safety, or other important purpose.'
        )
    }
    # options = (
    #     (
            
    #     ),
    # )

    _unsafe_func_names = (
        'random.randrange',
        'random.randint',
        'random.choice',
        'random.random',
        'random.uniform',
        'random.triangular',
        'random.whseed',
    )

    _unsafe_imports = (
        'random.*'
    )

    def __init__(self, linter=None):
        super(CWE330_InsecureRandom_Checker, self).__init__(linter)
        self._imports = {}

    def visit_importfrom(self,node):
        __DEBUG__ and print(node.as_string())
        for name in node.names:
            (importname, realname) = import_function_map(node.modname, name)
            # realname = '{module}.{function}'.format(
            #     module=node.modname,function=name[0]
            # )
            #
            # if name[1] is None:
            #     importname = name[0]
            # else:
            #     importname = name[1]
            
            if realname in self._unsafe_imports:
                self.add_message(
                    'veralint-cwe330-insecure-random-import-star',
                    node=node
                )

            # __DEBUG__ and print("  {:s} as {:s}".format(realname, importname))

            self._imports[importname] = realname

    def visit_call(self, node):
        reportname = full_function_path(node)
        realname = reportname
        if reportname in self._imports:
            realname = self._imports[reportname]

        __DEBUG__ and print("Visit call '{}'".format(realname))

        if realname in self._unsafe_func_names:
            __DEBUG__ and print("  Unsafe call")
            self.add_message('veralint-cwe330-insecure-random', node=node)
