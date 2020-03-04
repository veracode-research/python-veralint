from pylint.checkers import BaseChecker
from pylint.interfaces import IAstroidChecker

from veralint.util import __DEBUG__, full_function_path
from veralint.util.ImportFromMapper import ImportFromMapper


class CWE330_InsecureRandom_Checker(BaseChecker, ImportFromMapper):
    """CWE-330 Checks for use of the insecure RNGs from the ``random`` built-in module

    Contains two checks: first, if any known-to-be-insufficiently-random function is called,
    issues W3301. Second, if there is an ``from random import *`` statement, warns W3302. The second
    is because the checker can't tell statically what actually gets imported from ``random``, so
    it can't warn at time of use, unlike the first check.

    See: https://cwe.mitre.org/data/definitions/330.html for information about this weakness
    """
    __implements__ = IAstroidChecker

    name = 'cwe330-insecure-random'
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

    def visit_importfrom(self, node):
        for importname in super(CWE330_InsecureRandom_Checker, self).visit_importfrom(node):
            realname = self._imports[importname]
            if realname in self._unsafe_imports:
                self.add_message(
                    'veralint-cwe330-insecure-random-import-star',
                    node=node
                )

    def visit_call(self, node):
        reportname = full_function_path(node)
        realname = reportname
        if reportname in self._imports:
            realname = self._imports[reportname]

        __DEBUG__ and print("Visit call '{}'".format(realname))

        if realname in self._unsafe_func_names:
            __DEBUG__ and print("  Unsafe call")
            self.add_message('veralint-cwe330-insecure-random', node=node)
