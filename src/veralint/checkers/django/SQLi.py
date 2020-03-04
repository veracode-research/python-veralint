from pylint.checkers import BaseChecker
from pylint.interfaces import IAstroidChecker

from veralint.util import __DEBUG__, full_function_path
from veralint.util.ImportFromMapper import ImportFromMapper


class CWE89_Django_SQLi_Checker(BaseChecker, ImportFromMapper):
    """CWE-89 Checks for Django-based SQL Injection (SQLi)

    Checks for use of Django database query functions that are known to have SQLi most of the time.
    Can be an FP when developers are properly escaping using some unusual path or uses hard-coded,
    SQL statements with no tainted variables. However, using the raw SQL queries is still a code
    smell and warnings should still be issued.

    See: https://cwe.mitre.org/data/definitions/89.html for information about this weakness
    """
    __implements__ = IAstroidChecker

    name = 'cwe89-django-sqli'
    priority = -1
    msgs = {
        'W0891': (
            'Uses a Django method that takes raw SQL; Possible CWE-89 SQL Injection',
            'veralint-cwe89-django-raw',
            '(CWE-89) this Django method takes raw SQL'
        )
    }
    # options = (
    #     (

    #     ),
    # )

    _unsafe_func_names = (
        'django.db.models.expressions.RawSQL',
        'django.db.models.Model.objects.raw'
    )
    _unsafe_func_message = 'veralint-cwe89-django-raw'

    def __init__(self, linter=None):
        super(CWE89_Django_SQLi_Checker, self).__init__(linter)
        self._imports = {}
