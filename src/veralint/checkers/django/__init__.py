from veralint.checkers.django.SQLi import CWE89_Django_SQLi_Checker


def register(linter):
    linter.register_checker(CWE89_Django_SQLi_Checker(linter))
