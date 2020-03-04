from veralint.checkers.cwe330_insecure_random import CWE330_InsecureRandom_Checker


def register(linter):
    linter.register_checker(CWE330_InsecureRandom_Checker(linter))
