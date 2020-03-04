# python-veralint
A collection of PyLint checkers for security issues

Checkers are implemented in sets:

1. The **master set**, all direct `.py` files inside the `veralint.checkers` package. These are general security lint checks suitable for any python application, and use the plugin name `veralint`
2. The **environment-specific set**, in packages *underneath* `veralint.checkers`. Each of these is its own plugin containing checks useful for a particular application environment (e.g. `veralint.checkers.django` implements checks that only matter for Django applications). The plugin names here match the package names.

The `veralint` package must be in your `PYTHONPATH` or pylint checkers library

## Examples

    # use the master set
    $ pylint --load-plugins=veralint file_to_check.py

The above will use the master set of checkers as part of a pylint run to check `file_to_check.py`

    # use the django environment-specific checkers
    $ pylint --load-plugins=veralint,veralint.checkers.django file_to_check.py
    
The above will use the master set (`veralint`) *and* the Django environment-specific checkers