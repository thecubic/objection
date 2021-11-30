# objection
Utilities for AndroidAPS settings exports

It's not really interesting to do anything with this other than pass all the objectives instantly, which unlocks AndroidAPS into being fully functional.

This has been tested against AndroidAPS 2.8.2.1, which does not have the unlock shortcut and requires more than two months of burn to unlock all the functions.

## Installation

You don't need to install if you have [Click](https://github.com/pallets/click/) and [cryptography](https://github.com/pyca/cryptography) modules already installed, you could run it directly, e.g. `./objection-dump --help`

Otherwise, `pip install -r requirements.txt .` in this directory

### Scripts

- `objection-dump` will show you the status of objectives in a particular settings file
- `objection-pass` will pass all the known objectives in a particular settings file
- `objection-reset` will reset all the known objectives in a particular settings file
- `objection-pwchg` will change the password of a settings file
- `objection-edit` will allow you to interactively (REPL) edit a settings file

## Isn't this dangerous?

It is your freedom and thus your responsibility to use this app (and AndroidAPS) the way you see fit.  I suggest not harming yourself or anyone else with software.

Please read `LICENSE`.  The Disclaimer of Warranty and Limitation of Liability exactly cover a developer's obligations in this area.
