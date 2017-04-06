# twofa

A command-line 2-factor authentication manager.


## Installation

    pip install twofa


## Usage

**Print Token**

    2fa

**Add secret**

    2fa add 'Service Name' 'Secret'

**Delete secret**

    2fa rm --confirm 'Service Name'

**Rename Service**

    2fa rename 'Service Name' 'New Name'

**Print QR code**

    2fa qr 'Service Name'

if you are using a light terminal theme:

    2fa qr --invert 'Service Name'


### Security Considerations

The key file `~/.twofa.yaml` is not encrypted. Please consider encrypting your home partition if you need additional security.


### Bash autocomplete

We are using [Click bash integration](http://click.pocoo.org/5/bashcomplete/), which means you only need to add 

    eval "$(_2FA_COMPLETE=source 2fa)"

to your `~/.bashrc` to get autocompletion.
