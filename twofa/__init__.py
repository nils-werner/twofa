from __future__ import print_function, absolute_import
import os
import sys
import time
import base64
import getpass
import binascii

import click
import pyotp
import pyqrcode
import yaml
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def create_fernet(passwd, salt=None):
    if salt is None:
        salt = os.urandom(16)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=500000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(passwd))
    return Fernet(key), salt


def encrypt(data, passwd):
    f, salt = create_fernet(passwd)

    return f.encrypt(yaml.dump(data)), base64.b64encode(salt)


def decrypt(data, passwd, salt):
    salt = base64.b64decode(salt)
    f, _ = create_fernet(passwd, salt)

    return yaml.load(f.decrypt(data))


class Store(object):
    encrypted = False
    passwd = None

    def load_secrets(self):
        try:
            with open(os.path.expanduser('~/.twofa.yaml'), 'r') as outfile:
                data = yaml.load(outfile)
            if data['encrypted']:
                self.passwd = getpass.getpass("Enter password:")
                self.encrypted = True
                try:
                    data['secrets'] = decrypt(
                        data['secrets'], self.passwd, data['salt']
                    )
                except InvalidToken:
                    raise click.ClickException("Invalid password")

            return data['secrets']
        except (yaml.YAMLError, IOError):
            return {}

    def save_secrets(self, secrets, passwd=None):
        salt = ""
        if passwd is not None:
            self.passwd = passwd
            self.encrypted = True

        if passwd == "":
            self.encrypted = False

        if self.encrypted:
            secrets, salt = encrypt(secrets, self.passwd)

        data = {
            'encrypted': self.encrypted,
            'salt': salt,
            'secrets': secrets
        }

        with open(os.path.expanduser('~/.twofa.yaml'), 'w') as outfile:
            yaml.dump(data, outfile, default_flow_style=False)


def totp(secret):
    return pyotp.TOTP(secret).now()


@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx):
    if ctx.invoked_subcommand is None:
        return listcmd()


@cli.command(name='list')
def listcmd():
    store = Store()
    secrets = store.load_secrets()

    for label, secret in secrets.items():
        click.echo("{} - {}".format(totp(secret), label))

    click.echo("")
    expire = 30 - (int(time.time()) % 30)
    click.echo("Tokens expire in: {}s".format(expire))


@cli.command(name='add')
@click.argument('label')
@click.argument('secret')
def addcmd(label, secret):
    store = Store()
    secrets = store.load_secrets()

    if secrets.get(label):
        raise click.ClickException("Service '{}' already found. Aborting.".format(label))

    try:
        secret = "".join(secret.split())
        totp(secret)
        secrets[label] = secret
    except (TypeError, binascii.Error):
        raise click.ClickException(
            "Could not parse secret. Make sure to only use Base32 characters"
            " and no spaces"
        )

    store.save_secrets(secrets)


@cli.command(name='rename')
@click.argument('label')
@click.argument('new_label')
def renamecmd(label, new_label):
    store = Store()
    secrets = store.load_secrets()

    try:
        secrets[new_label] = secrets[label]
        del secrets[label]
    except KeyError:
        raise click.ClickException("Service '{}' not found. Aborting.".format(label))

    store.save_secrets(secrets)


@cli.command(name='rm')
@click.argument('label')
@click.option('--confirm/--no-confirm', default=False)
def rmcmd(label, confirm):
    store = Store()
    secrets = store.load_secrets()

    if not confirm:
        raise click.UsageError("Please confirm removal using --confirm option. Aborting.")

    try:
        del secrets[label]
    except KeyError:
        raise click.ClickException("Service '{}' not found. Aborting.".format(label))

    store.save_secrets(secrets)


@cli.command(name='qr')
@click.argument('label')
@click.option('--invert/--no-invert', default=False)
def qrcmd(label, invert):
    store = Store()
    secrets = store.load_secrets()
    secret = secrets.get(label)

    if secret:
        qr = pyqrcode.create(
            'otpauth://totp/{}?secret={}'.format(label, secret.upper())
        )
        if invert:
            click.echo(qr.terminal(
                module_color='black', background='white', quiet_zone=1
            ))
        else:
            click.echo(qr.terminal(quiet_zone=1))
    else:
        raise click.ClickException("Service '{}' not found.".format(label))


@cli.command(name='passwd')
def passwdcmd():
    store = Store()
    secrets = store.load_secrets()

    newpasswd = getpass.getpass("Enter new password:")
    confirmpasswd = getpass.getpass("Confirm new password:")

    if not newpasswd == confirmpasswd:
        raise click.ClickException("New passwords did not match. Aborting.")

    store.save_secrets(secrets, newpasswd)
