from __future__ import print_function, absolute_import
import os
import sys
import time
import base64
import binascii

import click
import pyotp
import pyqrcode
import yaml


def load_secrets():
    try:
        with open(os.path.expanduser('~/.twofa.yaml'), 'r') as outfile:
            return yaml.load(outfile)
    except (yaml.YAMLError, IOError):
        return {}


def save_secrets(data):
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
    secrets = load_secrets()

    for label, secret in secrets.items():
        click.echo("{} - {}".format(totp(secret), label))

    click.echo("")
    expire = 30 - (int(time.time()) % 30)
    click.echo("Tokens expire in: {}s".format(expire))


@cli.command(name='add')
@click.argument('label')
@click.argument('secret')
def addcmd(label, secret):
    secrets = load_secrets()

    if secrets.get(label):
        click.echo("Service '{}' already found. Aborting.".format(label))
        return 1

    try:
        secret = "".join(secret.split())
        totp(secret)
        secrets[label] = secret
    except (TypeError, binascii.Error):
        click.echo(
            "Could not parse secret. Make sure to only use Base32 characters"
            " and no spaces"
        )
        return 1

    save_secrets(secrets)


@cli.command(name='rename')
@click.argument('label')
@click.argument('new_label')
def renamecmd(label, new_label):
    secrets = load_secrets()

    try:
        secrets[new_label] = secrets[label]
        del secrets[label]
    except KeyError:
        click.echo("Service '{}' not found. Aborting.".format(label))
        return 1

    save_secrets(secrets)


@cli.command(name='rm')
@click.argument('label')
@click.option('--confirm/--no-confirm', default=False)
def rmcmd(label, confirm):
    secrets = load_secrets()

    if not confirm:
        click.echo("Please confirm removal using --confirm option. Aborting.")
        return 1

    try:
        del secrets[label]
    except KeyError:
        click.echo("Service '{}' not found. Aborting.".format(label))
        return 1

    save_secrets(secrets)


@cli.command(name='qr')
@click.argument('label')
@click.option('--invert/--no-invert', default=False)
def qrcmd(label, invert):
    secrets = load_secrets()
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
        click.echo("Service '{}' not found.".format(label))
        return 1
