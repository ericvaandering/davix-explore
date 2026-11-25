#!/usr/bin/env python3
# Copyright European Organization for Nuclear Research (CERN) since 2012
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Obtain OAuth2 tokens the same way the Rucio server does.

This reproduces the client-credentials flow of ``rucio.core.oidc.request_token``
using only the contents of ``idpsecrets.json``: the admin client registration is
read from that file, the token endpoint is discovered from the issuer, and a
token is requested for a given audience and scope.

It is deliberately stand-alone -- it needs nothing but ``requests`` and the
secrets file, so it can be run on a host that has no Rucio installation and no
database access.

Examples
--------
    # Explicit audience and scope.
    get_oidc_token.py --audience https://storage.example.org \\
                            --scope 'storage.read:/ offline_access'

    # Show the claims instead of the raw token.
    get_oidc_token.py --audience https://storage.example.org \\
                            --scope 'storage.read:/' --decode

It can also be imported, in which case ``get_token()`` is the entry point:

    from get_oidc_token import get_token
    token = get_token(audience='https://storage.example.org',
                      scope='storage.read:/ offline_access',
                      idpsecrets='/opt/rucio/etc/idpsecrets.json',
                      issuer='wlcg')

Note that a successfully printed token is a bearer credential: anything that
can read the output can use it until it expires.
"""

import argparse
import base64
import binascii
import configparser
import hashlib
import json
import os
import sys
from typing import Any, Optional

import requests

DEFAULT_TIMEOUT = 30


class TokenError(Exception):
    """Anything that stops us from producing a token."""


def get_config_dirs() -> list[str]:
    """The directories Rucio looks in for its configuration, in order."""
    configdirs = [os.path.join(os.environ[var], 'etc', '')
                  for var in ('RUCIO_HOME', 'VIRTUAL_ENV', 'CONDA_PREFIX')
                  if var in os.environ]
    configdirs.append('/opt/rucio/etc/')
    return configdirs


def locate_idpsecrets(explicit: Optional[str] = None) -> str:
    """Find ``idpsecrets.json``.

    Preference order: the explicit path, ``$RUCIO_IDPSECRETS``, the
    ``oidc.idpsecrets`` option of the Rucio configuration file, then an
    ``idpsecrets.json`` sitting in one of the standard configuration
    directories.
    """
    if explicit:
        if not os.path.exists(explicit):
            raise TokenError('No such file: %s' % explicit)
        return explicit

    if env_path := os.environ.get('RUCIO_IDPSECRETS'):
        if not os.path.exists(env_path):
            raise TokenError('$RUCIO_IDPSECRETS points at a missing file: %s' % env_path)
        return env_path

    config = read_rucio_config()
    if config is not None:
        try:
            configured = config.get('oidc', 'idpsecrets')
        except (configparser.NoSectionError, configparser.NoOptionError):
            pass
        else:
            if os.path.exists(configured):
                return configured
            raise TokenError('Option "idpsecrets" in section "oidc" points at a '
                             'missing file: %s' % configured)

    for confdir in get_config_dirs():
        candidate = os.path.join(confdir, 'idpsecrets.json')
        if os.path.exists(candidate):
            return candidate

    raise TokenError('Could not locate idpsecrets.json; pass --idpsecrets')


def read_rucio_config() -> Optional[configparser.ConfigParser]:
    """Parse the Rucio configuration file, or return None if there is none."""
    if 'RUCIO_CONFIG' in os.environ:
        candidates = [os.environ['RUCIO_CONFIG']]
    else:
        candidates = [os.path.join(confdir, 'rucio.cfg') for confdir in get_config_dirs()]

    for candidate in candidates:
        if not os.path.exists(candidate):
            continue
        parser = configparser.ConfigParser()
        try:
            parser.read(candidate)
        except configparser.Error as error:
            raise TokenError('Failed to parse %s: %s' % (candidate, error)) from error
        return parser
    return None


def load_client(path: str, issuer_id: Optional[str] = None) -> tuple[str, str, str, str]:
    """Read one client registration out of ``idpsecrets.json``.

    The file maps an issuer nickname to a registration containing at least
    ``issuer``, ``client_id`` and ``client_secret``.  The entry to use is the
    one named by ``issuer_id``, else the one named by ``oidc.admin_issuer`` in
    the Rucio configuration, else -- if the file holds exactly one entry --
    that entry.

    :returns: (issuer_id, issuer, client_id, client_secret)
    """
    try:
        with open(path) as secrets_file:
            secrets = json.load(secrets_file)
    except OSError as error:
        raise TokenError('Failed to read %s: %s' % (path, error)) from error
    except json.JSONDecodeError as error:
        raise TokenError('Failed to parse %s: %s' % (path, error)) from error

    if not isinstance(secrets, dict) or not secrets:
        raise TokenError('%s does not contain any client registrations' % path)

    if issuer_id is None:
        config = read_rucio_config()
        if config is not None:
            try:
                issuer_id = config.get('oidc', 'admin_issuer')
            except (configparser.NoSectionError, configparser.NoOptionError):
                pass

    if issuer_id is None:
        if len(secrets) > 1:
            raise TokenError('%s holds several issuers (%s); choose one with --issuer'
                             % (path, ', '.join(sorted(secrets))))
        issuer_id = next(iter(secrets))

    if issuer_id not in secrets:
        raise TokenError('No issuer "%s" in %s; available: %s'
                         % (issuer_id, path, ', '.join(sorted(secrets))))

    entry = secrets[issuer_id]
    try:
        return issuer_id, entry['issuer'], entry['client_id'], entry['client_secret']
    except (KeyError, TypeError) as error:
        raise TokenError('Entry "%s" in %s is missing %s' % (issuer_id, path, error)) from error


def discover_token_endpoint(issuer: str) -> str:
    """Resolve the token endpoint from the issuer's OIDC discovery document."""
    # urljoin() would drop the last path segment of an issuer that does not end
    # in a slash, which matters for issuers that live under a path.
    url = issuer.rstrip('/') + '/.well-known/openid-configuration'
    try:
        response = requests.get(url, timeout=DEFAULT_TIMEOUT)
        response.raise_for_status()
        return response.json()['token_endpoint']
    except requests.RequestException as error:
        raise TokenError('Failed to fetch %s: %s' % (url, error)) from error
    except (ValueError, KeyError) as error:
        raise TokenError('No token endpoint in the discovery document at %s: %s'
                         % (url, error)) from error


def request_token(token_endpoint: str, client_id: str, client_secret: str,
                  audience: str, scope: str) -> str:
    """Request a token with the client-credentials grant."""
    try:
        response = requests.post(url=token_endpoint,
                                 auth=(client_id, client_secret),
                                 data={'grant_type': 'client_credentials',
                                       'audience': audience,
                                       'scope': scope},
                                 timeout=DEFAULT_TIMEOUT)
    except requests.RequestException as error:
        raise TokenError('Request to %s failed: %s' % (token_endpoint, error)) from error

    if not response.ok:
        # The body of an OAuth2 error carries the actual reason; it is far more
        # useful than the status code on its own.
        raise TokenError('The provider refused the request (HTTP %s): %s'
                         % (response.status_code, response.text.strip()))

    try:
        return response.json()['access_token']
    except (ValueError, KeyError) as error:
        raise TokenError('No access token in the response from %s: %s'
                         % (token_endpoint, error)) from error


def resolve_client(idpsecrets: Optional[str] = None,
                   issuer: Optional[str] = None) -> dict[str, str]:
    """Resolve everything needed to request a token, short of requesting one.

    Locates the secrets file, picks a client registration out of it and
    discovers the token endpoint.

    :returns: a dict with keys ``secrets_path``, ``issuer_id``, ``issuer``,
        ``client_id``, ``client_secret`` and ``token_endpoint``.
    """
    secrets_path = locate_idpsecrets(idpsecrets)
    issuer_id, issuer_url, client_id, client_secret = load_client(secrets_path, issuer)
    return {
        'secrets_path': secrets_path,
        'issuer_id': issuer_id,
        'issuer': issuer_url,
        'client_id': client_id,
        'client_secret': client_secret,
        'token_endpoint': discover_token_endpoint(issuer_url),
    }


def get_token(audience: str, scope: str, idpsecrets: Optional[str] = None,
              issuer: Optional[str] = None) -> str:
    """Obtain a token for an audience and scope.  The one-call entry point.

    This is the whole flow end to end: locate the secrets file, pick a client
    registration out of it, discover the token endpoint and request the token.
    It is also what the command line drives, so anything reachable from the CLI
    is reachable from here.

    :param audience: the Audience claim to request, e.g. a storage hostname.
    :param scope: the space-separated Scope claim, e.g. ``'storage.read:/'``.
    :param idpsecrets: path to ``idpsecrets.json``.  If None, falls back to
        ``$RUCIO_IDPSECRETS``, then the ``oidc.idpsecrets`` option of the Rucio
        configuration, then ``idpsecrets.json`` in a configuration directory.
    :param issuer: which entry of the secrets file to use, by its nickname (the
        key, not the issuer URL).  If None, falls back to the ``oidc.admin_issuer``
        option, then to the sole entry if the file holds only one.
    :returns: the access token.
    :raises TokenError: if the token could not be obtained, for any reason.

    Example
    -------
        from get_oidc_token import get_token
        token = get_token('https://storage.example.org', 'storage.read:/')
    """
    client = resolve_client(idpsecrets, issuer)
    return request_token(client['token_endpoint'], client['client_id'],
                         client['client_secret'], audience, scope)


def decode_claims(token: str) -> dict[str, Any]:
    """Decode a JWT payload without verifying it.

    The signature is the identity provider's business; we only want to show the
    operator what they just asked for.
    """
    try:
        payload = token.split('.')[1]
    except IndexError as error:
        raise TokenError('The token is not a JWT') from error
    # JWTs are base64url without padding.
    payload += '=' * (-len(payload) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(payload))
    except (binascii.Error, ValueError) as error:
        raise TokenError('Failed to decode the token payload: %s' % error) from error


def cache_key(audience: str, scope: str) -> str:
    """The key the server would cache this token under."""
    return hashlib.md5(f'audience={audience};scope={scope}'.encode()).hexdigest()  # noqa: S324


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('--idpsecrets', metavar='PATH',
                        help='path to idpsecrets.json (default: $RUCIO_IDPSECRETS, '
                             'the "idpsecrets" option of section "oidc", or '
                             'idpsecrets.json in a Rucio configuration directory)')
    parser.add_argument('--issuer', metavar='NICKNAME',
                        help='which entry of idpsecrets.json to use (default: the '
                             '"admin_issuer" option of section "oidc", or the sole '
                             'entry if there is only one)')

    target = parser.add_argument_group(
        'target',
        'What the token is for.  Give --audience with --scope.')
    target.add_argument('--audience', metavar='AUDIENCE',
                        help='the audience to request')
    target.add_argument('--scope', metavar='SCOPE',
                        help='the space-separated scopes to request')

    output = parser.add_argument_group('output')
    output.add_argument('--decode', action='store_true',
                        help='print the token claims instead of the token itself')
    output.add_argument('--verbose', '-v', action='store_true',
                        help='report the client, endpoint, audience, scope and cache '
                             'key on stderr')
    return parser


def resolve_target(args: argparse.Namespace) -> tuple[str, str]:
    """Work out the audience and scope from the command line."""
    if not args.audience:
        raise TokenError('Nothing to request; give --audience and --scope')
    if args.scope is None:
        raise TokenError('--audience needs --scope')
    return args.audience, args.scope


def main() -> int:
    args = build_parser().parse_args()

    try:
        audience, scope = resolve_target(args)

        client = resolve_client(args.idpsecrets, args.issuer)

        if args.verbose:
            print('secrets:   %s' % client['secrets_path'], file=sys.stderr)
            print('issuer:    %s (%s)' % (client['issuer'], client['issuer_id']), file=sys.stderr)
            print('client_id: %s' % client['client_id'], file=sys.stderr)
            print('endpoint:  %s' % client['token_endpoint'], file=sys.stderr)
            print('audience:  %s' % audience, file=sys.stderr)
            print('scope:     %s' % scope, file=sys.stderr)
            print('cache key: %s' % cache_key(audience, scope), file=sys.stderr)

        token = request_token(client['token_endpoint'], client['client_id'],
                              client['client_secret'], audience, scope)

        if args.decode:
            print(json.dumps(decode_claims(token), indent=2, sort_keys=True))
        else:
            print(token)
    except TokenError as error:
        print('error: %s' % error, file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130

    return 0


if __name__ == '__main__':
    sys.exit(main())
