import os
from tqdm import tqdm
import argparse
import textwrap
import httpx
import bcrypt
import getpass

box_width = 60

def print_custom_help():
    blue = '\033[94m'
    endc = '\033[0m'

    cli_header = f"""
{blue}+------------------------------------------------------+
|                       Solun-CLI                      |
+------------------------------------------------------+{endc}
    """
    print(cli_header)

    print(blue + '+' + '-' * (box_width - 2) + '+' + endc)

    examples_and_info = f"""
    {blue}Solun-CLI is a tool for uploading and downloading files from Solun.{endc}

    Examples:
    {blue}solun file -p /path/to/file -b -pw "YourPassword" -e2e -ad 1d{endc}
    {blue}solun download -l https://solun.pm/file/xyz{endc}

    Arguments:
    {blue}-p, --path:{endc} Path to the file to be uploaded.
    {blue}-b, --bruteforceSafe:{endc} Enable brute force protection (default: disabled).
    {blue}-pw, --password:{endc} Set a password for the file (default: None).
    {blue}-e2e, --endToEndEncryption:{endc} Enable end-to-end encryption (default: disabled).
    {blue}-ad, --autoDeletion:{endc} Set auto deletion parameter - options: download, 1d, 1w, 1m, 3m, 6m, 1y, never (default: download).
    {blue}-l, --link:{endc} Link to the file to be downloaded.
    """
    print(textwrap.indent(textwrap.dedent(examples_and_info), ' ' * 4))
    print(blue + '+' + '-' * (box_width - 2) + '+' + endc)

def hash_password(password):
    try:
        salt = bcrypt.gensalt(10)

        hashed_password = bcrypt.hashpw(password.encode(), salt)
        return hashed_password.decode()
    except Exception as e:
        print("Error: " + str(e))
        return ''
    
def extract_file_id_and_secret(url):
    parts = [part for part in url.split('/') if part]
    file_id_index = parts.index('file') + 1
    file_id = parts[file_id_index] if len(parts) > file_id_index else None
    secret = parts[file_id_index + 1] if len(parts) > file_id_index + 1 else None

    return file_id, secret
class FileStreamWrapper:
    def __init__(self, generator):
        self.generator = generator

    def read(self, size=-1):
        try:
            return next(self.generator)
        except StopIteration:
            return b''
        
def convert_bytes(size):
    for x in ['bytes', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return '%.2f %s' % (size, x)
        size /= 1024.0

def upload_file(args):
    url = 'https://api.solun.pm/file/upload'

    total_size = os.path.getsize(args.path)

    with tqdm(total=total_size, unit='B', unit_scale=True, desc='Uploading file') as pbar:
        def file_stream():
            with open(args.path, 'rb') as f:
                while chunk := f.read(4096):
                    pbar.update(len(chunk))
                    yield chunk

        files = {'file': (args.path, FileStreamWrapper(file_stream()))}
        data = {
            'bruteforceSafe': args.bruteforceSafe,
            'password': 'null' if args.password == 'null' else hash_password(args.password),
            'endToEndEncryption': args.endToEndEncryption,
            'autoDeletion': args.autoDeletion
        }
        
        with httpx.Client(timeout=None) as client:
            response = client.post(url, files=files, data=data)

    return response

def download_file(args):
    check_url = 'https://api.solun.pm/file/check'
    receive_url = 'https://api.solun.pm/file/receive'
    download_url = 'https://api.solun.pm/file/download'
    password = ''

    file_id, secret = extract_file_id_and_secret(args.link)

    check_data = {'id': file_id}
    with httpx.Client(timeout=None) as client:
        check_response = client.post(check_url, json=check_data).json()

    if check_response['valid'] == False:
        print('+' + '-' * (box_width - 2) + '+')
        print('Error: Invalid file ID')
        print('+' + '-' * (box_width - 2) + '+')
        return

    if check_response['password'] == True:
        print('+' + '-' * (box_width - 2) + '+')
        print('This file is password protected.')
        password = getpass.getpass(prompt='Enter password: ')
        print('+' + '-' * (box_width - 2) + '+')

    if secret:
        receive_data = {'id': file_id, 'password': password, 'secret': secret}
    else:
        receive_data = {'id': file_id, 'password': password}

    with httpx.Client(timeout=None) as client:
        receive_response = client.post(receive_url, json=receive_data).json()

    if 'message' in receive_response:
        print('+' + '-' * (box_width - 2) + '+')
        print('Error:', receive_response['message'])
        print('+' + '-' * (box_width - 2) + '+')
        return

    if receive_response['valid'] == True:
        print('+' + '-' * (box_width - 2) + '+')
        print('File Information:')
        print('File Name: ' + receive_response['name'])
        print('File Size: ' + convert_bytes(receive_response['size']))
        print('File Type: ' + receive_response['type'])
        print('+' + '-' * (box_width - 2) + '+')

    # input "Do you really want to download this file? (y/n): "
    user_response = input("Do you really want to download this file? (y/n): ").strip().lower()
    if user_response == 'y':
        print("Saving file to current directory...")

        if secret:
            download_data = {'id': file_id, 'secret': secret}
        else:
            download_data = {'id': file_id}

        with httpx.Client(timeout=None) as client:
            download_response = client.post(download_url, json=download_data)

        with open(receive_response['name'], 'wb') as f:
            for chunk in download_response.iter_bytes():
                f.write(chunk)

        print("File downloaded successfully.")

        # Delete file from server
        delete_url = 'https://api.solun.pm/file/delete'
        if secret:
            delete_data = {'id': file_id, 'secret': secret, 'encryptAgain': True, 'forceDeleteOn1Download': True}
        else:
            delete_data = {'id': file_id, 'encryptAgain': True, 'forceDeleteOn1Download': True}

        with httpx.Client(timeout=None) as client:
            delete_response = client.post(delete_url, json=delete_data)
        
        print(delete_response.json()['message'])

    elif user_response == 'n':
        print("Download cancelled.")
    else:
        print("Invalid response. Please enter 'y' for yes or 'n' for no.")

    return

def main():
    parser = argparse.ArgumentParser(description='Solun-CLI', formatter_class=argparse.RawTextHelpFormatter, add_help=True)
    parser.print_help = lambda: print_custom_help()
    subparsers = parser.add_subparsers(help='sub-command help')

    file_parser = subparsers.add_parser('file', help='Upload a file')
    file_parser.add_argument('-p', '--path', required=True, help='Path to the file')
    file_parser.add_argument('-b', '--bruteforceSafe', action='store_true', help='Enable brute force protection (default: false')
    file_parser.add_argument('-pw', '--password', default='null', help='Set a password for the file')
    file_parser.add_argument('-e2e', '--endToEndEncryption', action='store_true', help='Enable end-to-end encryption (default: false)')
    file_parser.add_argument('-ad', '--autoDeletion', default='download', help='Set auto deletion parameter - download, 1d, 1w, 1m, 3m, 6m, 1y, never (default: download)')
    file_parser.set_defaults(func=upload_file)

    download_parser = subparsers.add_parser('download', help='Download a file')
    download_parser.add_argument('-l', '--link', required=True, help='Link to the file')
    download_parser.set_defaults(func=download_file)

    args = parser.parse_args()

    if hasattr(args, 'func'):
        response = args.func(args)
        
        if args.func == download_file:
            pass
        else:
            response_json = response.json()
            print('+' + '-' * (box_width - 2) + '+')
            print('Message:', response_json['message'])
            print('File URL:', response_json['link'])
            print('+' + '-' * (box_width - 2) + '+')
    else:
        parser.print_help()

if __name__ == "__main__":
    main()