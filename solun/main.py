import os
from tqdm import tqdm
import argparse
import textwrap
import httpx
import bcrypt

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
    {blue}Solun-CLI is a tool for uploading files to Solun.{endc}

    Examples:
    {blue}solun file -p /path/to/file -b -pw "YourPassword" -e2e -ad 1d{endc}

    Arguments:
    {blue}-p, --path:{endc} Path to the file to be uploaded.
    {blue}-b, --bruteforceSafe:{endc} Enable brute force protection (default: disabled).
    {blue}-pw, --password:{endc} Set a password for the file (default: None).
    {blue}-e2e, --endToEndEncryption:{endc} Enable end-to-end encryption (default: disabled).
    {blue}-ad, --autoDeletion:{endc} Set auto deletion parameter - options: download, 1d, 1w, 1m, 3m, 6m, 1y, never (default: download).
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
    
class FileStreamWrapper:
    def __init__(self, generator):
        self.generator = generator

    def read(self, size=-1):
        try:
            return next(self.generator)
        except StopIteration:
            return b''


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

    args = parser.parse_args()

    if hasattr(args, 'func'):
        response = args.func(args).json()
        print('+' + '-' * (box_width - 2) + '+')
        print('Message: ' + response['message'])
        print('File URL: ' + response['link'])
        print('+' + '-' * (box_width - 2) + '+')
    else:
        parser.print_help()

if __name__ == "__main__":
    main()