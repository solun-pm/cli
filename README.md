# Solun-CLI

Solun-CLI is a command line interface tool for uploading files to Solun.

## Installation

Clone the repository and navigate to the project directory:

```bash
cd cli
pip install .
```

## Usage
The `solun` command can be used to upload files with optional settings for brute force protection, password, end-to-end encryption, and auto deletion.

### Basic Upload
Upload a file:

```bash
solun file -p /path/to/your/file
```

### Advanced Upload
Upload a file with brute force protection, a password, end-to-end encryption, and set an auto deletion parameter:

```bash
solun file -p /path/to/your/file -b -pw "YourPassword" -e2e -ad 1d
```

## Arguments
* -p, --path: Path to the file to be uploaded.
* -b, --bruteforceSafe: Enable brute force protection (default: disabled).
* -pw, --password: Set a password for the file (default: None).
* -e2e, --endToEndEncryption: Enable end-to-end encryption (default: disabled).
* -ad, --autoDeletion: Set auto deletion parameter. Options: download, 1d, 1w, 1m, 3m, 6m, 1y, never (default: download).

## Build and Publish
To build the package, run the following command:

```bash
pip install .
pip install build
python3 -m build
``` 

To publish the package, run the following command:

```bash
rm -rf solun.egg-info 
twine upload dist/*
```