[![License: MPL 2.0](https://img.shields.io/badge/License-MPL%202.0-brightgreen.svg)](https://opensource.org/licenses/MPL-2.0)
[![TravisCI Build Status](https://travis-ci.org/advancedtelematic/ota-plus-tools.svg?branch=develop)](https://travis-ci.org/advancedtelematic/ota-plus-tools)
# ota-plus-tools

CLI tool for interacting with OTA+.

## Command Line Interface

To see a list of all subcommands, run: `ota-plus help`

### Getting started

1. Initialize a local ota-plus cache with:
```
ota-plus init \
  --client-id ${CLIENT_ID} \
  --client-secret ${CLIENT_SECRET} \
  --tuf-url ${TUF_URL} \
  --token-url ${TOKEN_URL}
```

2. Generate a new Targets signing key with:
```
ota-plus tuf key gen \
  --name targets-01 \
  --type rsa
```

3. Push the Targets public key to the remote TUF repository with:
```
ota-plus tuf key push \
  --role targets \
  --name targets-01
```

4. Initialize the `targets.json` metadata with:
```
ota-plus tuf targets init \
  --expires ${TARGET_EXPIRY_UTC} \
  --version ${TARGET_VERSION}
```

5. Add new targets with:
```
ota-plus tuf targets add \
  --path ${TARGET_PATH} \
  --name ${TARGET_NAME} \
  --version ${TARGET_VERSION} \
  --length ${TARGET_LENGTH} \
  --url ${TARGET_URL} \
  --sha256 ${TARGET_HASH}
```

6. Sign the `targets.json` metadata with:
```
ota-plus tuf targets sign \
  --key targets-01
```

6. Push the `targets.json` metadata with:
```
ota-plus tuf targets push
```
