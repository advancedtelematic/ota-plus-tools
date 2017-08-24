# ota-plus-tools

CLI tool for interacting with OTA+.

## Command Line Interface

To see a list of all subcommands, run: `ota-plus help`

### Getting started

1. Initialize a new ota-plus repository with:
```
ota-plus init \
  --client-id ${CLIENT_ID} \
  --client-secret ${CLIENT_SECRET} \
  --repo-id ${REPO_ID} \
  --tuf-url ${TUF_URL} \
  --token-url ${TOKEN_URL}
```

2. Generate a new Targets signing key with:
```
ota-plus keygen \
  --role targets \
  --type rsa
```

3. Push the Targets public key to the remote TUF repository with:
```
ota-plus tuf pushkey \
  --role targets
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
  --target ${TARGET_NAME} \
  --length ${TARGET_LENGTH} \
  --url ${TARGET_URL} \
  --sha256 ${TARGET_HASH}
```

6. Sign the `targets.json` metadata with:
```
ota-plus tuf targets sign
```

6. Push the `targets.json` metadata with:
```
ota-plus tuf targets push
```
