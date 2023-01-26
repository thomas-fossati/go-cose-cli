# go-cose-cli
command line interface around veraison/go-cose

## Install

```bash
go install github.com/thomas-fossati/go-cose-cli@latest
```

## Run

```bash
go-cose-cli -k ec256.json -a ES256 < /etc/passwd | xxd -p -r | cbor2diag.rb
```
