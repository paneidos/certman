# Certificate Manager

Manage your certificate in the standardized p12 format.
This format can hold both your private key and your certificate,
making it ideal for storing your those together. You can then
use the export commands to extract the parts you need to supply
to your web server or other service.

## Create

```
certman create my-cert.p12 [--key-type rsa|ecdsa]
```

## Sign

```
certman sign my-cert.p12 [sign-with.p12] [--attributes cn:mydomain.com]
```

## Export

Your key and certificate are usually required in PEM format.

```
certman export key my-cert.p12
certman export certificate my-cert.p12
```