# Intro
This is an NGINX module to check for a valid JWT and proxy to an upstream server or redirect to a login page.

## Building and testing
To build the Docker image, start NGINX, and run our Bash test against it, run

```bash
make
```

When you make a change to the module, run `make rebuild-nginx`.

When you make a change to `test.sh`, run `make rebuild-test-runner`.

| Command                    | Description                                                       |
| -------------------------- |:-----------------------------------------------------------------:|
| `make build-nginx`         | Builds the NGINX image                                            |
| `make rebuild-nginx`       | Re-builds the NGINX image                                         |
| `make build-test-runner`   | Builds the images used by the test stack (uses Docker compose)    |
| `make rebuild-test-runner` | Re-builds the images used by the test stack                       |
| `make start-nginx`         | Starts the NGINX container                                        |
| `make stop-nginx`          | Stops the NGINX container                                         |
| `make test`                | Runs `test.sh` against the NGINX container (uses Docker compose)  |

The image produced with `make build-nginx` only differs from the official Nginx image in two ways: the module itself and the nginx.conf configuration entry that loads it.

The tests use a customized Nginx image, distinct from the main image, as well as a test runner image.  By running `make test`, the two test containers will be created up with Docker compose, started, and the tests run.  At the end, both containers will be automatically stopped and destroyed.

This project is 100% Docker-ized.

## Dependencies
This module depends on the [JWT C Library](https://github.com/benmcollins/libjwt)

Transitively, that library depends on a JSON Parser called
[Jansson](https://github.com/akheron/jansson) as well as the OpenSSL library.

## NGINX Directives
This module requires several new `nginx.conf` directives,
which can be specified in on the `main` `server` or `location` level.

```
auth_jwt_key "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF"; # see docs for format based on algorithm
auth_jwt_loginurl "https://yourdomain.com/loginpage";
auth_jwt_enabled on;
auth_jwt_algorithm HS256;    # or RS256
auth_jwt_extract_sub on;     # or off
auth_jwt_validate_email on;  # or off
auth_jwt_use_keyfile off;    # or on
auth_jwt_keyfile_path "/app/pub_key";
```

The default algorithm is 'HS256', for symmetric key validation.  When using HS256, the value for `auth_jwt_key` should be specified in binhex format.  It is recommended to use at least 256 bits of data (32 pairs of hex characters or 64 characters in total) as in the example above.  Note that using more than 512 bits will not increase the security.  For key guidelines please see NIST Special Publication 800-107 Recommendation for Applications Using Approved Hash Algorithms, Section 5.3.2 The HMAC Key.

The configuration also supports the `auth_jwt_algorithm` 'RS256', for RSA 256-bit public key validation. If using "auth_jwt_algorithm RS256;", then the `auth_jwt_key` field must be set to your public key **OR** `auth_jwt_use_keyfile` should be set to `on` with the `auth_jwt_keyfile_path` set to the public key path (nginx won't start if the `auth_jwt_use_keyfile` is set to `on` without a keyfile).
That is the public key, rather than a PEM certificate.  I.e.:

```
auth_jwt_key "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0aPPpS7ufs0bGbW9+OFQ
RvJwb58fhi2BuHMd7Ys6m8D1jHW/AhDYrYVZtUnA60lxwSJ/ZKreYOQMlNyZfdqA
rhYyyUkedDn8e0WsDvH+ocY0cMcxCCN5jItCwhIbIkTO6WEGrDgWTY57UfWDqbMZ
4lMn42f77OKFoxsOA6CVvpsvrprBPIRPa25H2bJHODHEtDr/H519Y681/eCyeQE/
1ibKL2cMN49O7nRAAaUNoFcO89Uc+GKofcad1TTwtTIwmSMbCLVkzGeExBCrBTQo
wO6AxLijfWV/JnVxNMUiobiKGc/PP6T5PI70Uv67Y4FzzWTuhqmREb3/BlcbPwtM
oQIDAQAB
-----END PUBLIC KEY-----";
```

**OR**

```
auth_jwt_use_keyfile on;
auth_jwt_keyfile_path "/etc/nginx/pub_key.pem";
```

A typical use would be to specify the key and loginurl on the main level
and then only turn on the locations that you want to secure (not the login page).
Unauthorized requests are given 302 "Moved Temporarily" responses with a location of the specified loginurl.

```
auth_jwt_redirect            off;
```
If you prefer to return 401 Unauthorized, you may turn `auth_jwt_redirect` off.

```
auth_jwt_validation_type AUTHORIZATION;
auth_jwt_validation_type COOKIE=jwt;
```
By default the authorization header is used to provide a JWT for validation.
However, you may use the `auth_jwt_validation_type` configuration to specify the name of a cookie that provides the JWT.

```
auth_jwt_extract_sub
```
By default, the module will attempt to extract the `sub` claim (e.g. the user's id) from the JWT. If successful, the 
value will be set in the `x-userid` HTTP header. An error will be logged if this option is enabled and the JWT does not 
contain the `sub` claim.

```
auth_jwt_validate_email off;
```
By default, the module will attempt to validate the email address field of the JWT, then set the x-email header of the
session, and will log an error if it isn't found.  To disable this behavior, for instance if you are using a different
user identifier property such as `sub`, set `auth_jwt_validate_email` to the value `off`. _Note that this flag may be 
renamed to `auth_jwt_extract_email` in a future release._
