# Auth-JWT NGINX Module

This is an NGINX module to check for a valid JWT and proxy to an upstream server or redirect to a login page. It supports additional features such as extracting claims from the JWT and placing them on the request/response headers.

## Breaking Changes with v2

The `v2` branch, which has now been merged to `master` includes breaking changes. Please see the initial v2 release for details,

## Dependencies

This module depends on the [JWT C Library](https://github.com/benmcollins/libjwt). Transitively, that library depends on a JSON Parser called [Jansson](https://github.com/akheron/jansson) as well as the OpenSSL library.

## Directives

This module requires several new `nginx.conf` directives, which can be specified at the `http`, `server`, or `location` levels.

| Directive                            | Description                                                                                                                                          |
| ------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| `auth_jwt_key`                       | The key to use to decode/verify the JWT, *in binhex format* -- see below.                                                                            |
| `auth_jwt_redirect`                  | Set to "on" to redirect to `auth_jwt_loginurl` if authentication fails.                                                                              |
| `auth_jwt_loginurl`                  | The URL to redirect to if `auth_jwt_redirect` is enabled and authentication fails.                                                                   |
| `auth_jwt_enabled`                   | Set to "on" to enable JWT checking.                                                                                                                  |
| `auth_jwt_algorithm`                 | The algorithm to use. One of: HS256, HS384, HS512, RS256, RS384, RS512                                                                               |
| `auth_jwt_location`                  | Indicates where the JWT is located in the request -- see below.                                                                                      |
| `auth_jwt_validate_sub`              | Set to "on" to validate the `sub` claim (e.g. user id) in the JWT.                                                                                   |
| `auth_jwt_extract_request_claims`    | Set to a space-delimited list of claims to extract from the JWT and set as request headers. These will be accessible via e.g: `$http_jwt_sub`        |
| `auth_jwt_extract_response_claims`   | Set to a space-delimited list of claims to extract from the JWT and set as response headers. These will be accessible via e.g: `$sent_http_jwt_sub`  |
| `auth_jwt_use_keyfile`               | Set to "on" to read the key from a file rather than from the `auth_jwt_key` directive.                                                               |
| `auth_jwt_keyfile_path`              | Set to the path from which the key should be read when `auth_jwt_use_keyfile` is enabled.                                                            |


## Algorithms

The default algorithm is `HS256`, for symmetric key validation. When using one of the `HS*` algorithms, the value for `auth_jwt_key` should be specified in binhex format. It is recommended to use at least 256 bits of data (32 pairs of hex characters or 64 characters in total). Note that using more than 512 bits will not increase the security. For key guidelines please see [NIST Special Publication 800-107 Recommendation for Applications Using Approved Hash Algorithms](https://csrc.nist.gov/publications/detail/sp/800-107/rev-1/final), Section 5.3.2 The HMAC Key.

To generate a 256-bit key (32 pairs of hex characters; 64 characters in total):

```bash
openssl rand -hex 32
```

### Additional Supported Algorithms

The configuration also supports RSA public key validation via (e.g.) `auth_jwt_algorithm RS256`. When using the `RS*` alhorithms, the `auth_jwt_key` field must be set to your public key **OR** `auth_jwt_use_keyfile` should be set to `on` and `auth_jwt_keyfile_path` should point to the public key on disk. NGINX won't start if `auth_jwt_use_keyfile` is set to `on` and a key file is not provided.

When using an `RS*` algorithm with an inline key, be sure to set `auth_jwt_key` to the _public key_, rather than a PEM certificate. E.g.:

```nginx
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

When using an `RS*` algorithm with a public key file, do as follows:

```nginx
auth_jwt_use_keyfile on;
auth_jwt_keyfile_path "/path/to/pub_key.pem";
```

A typical use case would be to specify the key and login URL at the `http` level, and then only turn JWT authentication on for the locations which you want to secure (or vice-versa). Unauthorized requests will result in a `302 Moved Temporarily` response with the `Location` header set to the URL specified in the `auth_jwt_loginurl` directive, and a querystring parameter `return_url` whose value is the current / attempted URL.

If you prefer to return `401 Unauthorized` rather than redirect, you may turn `auth_jwt_redirect` off:

```nginx
auth_jwt_redirect off;
```
## JWT Locations

By default, the`Authorization` header is used to provide a JWT for validation. However, you may use the `auth_jwt_location` directive to specify the name of the header or cookie which provides the JWT:

```nginx
auth_jwt_location HEADER=auth-token;  # get the JWT from the "auth-token" header
auth_jwt_location COOKIE=auth-token;  # get the JWT from the "auth-token" cookie
```

## `sub` Validation

Optionally, the module can validate that a `sub` claim (e.g. the user's id) exists in the JWT. You may enable this feature as follows:

```nginx
auth_jwt_validate_sub on;
```

## Extracting Claims from the JWT

You may specify claims to be extracted from the JWT and placed on the request and/or response headers. This is especially handly because the claims will then also be available as NGINX variables.

If you only wish to access a claim as an NGINX variable, you should use `auth_jwt_extract_request_claims` so that the claim does not end up being sent to the client as a response header. However, if you do want the claim to be sent to the client in the response, then use `auth_jwt_extract_response_claims` instead.

_Please note that `number`, `boolean`, `array`, and `object` claims are not supported at this time -- only `string` claims are supported._ An error will be thrown if you attempt to extract a non-string claim.

### Using Request Claims

For example, you could configure an NGINX location which redirects to the current user's profile. Suppose `sub=abc-123`, the configuration below would redirect to `/profile/abc-123`.

```nginx
location /profile/me {
    auth_jwt_extract_request_claims sub;

    return 301 /profile/$http_jwt_sub;
}
```

### Using Response Claims

Response claims are used in the same way, with the only differences being:
 - the variables are accessed via the `$sent_http_jwt_*` pattern, e.g. `$sent_http_jwt_sub`, and
 - the headers are sent to the client.

### Extracting Multiple Claims

You may extract multiple claims by specifying all claims as arguments to a single directive, or by supplying multiple directives. The following two examples are equivalent.

```nginx
auth_jwt_extract_request_claims sub firstName lastName;
```

```nginx
auth_jwt_extract_request_claims sub;
auth_jwt_extract_request_claims firstName;
auth_jwt_extract_request_claims lastName;
```

## Versioning

This module has historically not been versioned, however, we are now starting to version the module in order to add clarity. We will add releases here in GitHub with additional details. In the future we may also publish pre-built modules for a selection of NGINX versions.

## Contributing

If you'd like to contribute to this repository, please first initiate the Git hooks by running `./.bin/init` (note the `.` before `bin`) -- this will ensure that tests are run before you push your changes.

### Environment Set-up for Visual Studio Code

1. Install the C/C++ extension from Microsoft.
2. Add a C/C++ config file at `.vscode/c_cpp_properties.json` with the following (or similar) content:

```json
{
    "configurations": [
        {
            "name": "Linux",
            "includePath": [
                "${workspaceFolder}/**",
                "~/Projects/nginx/objs/**",
                "~/Projects/nginx/src/**",
                "~/Projects/libjwt/include/**",
                "~/Projects/jansson/src/**"
            ],
            "defines": [],
            "compilerPath": "/usr/bin/clang",
            "cStandard": "c17",
            "cppStandard": "c++14",
            "intelliSenseMode": "linux-clang-x64"
        }
    ],
    "version": 4
}
```

Note the `includePath` additions above -- please update them as appropriate. Next we need to pull these sources.

#### Building NGINX

1. Download the NGINX release matching the version you're targeting.
2. Extract the NGINX archive to wherever you'd like.
3. Update the `includePath` entires shown above to match the location you chose.
4. Enter the directory where you extracted NGINX and run: `./configure --with-compat`

#### Cloning `libjwt`

1. Clone this repository as follows (replace `<target_dir>`): `git clone git@github.com:benmcollins/libjwt.git <target_dir>`
2. Enter the directory and switch to the latest tag: `git checkout $(git tag | sort -Vr | head -n 1)`
3. Update the `includePath` entires shown above to match the location you chose.

#### Cloning `libjansson`

1. Clone this repository as follows (replace `<target_dir>`): `git clone git@github.com:akheron/jansson.git <target_dir>`
2. Enter the directory and switch to the latest tag: `git checkout $(git tag | sort -Vr | head -n 1)`
3. Update the `includePath` entires shown above to match the location you chose.

#### Verifying Compliation

Once you save your changes to `.vscode/c_cpp_properties.json`, you should see that warnings and errors in the Problems panel go away, at least temprorarily. Hopfeully they don't come back, but if they do, make sure your include paths are set correctly.

### Building and Testing

The `./scripts.sh` file contains multiple commands to make things easy:

| Command               | Description                                                       |
| --------------------- | ----------------------------------------------------------------- |
| `build_module`        | Builds the NGINX image.                                           |
| `rebuild_module`      | Re-builds the NGINX image.                                        |
| `start_nginx`         | Starts the NGINX container.                                       |
| `stop_nginx`          | Stops the NGINX container.                                        |
| `cp_bin`              | Copies the compiled binaries out of the NGINX container.          |
| `build_test_runner`   | Builds the images used by the test stack (uses Docker compose).   |
| `rebuild_test_runner` | Re-builds the images used by the test stack.                      |
| `test`                | Runs `test.sh` against the NGINX container (uses Docker compose). |
| `test_now`            | Runs `test.sh` without rebuilding.                                |

You can run multiple commands in sequence by separating them with a space, e.g.:

```shell
./scripts.sh build_module test
```

To build the Docker images, module, start NGINX, and run the tests against, you can simply do:

```shell
./scripts.sh all
```

When you make a change to the module run `./scripts.sh build_module test` to build a fresh module and run the tests. Note that `rebuild_module` is not often needed as `build_module` hashes the module's source files which will cause a cache miss while building the container, causing the module to be rebuilt.

When you make a change to the test NGINX config or `test.sh`, run `./scripts.sh test` to run the tests. Similar to above, the test sources are hashed and the containers will be rebuilt as needed.

The image produced with `./scripts.sh build_module` only differs from the official NGINX image in two ways:
 - the JWT module itself, and
 - the `nginx.conf` file is overwritten with our own.

The tests use a customized NGINX image, distinct from the main image, as well as a test runner image. By running `./scripts.sh test`, the two test containers will be stood up via Docker compose, then they'll be started, and the tests will run. At the end of the test run, both containers will be automatically stopped and destroyed. See below to learn how to trace test failures across runs.

#### Tracing Test Failures

After making changes and finding that some tests fail, it can be difficult to understand why. By default, logs are written to Docker's internal log mechanism, but they won't be persisted after the test run completes and the containers are removed.

If you'd like to persist logs across test runs, you can configure the log driver to use `journald` (on Linux/Unix systems for example). You can do this by setting the environment variable `LOG_DRIVER` before running the tests:

```shell
# need to rebuild the test runner with the proper log driver
LOG_DRIVER=journald ./scripts.sh rebuild_test_runner

# run the tests
./scripts.sh test

# check the logs
journalctl -eu docker CONTAINER_NAME=jwt-nginx-test
```

Now you'll be able to see logs from previous test runs. The best way to make use of this  is to open two terminals, one where you run the tests, and one where you follow the logs:

```shell
# terminal 1
./scripts.sh test

# terminal 2
journalctl -fu docker CONTAINER_NAME=jwt-nginx-test
```
