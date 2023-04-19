# Intro

This is an NGINX module to check for a valid JWT and proxy to an upstream server or redirect to a login page.

## Building and testing

To build the Docker image, start NGINX, and run our Bash test against it, run

```bash
./scripts.sh all
```

When you make a change to the module or the NGINX test config, run `./scripts.sh rebuild_nginx` to rebuild the NGINX Docker image.

When you make a change to `test.sh`, run `./scripts.sh rebuild_test_runner test` to rebuild the test runner image and run the tests.

The `./scripts.sh` file contains multiple commands to make things easy:

| Command               | Description                                                       |
| --------------------- | ----------------------------------------------------------------- |
| `build_nginx`         | Builds the NGINX image.                                           |
| `rebuild_nginx`       | Re-builds the NGINX image.                                        |
| `start_nginx`         | Starts the NGINX container.                                       |
| `stop_nginx`          | Stops the NGINX container.                                        |
| `cp_bin`              | Copies the compiled binaries out of the NGINX container.          |
| `build_test_runner`   | Builds the images used by the test stack (uses Docker compose).   |
| `rebuild_test_runner` | Re-builds the images used by the test stack.                      |
| `test`                | Runs `test.sh` against the NGINX container (uses Docker compose). |

You can run multiple commands in sequence by separating them with a space, e.g.:

```shell
./scripts.sh rebuild_nginx rebuild_test_runner test
```

The image produced with `./scripts.sh build_nginx` only differs from the official NGINX image in two ways:
 - the JWT module itself, and
 - the `nginx.conf` file is overwritten with our own.

The tests use a customized NGINX image, distinct from the main image, as well as a test runner image. By running `./scripts.sh test`, the two test containers will be stood up via Docker compose, then they'll be started, and the tests will run. At the end of the test run, both containers will be automatically stopped and destroyed. See below to learn how to trace test failures across runs.

### Tracing test failures

After making changes and finding that some tests fail, it can be difficult to understand why. By default, logs are written to Docker's internal log mechanism, but they won't be persisted after the test run completes and the containers are removed.

In order to persist logs, you can configure the log driver to use. You can do this by setting the environment variable `LOG_DRIVER` before running the tests. On Linux/Unix systems, you can use the driver `journald`, as follows:

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

## Dependencies

This module depends on the [JWT C Library](https://github.com/benmcollins/libjwt). Transitively, that library depends on a JSON Parser called [Jansson](https://github.com/akheron/jansson) as well as the OpenSSL library.

## NGINX Directives
This module requires several new `nginx.conf` directives, which can be specified at the `http`, `server`, or `location` levels.

| Directive                  | Description                                                                                                        |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `auth_jwt_key`             | The key to use to decode/verify the JWT, *in binhex format* -- see below.                                          |
| `auth_jwt_redirect`        | Set to "on" to redirect to `auth_jwt_loginurl` if authentication fails.                                            |
| `auth_jwt_loginurl`        | The URL to redirect to if `auth_jwt_redirect` is enabled and authentication fails.                                 |
| `auth_jwt_enabled`         | Set to "on" to enable JWT checking.                                                                                |
| `auth_jwt_algorithm`       | The algorithm to use. One of: HS256, HS384, HS512, RS256, RS384, RS512                                             |
| `auth_jwt_extract_sub`     | Set to "on" to extract the `sub` claim (e.g. user id) from the JWT and into the `x-userid` header on the response. |
| `auth_jwt_validate_email`  | Set to "on" to extract the `emailAddress` claim from the JWT and into the `x-email` header on the response.        |
| `auth_jwt_use_keyfile`     | Set to "on" to read the key from a file rather than from the `auth_jwt_key` directive.                             |
| `auth_jwt_keyfile_path`    | Set to the path from which the key should be read when `auth_jwt_use_keyfile` is enabled.                          |


The default algorithm is `HS256`, for symmetric key validation. When using one of the `HS*` algorithms, the value for `auth_jwt_key` should be specified in binhex format. It is recommended to use at least 256 bits of data (32 pairs of hex characters or 64 characters in total) as in the example above. Note that using more than 512 bits will not increase the security. For key guidelines please see [NIST Special Publication 800-107 Recommendation for Applications Using Approved Hash Algorithms](https://csrc.nist.gov/publications/detail/sp/800-107/rev-1/final), Section 5.3.2 The HMAC Key.

The configuration also supports RSA public key validation via (e.g.) `auth_jwt_algorithm RS256`. When using the `RS*` alhorithms, the `auth_jwt_key` field must be set to your public key **OR** `auth_jwt_use_keyfile` should be set to `on` and `auth_jwt_keyfile_path` should point to the public key on disk. NGINX won't start if `auth_jwt_use_keyfile` is set to `on` and a key file is not provided.

When using an `RS*` algorithm with an inline key, be sure to set `auth_jwt_key` to the _public key_, rather than a PEM certificate. E.g.:

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

When using an `RS*` algorithm with a public key file, do as follows:

```
auth_jwt_use_keyfile on;
auth_jwt_keyfile_path "/path/to/pub_key.pem";
```

A typical use would be to specify the key and login URL at the `http` level, and then only turn JWT authentication on for the locations which you want to secure. Unauthorized requests result in a 302 "Moved Temporarily" response with the `Location` header set to the URL specified in the `auth_jwt_loginurl` directive, and a querystring parameter `return_url` whose value is the current / attempted URL.

If you prefer to return `401 Unauthorized` rather than redirect, you may turn `auth_jwt_redirect` off:

```
auth_jwt_redirect off;
```

By default the authorization header is used to provide a JWT for validation. However, you may use the `auth_jwt_validation_type` configuration to specify the name of a cookie that provides the JWT:

```
auth_jwt_validation_type COOKIE=jwt;
```

By default, the module will attempt to extract the `sub` claim (e.g. the user's id) from the JWT. If successful, the 
value will be set in the `x-userid` HTTP header. An error will be logged if this option is enabled and the JWT does not 
contain the `sub` claim. You may disable this option as follows:

```
auth_jwt_extract_sub off
```

By default, the module will attempt to validate the email address field of the JWT, then set the x-email header of the
session, and will log an error if it isn't found. To disable this behavior, for instance if you are using a different
user identifier property such as `sub`, set `auth_jwt_validate_email` to the value `off`. _Note that this flag may be 
renamed to `auth_jwt_extract_email` in a future release._ You may disable this option as follows:

```
auth_jwt_validate_email off;
```

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
                "~/Projects/third-party/nginx/objs/**",
                "~/Projects/third-party/nginx/src/**",
                "~/Projects/third-party/libjwt/include/**",
                "~/Projects/third-party/jansson/src/**"
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

### Cloning libjwt

1. Clone this repository as follows (replace `<target_dir>`): `git clone git@github.com:benmcollins/libjwt.git <target_dir>
2. Enter the directory and switch to the latest tag: `git checkout $(git tag | sort -Vr | head -n 1)`
3. Update the `includePath` entires shown above to match the location you chose.

### Cloning lobjansson

1. Clone this repository as follows (replace `<target_dir>`): `git clone git@github.com:akheron/jansson.git <target_dir>
2. Enter the directory and switch to the latest tag: `git checkout $(git tag | sort -Vr | head -n 1)`
3. Update the `includePath` entires shown above to match the location you chose.

### Verify Compliation

Once you save your changes to `.vscode/c_cpp_properties.json`, you should see that warnings and errors in the Problems panel go away, at least temprorarily. Hopfeully they don't come back, but if they do, make sure your include paths are set correctly.
