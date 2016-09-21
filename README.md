# Intro
This is an NGINX module to check for a valid JWT and proxy to an upstream server or redirect to a login page.

# Build Requirements
This module depends on the [JWT C Library](https://github.com/benmcollins/libjwt)

Transitively, that library depends on a JSON Parser called [Jansson](https://github.com/akheron/jansson) as well as OpenSSL

# NGINX Directives
This module requires several new nginx.conf directives, which can be specified in on the `main` `server` or `location` level.

```
auth_jwt_key "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF";
auth_jwt_loginurl "https://yourdomain.com/loginpage";
auth_jwt_enabled on;
```

So, a typical use would be to specify the key and loginurl on the main level and then only turn on the locations that you want to secure (not the login page).

To compile nginx with this module, use an `--add-module` option to `configure`

```
./configure --add-module=path/to/this/module/directory
```