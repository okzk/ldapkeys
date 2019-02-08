# ldapkeys

Helper command for `AuthorizedKeysCommand` in sshd.

## Install

Download from [releases](https://github.com/okzk/ldapkeys/releases).

## Configurations

Create `/etc/ldapkeys/config.toml` as below.

```toml
URL = "ldap://ldap.server.local"
BaseDN = "dc=example,dc=com"

# (Optional)
Filter = "(description=foo)"

# (Optional) 
BindDN = "uid=foo,ou=People,dc=example,dc=com"
BindPassword = "secret_password"
```

And update your `/etc/ssh/sshd_config`.

```
PubkeyAuthentication yes 
AuthorizedKeysCommand  /path/to/ldapkeys
AuthorizedKeysCommandUser nobody
```
