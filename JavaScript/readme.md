
## Sample Request Body:

```Json
{
  "action": "search",
  "server": "ldap.yourcompany.com",
  "username": "service-account@yourcompany.com",
  "password": "xxxxxxxxxxxxxxxx",
  "searchBase": "dc=example,dc=com",
  "filter": "(mail=john.doe@yourcompany.com)",
  "attributes": ["cn", "mail", "memberOf", "displayName"]
}
```