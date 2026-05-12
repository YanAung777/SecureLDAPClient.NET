
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

```JavaScript
const LdapHelper = require('./LdapHelper');

async function main() {
    let client = null;

    try {
        client = await LdapHelper.createSecureLdapConnection({
            server: 'ldap.example.com',
            bindDn: 'cn=service-account,dc=example,dc=com',
            password: 'YourSecurePassword!',
        });

        console.log('✅ Connected to LDAP');

        // Get user by email
        const user = await LdapHelper.getUserByEmail(
            client,
            'dc=example,dc=com',
            'john.doe@example.com',
            ['cn', 'mail', 'displayName', 'memberOf']
        );

        if (user) {
            console.log('User found:', LdapHelper.getAttributeValue(user, 'cn'));
            const groups = LdapHelper.getAllAttributeValues(user, 'memberOf');
            console.log('Groups:', groups.length);
        }

        // Direct authentication
        const isValid = await LdapHelper.authenticateUser({
            server: 'ldap.example.com',
            userDnOrUpn: 'jane.doe@example.com',
            password: 'UserPass123!'
        });

        console.log('Authentication:', isValid);

    } catch (err) {
        console.error('Error:', err.message);
    } finally {
        if (client) await client.unbind().catch(() => {});
    }
}

main();
```

