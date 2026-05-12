const LdapHelper = require('../shared/LdapHelper');

module.exports = async function (context, req) {
    context.log('LDAP Proxy function processed a request.');

    try {
        const body = req.body || {};
        const { 
            action, 
            server, 
            username, 
            password, 
            searchBase, 
            filter, 
            attributes 
        } = body;

        if (!action || !server || !username || !password) {
            context.res = {
                status: 400,
                body: { error: "Missing required fields: action, server, username, password" }
            };
            return;
        }

        let client = null;

        switch (action.toLowerCase()) {
            
            case 'authenticate':
                const authResult = await LdapHelper.authenticateUser(server, username, password);
                context.res = {
                    status: authResult.success ? 200 : 401,
                    body: authResult
                };
                break;

            case 'search':
            case 'getuser':
                client = await LdapHelper.createSecureConnection({ server, bindDn: username, password });

                const user = await LdapHelper.searchUser(
                    client,
                    searchBase || process.env.LDAP_SEARCH_BASE,
                    filter || `(mail=${username})`,
                    attributes || ['cn', 'mail', 'displayName', 'sAMAccountName', 'memberOf']
                );

                context.res = {
                    status: 200,
                    body: {
                        success: true,
                        user: user,
                        groups: user ? LdapHelper.getAllAttributeValues(user, 'memberOf') : []
                    }
                };
                break;

            case 'getuserbyemail':
                client = await LdapHelper.createSecureConnection({ server, bindDn: username, password });
                const userByEmail = await LdapHelper.searchUser(
                    client, 
                    searchBase || process.env.LDAP_SEARCH_BASE, 
                    `(mail=${body.email})`, 
                    attributes
                );
                context.res = { status: 200, body: { success: true, user: userByEmail } };
                break;

            default:
                context.res = {
                    status: 400,
                    body: { error: "Invalid action. Use: authenticate, search, getuser, getuserbyemail" }
                };
        }

    } catch (error) {
        context.log.error('LDAP Proxy Error:', error);
        context.res = {
            status: 500,
            body: {
                success: false,
                error: error.message || 'Internal server error'
            }
        };
    } finally {
        // Cleanup
        if (client) {
            await client.unbind().catch(() => {});
        }
    }
};