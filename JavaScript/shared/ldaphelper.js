const { Client } = require('ldapts');

class LdapHelper {
    static async createSecureConnection(config) {
        const {
            server,
            bindDn,
            password,
            maxRetries = 3,
            baseDelayMs = 1000
        } = config;

        let lastError;

        for (let attempt = 0; attempt <= maxRetries; attempt++) {
            try {
                const client = new Client({
                    url: `ldaps://${server}:636`,
                    tlsOptions: {
                        rejectUnauthorized: true
                    },
                    connectTimeout: 10000,
                    timeout: 15000
                });

                await client.bind(bindDn, password);
                return client;
            } catch (error) {
                lastError = error;
                console.error(`LDAP bind attempt ${attempt + 1} failed:`, error.message);

                if (attempt < maxRetries) {
                    const delay = baseDelayMs * Math.pow(2, attempt);
                    await new Promise(r => setTimeout(r, delay));
                }
            }
        }

        throw new Error(`LDAP connection failed after ${maxRetries + 1} attempts: ${lastError?.message}`);
    }

    static async searchUser(client, searchBase, filter, attributes = []) {
        const { searchEntries } = await client.search(searchBase, {
            filter,
            scope: 'sub',
            attributes: attributes.length ? attributes : undefined
        });
        return searchEntries.length > 0 ? searchEntries[0] : null;
    }

    static getAttributeValue(entry, attr) {
        if (!entry || !entry[attr]) return null;
        const val = entry[attr];
        return Array.isArray(val) ? val[0] : val;
    }

    static getAllAttributeValues(entry, attr) {
        if (!entry || !entry[attr]) return [];
        const val = entry[attr];
        return Array.isArray(val) ? val : [val];
    }

    static async authenticateUser(server, userDnOrUpn, password) {
        let client = null;
        try {
            client = await LdapHelper.createSecureConnection({ server, bindDn: userDnOrUpn, password, maxRetries: 2 });
            return { success: true };
        } catch (error) {
            return { success: false, error: error.message };
        } finally {
            if (client) await client.unbind().catch(() => {});
        }
    }
}

module.exports = LdapHelper;