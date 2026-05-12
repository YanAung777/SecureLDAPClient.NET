const { Client } = require('ldapts');

class LdapHelper {
    /**
     * Create and bind a secure LDAPS connection
     */
    static async createSecureLdapConnection({
        server,
        bindDn,
        password,
        maxRetries = 3,
        baseDelayMs = 1000,
        tlsOptions = {}
    }) {
        let lastError;

        for (let attempt = 0; attempt <= maxRetries; attempt++) {
            try {
                const client = new Client({
                    url: `ldaps://${server}:636`,
                    tlsOptions: {
                        rejectUnauthorized: true,
                        ...tlsOptions
                    }
                });

                await client.bind(bindDn, password);
                console.log(`✅ LDAP bind successful (attempt ${attempt + 1})`);
                return client;
            } catch (error) {
                lastError = error;
                console.error(`LDAP attempt ${attempt + 1} failed:`, error.message);

                if (attempt < maxRetries) {
                    const delay = baseDelayMs * Math.pow(2, attempt);
                    await new Promise(r => setTimeout(r, delay));
                }
            }
        }

        throw new Error(`Failed to connect to LDAP after ${maxRetries + 1} attempts: ${lastError.message}`);
    }

    /**
     * Simple search - returns first result or null
     */
    static async searchUser(client, searchBase, filter, attributes = []) {
        if (!client || !searchBase || !filter) {
            throw new Error('Missing required parameters: client, searchBase, filter');
        }

        try {
            const { searchEntries } = await client.search(searchBase, {
                filter,
                scope: 'sub',
                attributes: attributes.length ? attributes : undefined
            });

            return searchEntries.length > 0 ? searchEntries[0] : null;
        } catch (error) {
            console.error('LDAP Search Error:', error.message);
            throw error;
        }
    }

    // ==================== Specific Helpers ====================

    static async getUserByEmail(client, searchBase, email, attributes = []) {
        return this.searchUser(client, searchBase, `(mail=${email})`, attributes);
    }

    static async getUserBySamAccountName(client, searchBase, samAccountName, attributes = []) {
        return this.searchUser(client, searchBase, `(sAMAccountName=${samAccountName})`, attributes);
    }

    static async getUserByUpn(client, searchBase, upn, attributes = []) {
        return this.searchUser(client, searchBase, `(userPrincipalName=${upn})`, attributes);
    }

    // ==================== Attribute Helpers ====================

    static getAttributeValue(entry, attributeName) {
        if (!entry || !entry[attributeName]) return null;
        const value = entry[attributeName];
        return Array.isArray(value) ? value[0] : value;
    }

    static getAllAttributeValues(entry, attributeName) {
        if (!entry || !entry[attributeName]) return [];
        const value = entry[attributeName];
        return Array.isArray(value) ? value : [value];
    }

    // ==================== Authentication ====================

    static async authenticateUser({
        server,
        userDnOrUpn,
        password,
        maxRetries = 2
    }) {
        let client = null;
        try {
            client = await this.createSecureLdapConnection({
                server,
                bindDn: userDnOrUpn,
                password,
                maxRetries
            });
            return true;
        } catch (error) {
            return false;
        } finally {
            if (client) {
                await client.unbind().catch(() => {});
            }
        }
    }

    // ==================== Paged Search (Async Iterator) ====================

    static async *searchPaged(client, searchBase, filter, options = {}) {
        const {
            attributes = [],
            pageSize = 500,
            scope = 'sub'
        } = options;

        let cookie = null;

        while (true) {
            const { searchEntries, searchRef, searchControls } = await client.search(searchBase, {
                filter,
                scope,
                attributes: attributes.length ? attributes : undefined,
                paged: { pageSize, cookie }
            });

            for (const entry of searchEntries) {
                yield entry;
            }

            // Get cookie for next page
            const pageControl = searchControls?.find(c => c.type === '1.2.840.113556.1.4.319');
            cookie = pageControl?.value?.cookie;

            if (!cookie) break;
        }
    }
}

module.exports = LdapHelper;