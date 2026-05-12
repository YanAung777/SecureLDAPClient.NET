// ====================== EXAMPLE USAGE ======================

class Program
{
    static async Task Main(string[] args)
    {
        LdapConnection? connection = null;

        try
        {
            Console.WriteLine("🔄 Connecting to LDAP Server...");

            connection = await LdapHelper.CreateSecureLdapConnectionAsync(
                server: "ldap.example.com",                          // ← Change this
                bindDn: "cn=service-account,dc=example,dc=com",     // Service account
                password: "YourSecurePassword123!",                  // ← Change this
                trustedCertificatesDirectory: "/app/certs",          // For Linux/Docker
                maxRetries: 3);

            Console.WriteLine("✅ Successfully connected to LDAP!");

            // === 1. Get User by Email ===
            var userByEmail = await LdapHelper.GetUserByEmailAsync(
                connection,
                searchBase: "dc=example,dc=com",
                email: "john.doe@example.com",
                attributesToLoad: new[] { "cn", "displayName", "mail", "sAMAccountName", "memberOf" });

            if (userByEmail != null)
            {
                Console.WriteLine($"\n✅ User found by email:");
                Console.WriteLine($"   DN: {userByEmail.DistinguishedName}");
                Console.WriteLine($"   Name: {LdapHelper.GetAttributeValue(userByEmail, "cn")}");
                Console.WriteLine($"   Email: {LdapHelper.GetAttributeValue(userByEmail, "mail")}");

                var groups = LdapHelper.GetAllAttributeValues(userByEmail, "memberOf");
                Console.WriteLine($"   Groups: {groups.Count}");
            }

            // === 2. Get User by sAMAccountName ===
            var userBySam = await LdapHelper.GetUserBySamAccountNameAsync(
                connection, "dc=example,dc=com", "jdoe");

            if (userBySam != null)
                Console.WriteLine($"\n✅ Found by sAMAccountName: {LdapHelper.GetAttributeValue(userBySam, "cn")}");
            
            // 3. Get User by UPN
            var upnUser = await LdapHelper.GetUserByUpnAsync(connection, "dc=example,dc=com", "jane.doe@example.com");

            // === 3. User Authentication ===
            Console.WriteLine("\n🔐 Testing user authentication...");
            bool isAuthenticated = await LdapHelper.AuthenticateUserAsync(
                server: "ldap.example.com",
                userDnOrUpn: "jane.doe@example.com",
                password: "UserPassword123!",
                trustedCertificatesDirectory: "/app/certs");

            Console.WriteLine($"   Authentication result: {(isAuthenticated ? "✅ Success" : "❌ Failed")}");

            // === 4. Paged Search Example ===
            Console.WriteLine("\n📊 Performing paged search for all users...");
            int count = 0;
            await foreach (var entry in LdapHelper.SearchPagedAsAsyncEnumerable(
                connection,
                searchBase: "dc=example,dc=com",
                filter: "(objectClass=user)",
                attributesToLoad: new[] { "cn", "mail" },
                pageSize: 500))
            {
                count++;
                if (count <= 3)
                {
                    Console.WriteLine($"   {count}. {LdapHelper.GetAttributeValue(entry, "cn")} - {LdapHelper.GetAttributeValue(entry, "mail")}");
                }
            }
            Console.WriteLine($"✅ Total users found: {count}");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"❌ Error: {ex.Message}");
        }
        finally
        {
            connection?.Dispose();
            Console.WriteLine("\n🔚 Connection disposed.");
        }
    }
}
