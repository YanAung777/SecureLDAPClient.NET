# LdapHelper - Secure LDAPS Client for .NET

A robust, production-ready LDAP helper class for **.NET** that simplifies secure LDAPS connections, user lookups, and authentication with built-in retry logic, Linux support, and comprehensive helper methods.
### Notes
LdapSessionOptions.VerifyServerCertificate is not supported in Linux 
LdapConnection fails to bind on Linux when running .NET 6.0.0-rc.2.21480.5 version of System.DirectoryServices.Protocols package and throws
see : https://github.com/dotnet/runtime/issues/60972

When a custom CA (Root CA) needs to be verified on Linux, the expected callback-based validation path throws an exception. That made the C# option unsuitable for this service because CA validation is a hard requirement and could not be safely bypassed. You must use node.js deployment.
https://www.npmjs.com/package/ldap-async

## ✨ Features

- **Secure LDAPS** connections with proper certificate handling
- Full support for **Linux / Docker** containers (using `TrustedCertificatesDirectory`)
- Automatic retry logic with exponential backoff
- Simple and paged search capabilities (`IAsyncEnumerable` support)
- Convenient user lookup helpers (`GetUserByEmail`, `GetUserBySamAccountName`, etc.)
- Direct user authentication wrapper
- Rich attribute extraction helpers
- Comprehensive error handling
- Cross-platform (Windows + Linux + macOS)

## 📋 Requirements

- **.NET 8.0** or higher (recommended .NET 8+)
- For Linux/macOS: .NET 10+ recommended for best `TrustedCertificatesDirectory` support
- LDAP server with LDAPS (port 636)

## 🚀 Installation

1. Copy `LdapHelper.cs` into your project.
2. Make sure you have the required NuGet package:

```bash
dotnet add package System.DirectoryServices.Protocols
```

## 🔧 Usage
1. Basic Connection

```C#
using System.Threading.Tasks;
var connection = await LdapHelper.CreateSecureLdapConnectionAsync(
    server: "ldap.example.com",
    bindDn: "cn=service-account,dc=example,dc=com",
    password: "YourSecurePassword",
    trustedCertificatesDirectory: "/app/certs",   // Required on Linux
    maxRetries: 3);
```
## 2. User Lookup Example
```C#
   using System.Threading.Tasks;

var connection = await LdapHelper.CreateSecureLdapConnectionAsync(
    server: "ldap.example.com",
    bindDn: "cn=service-account,dc=example,dc=com",
    password: "YourSecurePassword",
    trustedCertificatesDirectory: "/app/certs",   // Required on Linux
    maxRetries: 3);
```
## 3. Extracting Attributes
```C#
string? name = LdapHelper.GetAttributeValue(user, "cn");
List<string> groups = LdapHelper.GetAllAttributeValues(user, "memberOf");

Console.WriteLine($"User: {name}");
Console.WriteLine($"Groups: {string.Join(", ", groups)}");
```
## 4. User Authentication


```C#
bool isValid = await LdapHelper.AuthenticateUserAsync(
    server: "ldap.example.com",
    userDnOrUpn: "jane.doe@example.com",
    password: "UserPassword123!",
    trustedCertificatesDirectory: "/app/certs");
Console.WriteLine($"Authentication: {isValid}");
```
## 5. Paged Search (for large result sets)
```C#
await foreach (var entry in LdapHelper.SearchPagedAsAsyncEnumerable(
    connection,
    searchBase: "dc=example,dc=com",
    filter: "(objectClass=user)",
    attributesToLoad: new[] { "cn", "mail" },
    pageSize: 500))
{
Console.WriteLine(LdapHelper.GetAttributeValue(entry, "cn"));
}
```
## 🐧 Linux / Docker Configuration
On Linux containers, place your CA certificate(s) in PEM format inside the directory:
```Bash
/app/certs/
├── ca-cert.pem
└── another-ca.pem
```
Then pass the path:
```C#
trustedCertificatesDirectory: "/app/certs"
```

## 🛡️ Security Recommendations
- Always use LDAPS (port 636)
- Rotate service account passwords regularly
- Use least-privilege service accounts
- Store secrets in Azure Key Vault, Docker Secrets, etc.
- Enable certificate validation (avoid disabling)
- Use short-lived connections where possible
## 📖 API Reference

| Method                                      | Description                                              |
|---------------------------------------------|----------------------------------------------------------|
| `CreateSecureLdapConnectionAsync()`        | Create and bind LDAPS connection with retries            |
| `SearchUserAsync()`                         | General search                                           |
| `GetUserByEmailAsync()`                     | Search by email                                          |
| `GetUserBySamAccountNameAsync()`            | Search by Windows username (sAMAccountName)              |
| `GetUserByUpnAsync()`                       | Search by User Principal Name (UPN)                      |
| `AuthenticateUserAsync()`                   | Validate user credentials by binding                     |
| `GetAttributeValue()`                       | Get single attribute value                               |
| `GetAllAttributeValues()`                   | Get all values of a multi-valued attribute               |
| `SearchPagedAsync()`                        | Paged search returning all results as List               |
| `SearchPagedAsAsyncEnumerable()`            | Streaming paged search (memory efficient)                |
