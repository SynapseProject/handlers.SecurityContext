using System;
using System.Security;

using Zephyr.SecurityContext;


public class Win32LogonInfo
{
    public string UserName { get; set; }
    public string Password { get; set; }
    public string Domain { get; set; }

    internal SecureString SecureUserName;
    internal SecureString SecurePassword;
    internal SecureString SecureDomain;

    public void MakeSecure()
    {
        SecureUserName = UserName.ToSecureString();
        UserName = null;

        SecurePassword = Password.ToSecureString();
        Password = null;

        SecureDomain = Domain.ToSecureString();
        Domain = null;
    }
}