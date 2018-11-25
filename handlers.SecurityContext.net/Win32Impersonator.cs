using System;
using System.Security;

using Synapse.Core;
using zephyr.SecurityContext;
using zephyr.SecurityContext.Windows;


public class Win32Impersonator : SecurityContextRuntimeBase
{
    Win32Identity _identity = null;

    public override ExecuteResult Logon(SecurityContextStartInfo startInfo)
    {
        try
        {
            Win32LogonInfo logonInfo = DeserializeOrNew<Win32LogonInfo>( startInfo.Parameters );
            logonInfo.MakeSecure();

            _identity = new Win32Identity();
            _identity.Impersonate( logonInfo.SecureUserName, logonInfo.SecureDomain, logonInfo.SecurePassword );

            string message = $"SecurityContext: {logonInfo.SecureUserName.ToUnsecureString()}, IsImpersonating: {_identity.IsImpersonating}";
            OnLogMessage( "Logon", message );
            return new ExecuteResult() { Status = StatusType.Success, Message = message };
        }
        catch( Exception ex )
        {
            OnLogMessage( "Logon", ex.Message, ex: ex );
            return new ExecuteResult() { Status = StatusType.Failed, Message = ex.Message };
        }
    }

    public override void Logoff()
    {
        _identity?.Undo();
    }

    public override object GetConfigInstance()
    {
        return null;
    }

    public override object GetParametersInstance()
    {
        return new Win32LogonInfo
        {
            UserName = "username",
            Password = "password",
            Domain = "domain"
        };
    }
}


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