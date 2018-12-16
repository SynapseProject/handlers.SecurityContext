using System;

using Synapse.Core;

using Zephyr.SecurityContext;
using Zephyr.SecurityContext.Windows;


#if(NET452 || NET46 || NET461 || NET462 || NET47 || NET471 || NET472)
public class Win32ImpersonationProvider : SecurityContextRuntimeBase
{
    Win32Impersonate _identity = null;

    public override ExecuteResult Logon(SecurityContextStartInfo startInfo)
    {
        try
        {
            Win32LogonInfo logonInfo = DeserializeOrNew<Win32LogonInfo>( startInfo.Parameters );
            logonInfo.MakeSecure();

            _identity = new Win32Impersonate();
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
#endif