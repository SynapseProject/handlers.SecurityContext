using System;
using System.Security;
using System.Security.Principal;

using Synapse.Core;
using Zephyr.SecurityContext;
using Zephyr.SecurityContext.Windows;


public class Win32IdentityProvider : SecurityContextRuntimeBase
{
    Win32Identity _w32;

    public override ExecuteResult Logon(SecurityContextStartInfo startInfo)
    {
        try
        {
            Win32LogonInfo logonInfo = DeserializeOrNew<Win32LogonInfo>( startInfo.Parameters );
            logonInfo.MakeSecure();

            _w32 = new Win32Identity( logonInfo.SecureUserName, logonInfo.SecureDomain, logonInfo.SecurePassword );

            string message = $"SecurityContext: {logonInfo.SecureUserName.ToUnsecureString()}, HasIdentity: {_w32.HasIdentity}";
            OnLogMessage( "Logon", message );
            return new ExecuteResult() { Status = StatusType.Success, Message = message };
        }
        catch( Exception ex )
        {
            OnLogMessage( "Logon", ex.Message, ex: ex );
            return new ExecuteResult() { Status = StatusType.Failed, Message = ex.Message };
        }
    }

    public override ExecuteResult ExecuteProxy(Func<HandlerStartInfo, ExecuteResult> func, HandlerStartInfo handlerStartInfo)
    {
        ExecuteResult result = null;
        WindowsIdentity.RunImpersonated( _w32.Identity.AccessToken, () =>
        {
            result = func( handlerStartInfo );
            result.SecurityContext = _w32.Identity.Name;
        } );
        return result;
    }

    public override bool UseExecuteProxy { get { return true; } set { } }

    public override void Logoff()
    {
        _w32?.Logoff();
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