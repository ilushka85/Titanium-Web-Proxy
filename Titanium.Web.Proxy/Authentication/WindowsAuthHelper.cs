using System;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace Titanium.Web.Proxy.Authentication.Security
{
    /// <summary>
    /// Adapated from
    /// http://www.pinvoke.net/default.aspx/secur32.initializesecuritycontext
    /// </summary>
    public class WindowsAuthHelper
    {
        public const int SEC_E_OK = 0;
        public const int SEC_I_CONTINUE_NEEDED = 0x90312;
        const int SECPKG_CRED_OUTBOUND = 2;
        const int SECURITY_NATIVE_DREP = 0x10;
        const int MAX_TOKEN_SIZE = 12288;

        SECURITY_HANDLE _hOutboundCred = new SECURITY_HANDLE(0);
        public SECURITY_HANDLE _hClientContext = new SECURITY_HANDLE(0);

        public const int ISC_REQ_REPLAY_DETECT = 0x00000004;
        public const int ISC_REQ_SEQUENCE_DETECT = 0x00000008;
        public const int ISC_REQ_CONFIDENTIALITY = 0x00000010;
        public const int ISC_REQ_CONNECTION = 0x00000800;

        public const int STANDARD_CONTEXT_ATTRIBUTES = ISC_REQ_CONFIDENTIALITY | ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_CONNECTION;

        /// <summary>
        /// computes the client response for server Authentication challenge tokens
        /// </summary>
        /// <param name="serverToken"></param>
        /// <param name="bContinueProcessing">Indicates if susequent calls to server is expected to finish authentication</param>
        /// <returns>client response token to server as bytes</returns>
        public byte[] ComputeClientResponse(byte[] serverToken, out bool bContinueProcessing)
        {
            byte[] clientToken;

            string _sAccountName = WindowsIdentity.GetCurrent().Name;
            SECURITY_INTEGER ClientLifeTime = new SECURITY_INTEGER(0);

            if (AcquireCredentialsHandle(_sAccountName, "NTLM", SECPKG_CRED_OUTBOUND,
                                            IntPtr.Zero, IntPtr.Zero, 0, IntPtr.Zero,
                                            ref _hOutboundCred, ref ClientLifeTime) != SEC_E_OK)
            {
                throw new Exception("Couldn't acquire client credentials");
            }


            int ss = -1;

            SecBufferDesc ClientToken = new SecBufferDesc(MAX_TOKEN_SIZE);

            try
            {
                uint ContextAttributes = 0;

                if (serverToken == null)
                {
                    ss = InitializeSecurityContext(
                        ref _hOutboundCred,
                        IntPtr.Zero,
                        _sAccountName,                  // null string pszTargetName,
                        STANDARD_CONTEXT_ATTRIBUTES,
                        0,                              //int Reserved1,
                        SECURITY_NATIVE_DREP,           //int TargetDataRep
                        IntPtr.Zero,                    //Always zero first time around...
                        0,                              //int Reserved2,
                        out _hClientContext,            //pHandle CtxtHandle = SecHandle
                        out ClientToken,                //ref SecBufferDesc pOutput, //PSecBufferDesc
                        out ContextAttributes,          //ref int pfContextAttr,
                        out ClientLifeTime);            //ref IntPtr ptsExpiry ); //PTimeStamp

                }
                else
                {
                    SecBufferDesc ServerToken = new SecBufferDesc(serverToken);

                    try
                    {
                        ss = InitializeSecurityContext(
                            ref _hOutboundCred,
                            ref _hClientContext,
                            _sAccountName,                                  // null string pszTargetName,
                            STANDARD_CONTEXT_ATTRIBUTES,
                            0,                                              //int Reserved1,
                            SECURITY_NATIVE_DREP,                           //int TargetDataRep
                            ref ServerToken,                                //Always zero first time around...
                            0,                                              //int Reserved2,
                            out _hClientContext,                            //pHandle CtxtHandle = SecHandle
                            out ClientToken,                                //ref SecBufferDesc pOutput, //PSecBufferDesc
                            out ContextAttributes,                          //ref int pfContextAttr,
                            out ClientLifeTime);                            //ref IntPtr ptsExpiry ); //PTimeStamp
                    }
                    finally
                    {
                        ServerToken.Dispose();
                    }
                }

                if (ss != SEC_E_OK && ss != SEC_I_CONTINUE_NEEDED)
                {
                    throw new Exception("InitializeSecurityContext() failed!!!");
                }

                clientToken = ClientToken.GetSecBufferByteArray();
            }
            finally
            {
                ClientToken.Dispose();
            }

            bContinueProcessing = ss != SEC_E_OK;

            return clientToken;
        }

        public string ComputeClientNTLMChallengeRespose(string challengeFromServer)
        {
            return null;
        }

        #region Native calls to secur32.dll

        [DllImport("secur32", CharSet = CharSet.Auto)]
        static extern int AcquireCredentialsHandle(
                            string pszPrincipal,                //SEC_CHAR*
                            string pszPackage,                  //SEC_CHAR* //"Kerberos","NTLM","Negotiative"
                            int fCredentialUse,
                            IntPtr PAuthenticationID,           //_LUID AuthenticationID,//pvLogonID, //PLUID
                            IntPtr pAuthData,                   //PVOID
                            int pGetKeyFn,                      //SEC_GET_KEY_FN
                            IntPtr pvGetKeyArgument,            //PVOID
                            ref SECURITY_HANDLE phCredential,   //SecHandle //PCtxtHandle ref
                            ref SECURITY_INTEGER ptsExpiry);    //PTimeStamp //TimeStamp ref

        [DllImport("secur32", CharSet = CharSet.Auto, SetLastError = true)]
        static extern int InitializeSecurityContext(ref SECURITY_HANDLE phCredential,//PCredHandle
                            IntPtr phContext,                   //PCtxtHandle
                            string pszTargetName,
                            int fContextReq,
                            int Reserved1,
                            int TargetDataRep,
                            IntPtr pInput,                      //PSecBufferDesc SecBufferDesc
                            int Reserved2,
                            out SECURITY_HANDLE phNewContext,   //PCtxtHandle
                            out SecBufferDesc pOutput,          //PSecBufferDesc SecBufferDesc
                            out uint pfContextAttr,             //managed ulong == 64 bits!!!
                            out SECURITY_INTEGER ptsExpiry);    //PTimeStamp

        [DllImport("secur32", CharSet = CharSet.Auto, SetLastError = true)]
        static extern int InitializeSecurityContext(ref SECURITY_HANDLE phCredential,   //PCredHandle
                            ref SECURITY_HANDLE phContext,                              //PCtxtHandle
                            string pszTargetName,
                            int fContextReq,
                            int Reserved1,
                            int TargetDataRep,
                            ref SecBufferDesc SecBufferDesc,                            //PSecBufferDesc SecBufferDesc
                            int Reserved2,
                            out SECURITY_HANDLE phNewContext,                           //PCtxtHandle
                            out SecBufferDesc pOutput,                                  //PSecBufferDesc SecBufferDesc
                            out uint pfContextAttr,                                     //managed ulong == 64 bits!!!
                            out SECURITY_INTEGER ptsExpiry);                            //PTimeStamp

        #endregion
    }
}
