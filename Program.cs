using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Extensions.Msal;
using Mjcheetham.PromptToolkit;
using MsalPrompt = Microsoft.Identity.Client.Prompt;
using Prompt = Mjcheetham.PromptToolkit.Prompt;

#if NETFRAMEWORK
using Microsoft.Identity.Client.Desktop;
using Microsoft.Identity.Client.MsaPassthrough;
#endif

namespace msal
{
    public static class Program
    {
        private const string MicrosoftCorpTenant = "72f988bf-86f1-41af-91ab-2d7cd011db47";
        private const string AzureDevOps = "499b84ac-1321-427f-aa17-267ca6975798/.default";
        private const string GraphUserRead = "user.read";
        private const string TestApp = "1d18b3b0-251b-4714-a02a-9956cec86c2d";
        private const string VisualStudio = "872cd9fa-d31f-45e0-9eab-6e460a02d1f1";
        private const string VisualStudioNew = "04f0c124-f2bc-4f59-8241-bf6df9866bbd";
        private const string Gcm = "d735b71b-9eee-4a4f-ad23-421660877ba6";
        private const string PreProd = "https://login.windows-ppe.net";
        private const string Prod = "https://login.microsoftonline.com";
        private const string Localhost = "http://localhost";

        public static async Task Main(string[] args)
        {
            var console = new SystemConsole();
            var prompt = new Prompt(console);

            ActionType actionType = prompt.AskOption<ActionType>("Select an action:");

            Uri? authority = null;
            string? redirectUri = null;
            string? clientId = null;
            if (actionType != ActionType.ListAccounts)
            {
                authority = GetAuthority(console, prompt, PreProd, Prod);
                redirectUri = GetRedirectUri(console, prompt, Localhost);
                clientId = GetClientId(console, prompt, TestApp, Gcm, VisualStudio, VisualStudioNew);
            }

#if NETFRAMEWORK
            bool useWam = prompt.AskBoolean("Use the WAM OS broker?", true);
#else
            bool useWam = false;
#endif

            IPublicClientApplication app = BuildPca(authority, clientId, redirectUri, useWam);

            await ConfigureCacheAsync(prompt, app);

            switch (actionType)
            {
                case ActionType.AcquireTokenInteractive:
                {
                    FlowType flowType = prompt.AskOption<FlowType>("Select a flow:");
                    MsalPrompt? promptType = null;
                    if (flowType != FlowType.DeviceCode)
                    {
                        promptType = GetPrompt(prompt);
                    }

                    string[] scopes = GetScopes(prompt, AzureDevOps, GraphUserRead);

                    try
                    {
                        console.WriteLineAlert("Performing interactive authentication...");

                        AuthenticationResult result = await AcquireTokenInteractiveAsync(
                            console,
                            app, scopes,
                            promptType, flowType);

                        WriteSuccess(console, prompt, result);
                    }
                    catch (Exception ex)
                    {
                        WriteFailure(console, ex);
                    }

                    break;
                }
                case ActionType.AcquireTokenSilent:
                {
                    try
                    {
                        string[] scopes = GetScopes(prompt, AzureDevOps, GraphUserRead);

                        if (!TryGetAccountAsync(app, prompt, out string? accountHint))
                        {
                            console.WriteLineFailure("No existing accounts!");
                            return;
                        }

                        console.WriteLineAlert("Performing silent authentication...");

                        AuthenticationResult result = await AcquireTokenSilentAsync(app, scopes, accountHint);

                        WriteSuccess(console, prompt, result);
                    }
                    catch (Exception ex)
                    {
                        WriteFailure(console, ex);
                    }

                    break;
                }
                case ActionType.ListAccounts:
                {
                    IAccount[] accounts = (await app.GetAccountsAsync()).ToArray();
                    switch (accounts)
                    {
                        case {Length: 0}:
                            console.WriteLineAlert("Found no accounts.");
                            break;
                        case {Length: 1}:
                            console.WriteLineSuccess("Found 1 account.");
                            break;
                        case {Length: > 1}:
                            console.WriteLineSuccess("Found {0} accounts.", accounts.Length);
                            break;
                    }

                    foreach (IAccount account in accounts)
                    {
                        console.WriteLineInfo("{0} ({1})",
                            account.Username, account.HomeAccountId);
                    }

                    break;
                }
            }
        }

        private static Uri GetAuthority(IConsole console, Prompt prompt, string ppe, string prod)
        {
            AuthorityType authorityType = prompt.AskOption<AuthorityType>("Select an authority:");
            Uri authorityBase = authorityType switch
            {
                AuthorityType.AzurePreproduction => new Uri(ppe),
                AuthorityType.AzureProduction => new Uri(prod),
                _ => new Uri(prod)
            };

            TenantType tenantType = prompt.AskOption<TenantType>("Select a tenant:");
            Uri authority = tenantType switch
            {
                TenantType.Common => new Uri(authorityBase, "common"),
                TenantType.Consumers => new Uri(authorityBase, "consumers"),
                TenantType.Organizations => new Uri(authorityBase, "organizations"),
                TenantType.MicrosoftCorp => new Uri(authorityBase, MicrosoftCorpTenant),
                _ => new Uri(authorityBase, prompt.AskString("Enter the tenant ID:")),
            };
            console.WriteLineInfo("Authority is {0}", authority);
            return authority;
        }

        private static string GetRedirectUri(IConsole console, Prompt prompt, string localhost)
        {
            RedirectType redirectType = prompt.AskOption<RedirectType>("Select a redirect URL:");
            string redirectUri = redirectType switch
            {
                RedirectType.Localhost => localhost,
                _ => prompt.AskString("Enter custom redirect URL:")
            };
            if (redirectType != RedirectType.Custom)
            {
                console.WriteLineInfo("Redirect URL is {0}", redirectUri);
            }

            return redirectUri;
        }

        private static string GetClientId(IConsole console, Prompt prompt, string testApp, string gcm,
            string visualStudio, string visualStudioNew)
        {
            ClientType clientType = prompt.AskOption<ClientType>("Select a client ID:");
            string clientId = clientType switch
            {
                ClientType.TestApp => testApp,
                ClientType.GitCredentialManager => gcm,
                ClientType.VisualStudio => visualStudio,
                ClientType.VisualStudioNew => visualStudioNew,
                _ => prompt.AskString("Enter custom client ID:")
            };
            if (clientType != ClientType.Custom)
            {
                console.WriteLineInfo("Client ID is {0}", clientId);
            }

            return clientId;
        }

        private static bool TryGetAccountAsync(IPublicClientApplication app, Prompt prompt, out string? account)
        {
            account = null;

            string[] accounts = app.GetAccountsAsync().Result.Select(x => x.Username).ToArray();
            if (accounts.Length == 0)
            {
                return false;
            }

            account = prompt.AskOption("Select an account:", accounts);
            return true;
        }

        private static MsalPrompt? GetPrompt(Prompt prompt)
        {
            PromptType promptType = prompt.AskOption<PromptType>("Select a prompt type:");
            return promptType switch
            {
                PromptType.SelectAccount => MsalPrompt.SelectAccount,
                PromptType.Consent => MsalPrompt.Consent,
#if NETFRAMEWORK
                PromptType.Never => MsalPrompt.Never,
#endif
                PromptType.ForceLogin => MsalPrompt.ForceLogin,
                PromptType.NoPrompt => MsalPrompt.NoPrompt,
                _ => null
            };
        }

        private static async Task ConfigureCacheAsync(Prompt prompt, IPublicClientApplication app)
        {
            string cacheFilePath;
            string? osxKcService = null;
            string? osxKcAccount = null;
            var cacheType = prompt.AskOption<CacheType>("Select token cache to use:");
            switch (cacheType)
            {
                case CacheType.InMemory:
                    return;
                case CacheType.MicrosoftDeveloperShared:
                    string localAppDataPath = PlatformUtils.IsWindows()
                        ? Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)
                        : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".local");
                    cacheFilePath = Path.Combine(
                        localAppDataPath,
                        ".IdentityService", "msal.cache");
                    if (PlatformUtils.IsMacOS())
                    {
                        osxKcService = "Microsoft.Developer.IdentityService";
                        osxKcAccount = "MSALCache";
                    }

                    break;
                default:
                    cacheFilePath = prompt.AskString("Enter token cache file path:");
                    if (PlatformUtils.IsMacOS())
                    {
                        osxKcService = prompt.AskString("Enter Keychain service name:");
                        osxKcAccount = prompt.AskString("Enter Keychain account name:");
                    }

                    break;
            }

            string cacheDirectory = Path.GetDirectoryName(cacheFilePath)!;
            string cacheFileName = Path.GetFileName(cacheFilePath);
            var storagePropsBuilder = new StorageCreationPropertiesBuilder(
                cacheFileName, cacheDirectory);

            if (PlatformUtils.IsMacOS())
            {
                storagePropsBuilder.WithMacKeyChain(osxKcService, osxKcAccount);
            }

            var helper = await MsalCacheHelper.CreateAsync(storagePropsBuilder.Build());
            helper.RegisterCache(app.UserTokenCache);
        }

        private enum CacheType
        {
            InMemory,
            MicrosoftDeveloperShared,
            CustomFile,
        }

        private static string[] GetScopes(Prompt prompt, string azureDevOps, string graphUserRead)
        {
            ScopeSet scopeSet = prompt.AskOption<ScopeSet>("Select scopes:");
            string[] scopes = scopeSet switch
            {
                ScopeSet.AzureDevOps => new[] {azureDevOps},
                ScopeSet.MicrosoftGraph => new[] {graphUserRead},
                _ => prompt.AskString("Enter custom scopes:").Split(' ')
            };
            return scopes;
        }

        private static void WriteSuccess(IConsole console, Prompt prompt, AuthenticationResult result)
        {
            console.WriteLineSuccess("Authentication successful!");
            console.WriteLineInfo("User name: {0}", result.Account.Username);
            console.WriteLineInfo("Home tenant ID: {0}", result.Account.HomeAccountId.TenantId);

            bool printFull = prompt.AskBoolean("Print full token value?", false);
            if (printFull)
            {
                console.WriteLineInfo(result.AccessToken);
            }
            else
            {
                console.WriteLineInfo(result.AccessToken.Substring(0, 40) + "...");
            }
        }

        private static void WriteFailure(IConsole console, Exception exception)
        {
            console.WriteLineFailure("Exception: {0}", exception.Message);
        }

        private static async Task<AuthenticationResult> AcquireTokenInteractiveAsync(IConsole console,
            IPublicClientApplication pca, string[] scopes, MsalPrompt? prompt, FlowType flowType)
        {
            if (flowType == FlowType.DeviceCode)
            {
                return await pca.AcquireTokenWithDeviceCode(scopes, delegate(DeviceCodeResult dcr)
                {
                    console.WriteLineInfo(dcr.Message);
                    return Task.CompletedTask;
                }).ExecuteAsync();
            }

            AcquireTokenInteractiveParameterBuilder ati = pca.AcquireTokenInteractive(scopes);

            if (prompt.HasValue)
            {
                ati.WithPrompt(prompt.Value);
            }

            switch (flowType)
            {
                case FlowType.SystemWebView:
                    ati.WithUseEmbeddedWebView(false);
                    break;
#if NETFRAMEWORK
                case FlowType.EmbeddedWebView:
                    ati.WithUseEmbeddedWebView(true);
                    break;
#endif
            }

            AuthenticationResult result = await ati.ExecuteAsync();
            return result;
        }

        private static async Task<AuthenticationResult> AcquireTokenSilentAsync(
            IPublicClientApplication pca, string[] scopes, string? loginHint)
        {
            return await pca.AcquireTokenSilent(scopes, loginHint).ExecuteAsync();
        }

        private static IPublicClientApplication BuildPca(Uri? authority, string? clientId, string? redirectUri,
            bool useWam)
        {
            // Use dummy client ID if we're only listing accounts in the cache
            clientId ??= Guid.NewGuid().ToString("D");

            var builder = PublicClientApplicationBuilder.Create(clientId);

            if (authority != null)
                builder = builder.WithAuthority(authority);

            if (redirectUri != null)
                builder = builder.WithRedirectUri(redirectUri);

            if (useWam)
            {
#if NETFRAMEWORK
                builder.WithExperimentalFeatures();
                builder.WithWindowsBroker();
                builder.WithMsaPassthrough();
#endif
            }

            IPublicClientApplication pca = builder.Build();
            return pca;
        }

        private enum ActionType
        {
            AcquireTokenInteractive,
            AcquireTokenSilent,
            ListAccounts,
        }

        private enum FlowType
        {
            SystemWebView,
#if NETFRAMEWORK
            EmbeddedWebView,
#endif
            DeviceCode,
        }

        private enum AuthorityType
        {
            AzureProduction,
            AzurePreproduction,
        }

        private enum TenantType
        {
            Common,
            Consumers,
            Organizations,
            MicrosoftCorp,
            Custom,
        }

        private enum ClientType
        {
            TestApp,
            GitCredentialManager,
            VisualStudio,
            VisualStudioNew,
            Custom,
        }

        private enum RedirectType
        {
            Localhost,
            Custom,
        }

        private enum PromptType
        {
            Default,
            SelectAccount,
            Consent,
#if NETFRAMEWORK
                Never,
#endif
            ForceLogin,
            NoPrompt,
        }

        private enum ScopeSet
        {
            MicrosoftGraph,
            AzureDevOps,
            Custom,
        }
    }

    internal static class PlatformUtils
    {
        public static bool IsWindows()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
        }

        public static bool IsPosix()
        {
            return IsMacOS() || IsLinux();
        }

        public static bool IsMacOS()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.OSX);
        }

        public static bool IsLinux()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Linux);
        }
    }

    internal enum OperatingSystemType
    {
        Unknown,
        Windows,
        OSX,
        Linux,
    }
}
