using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Desktop;
using Microsoft.Identity.Client.Extensions.Msal;
using Microsoft.IdentityModel.JsonWebTokens;
using Mjcheetham.PromptToolkit;
using MsalPrompt = Microsoft.Identity.Client.Prompt;
using Prompt = Mjcheetham.PromptToolkit.Prompt;

namespace msal
{
    public static class Program
    {
        private const string MicrosoftServicesTenant = "f8cdef31-a31e-4b4a-93e4-5f571e91255a";
        private const string MicrosoftCorpTenant = "72f988bf-86f1-41af-91ab-2d7cd011db47";
        private const string MatthewCheethamTenant = "6ac55484-1f79-4c04-ba1b-74e13182258e";
        private const string AzureDevOpsDefault = "499b84ac-1321-427f-aa17-267ca6975798/.default";
        private const string AzureDevOpsCodeFull = "499b84ac-1321-427f-aa17-267ca6975798/vso.code_full";
        private const string MsGitApiTelemetryReadConfig = "api://33fc41c8-2ac3-4342-8be6-d3ec598622c9/Telemetry.ReadConfig";
        private const string GraphUserRead = "user.read";
        private const string TestApp = "1d18b3b0-251b-4714-a02a-9956cec86c2d";
        private const string VisualStudio = "872cd9fa-d31f-45e0-9eab-6e460a02d1f1";
        private const string VisualStudioNew = "04f0c124-f2bc-4f59-8241-bf6df9866bbd";
        private const string Gcm = "d735b71b-9eee-4a4f-ad23-421660877ba6";
        private const string CodesignClient = "70d4c0bd-fe5f-4266-aa7f-f4d2b540c4be";
        private const string MsGitTools = "7a060ccb-fcb0-4eff-9819-fbaaf060a012";
        private const string PreProd = "https://login.windows-ppe.net";
        private const string Prod = "https://login.microsoftonline.com";
        private const string Localhost = "http://localhost";
        private const string LocalhostIpv4 = "http://127.0.0.1";

        public static async Task Main(string[] args)
        {
            var console = new SystemConsole();
            var prompt = new Prompt(console);

            ActionType actionType = prompt.AskOption<ActionType>("Select an action:");

            bool useBroker = false;
            if (OperatingSystem.IsWindows())
            {
                useBroker = prompt.AskBoolean("Use the OS broker?", true);
            }

            Uri? authority = null;
            string? redirectUri = null;
            string? clientId = null;
            if (actionType != ActionType.ListAccounts)
            {
                authority = GetAuthority(console, prompt);
                clientId = GetClientId(console, prompt);
                redirectUri = useBroker
                    ? null
                    : GetRedirectUri(console, prompt);
            }

            bool useMsaPt = false;
            bool listOsAccounts = false;
            if (useBroker)
            {
                useMsaPt = prompt.AskBoolean("Enable MSA-PT?", false);

                if (actionType != ActionType.AcquireTokenInteractive)
                {
                    listOsAccounts = prompt.AskBoolean("List OS accounts?", true);
                }
            }

            IPublicClientApplication app = BuildPca(authority, clientId, redirectUri, useBroker, useMsaPt, listOsAccounts);

            await ConfigureCacheAsync(prompt, app);

            switch (actionType)
            {
                case ActionType.AcquireTokenInteractive:
                {
                    FlowType flowType = useBroker
                        ? FlowType.SystemWebView
                        : prompt.AskOption<FlowType>("Select a flow:");

                    MsalPrompt? promptType = null;
                    if (flowType != FlowType.DeviceCode)
                    {
                        promptType = GetPrompt(prompt);
                    }

                    string[] scopes = GetScopes(prompt, AzureDevOpsDefault, AzureDevOpsCodeFull, GraphUserRead, MsGitApiTelemetryReadConfig);

                    console.WriteLineInfo("Scopes are {0}", string.Join(", ", scopes));

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
                        string[] scopes = GetScopes(prompt, AzureDevOpsDefault, AzureDevOpsCodeFull, GraphUserRead, MsGitApiTelemetryReadConfig);

                        if (!TryGetAccountAsync(app, prompt, out IAccount? account))
                        {
                            console.WriteLineFailure("No existing accounts!");
                            return;
                        }

                        console.WriteLineAlert("Performing silent authentication...");

                        AuthenticationResult result = await AcquireTokenSilentAsync(app, scopes, account!);

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

        private static Uri GetAuthority(IConsole console, Prompt prompt)
        {
            AuthorityType authorityType = prompt.AskOption<AuthorityType>("Select an authority:");
            Uri authorityBase = authorityType switch
            {
                AuthorityType.AzurePreproduction => new Uri(PreProd),
                AuthorityType.AzureProduction => new Uri(Prod),
                _ => new Uri(Prod)
            };

            TenantType tenantType = prompt.AskOption<TenantType>("Select a tenant:");
            Uri authority = tenantType switch
            {
                TenantType.Common => new Uri(authorityBase, "common"),
                TenantType.Consumers => new Uri(authorityBase, "consumers"),
                TenantType.Organizations => new Uri(authorityBase, "organizations"),
                TenantType.MicrosoftCorp => new Uri(authorityBase, MicrosoftCorpTenant),
                TenantType.MicrosoftServices => new Uri(authorityBase, MicrosoftServicesTenant),
                TenantType.MatthewCheetham => new Uri(authorityBase, MatthewCheethamTenant),
                _ => new Uri(authorityBase, prompt.AskString("Enter the tenant ID:")),
            };
            console.WriteLineInfo("Authority is {0}", authority);
            return authority;
        }

        private static string GetRedirectUri(IConsole console, Prompt prompt)
        {
            RedirectType redirectType = prompt.AskOption<RedirectType>("Select a redirect URL:");
            string redirectUri = redirectType switch
            {
                RedirectType.Localhost => Localhost,
                RedirectType.LocalhostIpv4 => LocalhostIpv4,
                _ => prompt.AskString("Enter custom redirect URL:")
            };
            if (redirectType != RedirectType.Custom)
            {
                console.WriteLineInfo("Redirect URL is {0}", redirectUri);
            }

            return redirectUri;
        }

        private static string GetClientId(IConsole console, Prompt prompt)
        {
            ClientType clientType = prompt.AskOption<ClientType>("Select a client ID:");
            string clientId = clientType switch
            {
                ClientType.TestApp => TestApp,
                ClientType.GitCredentialManager => Gcm,
                ClientType.VisualStudio => VisualStudio,
                ClientType.VisualStudioNew => VisualStudioNew,
                ClientType.CodesignClient => CodesignClient,
                ClientType.MsGitTools => MsGitTools,
                _ => prompt.AskString("Enter custom client ID:")
            };
            if (clientType != ClientType.Custom)
            {
                console.WriteLineInfo("Client ID is {0}", clientId);
            }

            return clientId;
        }

        private static bool TryGetAccountAsync(IPublicClientApplication app, Prompt prompt, out IAccount? account)
        {
            account = null;

            IAccount[] accounts = app.GetAccountsAsync().Result.ToArray();
            if (accounts.Length == 0)
            {
                return false;
            }

            string[] userNames = accounts.Select(x => x.Username).ToArray();
            string userName = prompt.AskOption("Select an account:", userNames);

            account = accounts.FirstOrDefault(x => x.Username == userName);
            return account is not null;
        }

        private static MsalPrompt? GetPrompt(Prompt prompt)
        {
            PromptType promptType = prompt.AskOption<PromptType>("Select a prompt type:");
            return promptType switch
            {
                PromptType.SelectAccount => MsalPrompt.SelectAccount,
                PromptType.Consent => MsalPrompt.Consent,
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
                    string localAppDataPath = OperatingSystem.IsWindows()
                        ? Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)
                        : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".local");
                    cacheFilePath = Path.Combine(
                        localAppDataPath,
                        ".IdentityService", "msal.cache");
                    if (OperatingSystem.IsMacOS())
                    {
                        osxKcService = "Microsoft.Developer.IdentityService";
                        osxKcAccount = "MSALCache";
                    }

                    break;
                default:
                    cacheFilePath = prompt.AskString("Enter token cache file path:");
                    if (OperatingSystem.IsMacOS())
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

            if (OperatingSystem.IsMacOS())
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

        private static string[] GetScopes(
            Prompt prompt, string azureDevOps, string azureDevOpsCodeFull, string graphUserRead,
            string bundleServerBundleRead)
        {
            ScopeSet scopeSet = prompt.AskOption<ScopeSet>("Select scopes:");
            string[] scopes = scopeSet switch
            {
                ScopeSet.AzureDevOpsDefault => new[] {azureDevOps},
                ScopeSet.AzureDevOpsCodeFull => new[] {azureDevOpsCodeFull},
                ScopeSet.MicrosoftGraph => new[] {graphUserRead},
                ScopeSet.MsGitApiTelemetryReadConfig => new [] {bundleServerBundleRead},
                _ => prompt.AskString("Enter custom scopes:").Split(' ')
            };
            return scopes;
        }

        private static void WriteSuccess(IConsole console, Prompt prompt, AuthenticationResult result)
        {
            console.WriteLineSuccess("Authentication successful!");
            console.WriteLineInfo("User name: {0}", result.Account.Username);
            console.WriteLineInfo("Home tenant ID: {0}", result.Account.HomeAccountId.TenantId);

            bool printFull = prompt.AskBoolean("Print raw token value?", false);
            if (printFull)
            {
                console.WriteLineInfo(result.AccessToken);

                var handler = new JsonWebTokenHandler();

                JsonWebToken? jwt = null;
                try
                {
                    jwt = (JsonWebToken)handler.ReadToken(result.AccessToken);
                }
                catch
                {
                    // ignored
                }

                if (jwt is not null)
                {
                    console.WriteLineInfo(
                        jwt.IsEncrypted
                            ? "Token is an encrypted JWT."
                            : "Token is an unencrypted JWT."
                    );

                    if (!jwt.IsEncrypted && prompt.AskBoolean("Print decoded JWT?", false))
                    {
                        var jsonOptions = new JsonSerializerOptions { WriteIndented = true };
                        string Base64ToPrettyJson(string encoded)
                        {
                            byte[] bytes = Base64UrlConvert.Decode(encoded);
                            string json = Encoding.UTF8.GetString(bytes);
                            var obj = JsonSerializer.Deserialize<JsonElement>(json);
                            return JsonSerializer.Serialize(obj, jsonOptions);
                        }

                        var sb = new StringBuilder();
                        sb.Append(Base64ToPrettyJson(jwt.EncodedHeader));
                        sb.Append('.');
                        sb.Append(Base64ToPrettyJson(jwt.EncodedPayload));
                        sb.Append(".[signature]");

                        console.WriteLineInfo(sb.Replace("{", "{{").Replace("}", "}}").ToString());
                    }
                }
                else
                {
                    console.WriteLineAlert("Token is opaque.");
                }
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
                case FlowType.EmbeddedWebView:
                    ati.WithUseEmbeddedWebView(true);
                    break;
            }

            AuthenticationResult result = await ati.ExecuteAsync();
            return result;
        }

        private static async Task<AuthenticationResult> AcquireTokenSilentAsync(
            IPublicClientApplication pca, string[] scopes, IAccount account)
        {
            return await pca.AcquireTokenSilent(scopes, account).ExecuteAsync();
        }

        private static IPublicClientApplication BuildPca(Uri? authority, string? clientId, string? redirectUri,
            bool useBroker, bool useMsaPt, bool listOsAccounts)
        {
            // Use dummy client ID if we're only listing accounts in the cache
            clientId ??= Guid.NewGuid().ToString("D");

            var builder = PublicClientApplicationBuilder.Create(clientId);

            if (authority != null)
                builder = builder.WithAuthority(authority);

            if (redirectUri != null)
                builder = builder.WithRedirectUri(redirectUri);

            if (useBroker)
            {
                builder.WithBroker(
                    new BrokerOptions(BrokerOptions.OperatingSystems.Windows)
                    {
                        Title = "MSAL CLI",
                        MsaPassthrough = useMsaPt,
                        ListOperatingSystemAccounts = listOsAccounts,
                    }
                );

                SetParentWindowHandle(builder);
            }

            builder = builder.WithWindowsEmbeddedBrowserSupport();

            IPublicClientApplication pca = builder.Build();
            return pca;
        }

        private static void SetParentWindowHandle(PublicClientApplicationBuilder builder)
        {
            if (OperatingSystem.IsWindows())
            {
                builder.WithParentActivityOrWindow(() => GetAncestor(GetConsoleWindow(), 3));
            }
        }

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetConsoleWindow();

        [DllImport("user32.dll")]
        private static extern IntPtr GetAncestor(IntPtr hWnd, int flags);

        private enum ActionType
        {
            AcquireTokenInteractive,
            AcquireTokenSilent,
            ListAccounts,
        }

        private enum FlowType
        {
            SystemWebView,
            EmbeddedWebView,
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
            MicrosoftServices,
            MatthewCheetham,
            Custom,
        }

        private enum ClientType
        {
            TestApp,
            GitCredentialManager,
            VisualStudio,
            VisualStudioNew,
            CodesignClient,
            MsGitTools,
            Custom,
        }

        private enum RedirectType
        {
            Localhost,
            LocalhostIpv4,
            Custom,
        }

        private enum PromptType
        {
            Default,
            SelectAccount,
            Consent,
            ForceLogin,
            NoPrompt,
        }

        private enum ScopeSet
        {
            MicrosoftGraph,
            AzureDevOpsDefault,
            AzureDevOpsCodeFull,
            MsGitApiTelemetryReadConfig,
            Custom,
        }
    }

    internal static class PlatformUtils
    {
        public static bool IsPosix()
        {
            return OperatingSystem.IsMacOS() || OperatingSystem.IsLinux();
        }
    }

    internal static class Base64UrlConvert
    {
        // The base64url format is the same as regular base64 format except:
        //   1. character 62 is "-" (minus) not "+" (plus)
        //   2. character 63 is "_" (underscore) not "/" (slash)
        private const char Base64PadCharacter = '=';
        private const char Base64Character62 = '+';
        private const char Base64Character63 = '/';
        private const char Base64UrlCharacter62 = '-';
        private const char Base64UrlCharacter63 = '_';

        public static string Encode(byte[] data, bool includePadding = true)
        {
            string base64Url = Convert.ToBase64String(data)
                .Replace(Base64Character62, Base64UrlCharacter62)
                .Replace(Base64Character63, Base64UrlCharacter63);

            return includePadding ? base64Url : base64Url.TrimEnd(Base64PadCharacter);
        }

        public static byte[] Decode(string base64Url)
        {
            string base64 = base64Url
                .Replace(Base64UrlCharacter62, Base64Character62)
                .Replace(Base64UrlCharacter63, Base64Character63);

            switch (base64.Length % 4)
            {
                case 2:
                    base64 += $"{Base64PadCharacter}{Base64PadCharacter}";
                    break;
                case 3:
                    base64 += Base64PadCharacter.ToString();
                    break;
            }

            return Convert.FromBase64String(base64);
        }
    }
}
