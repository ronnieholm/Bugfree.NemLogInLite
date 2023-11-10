namespace Bugfree.NemLogInLite.Web

open System
open System.ComponentModel.DataAnnotations
open System.Globalization
open System.Reflection
open System.Text
open System.Text.Json
open System.Threading.Tasks
open Microsoft.AspNetCore.Authentication.JwtBearer
open Microsoft.AspNetCore.Builder
open Microsoft.AspNetCore.Hosting
open Microsoft.AspNetCore.Http
open Microsoft.AspNetCore.Mvc
open Microsoft.AspNetCore.Mvc.Controllers
open Microsoft.Extensions.Configuration
open Microsoft.Extensions.DependencyInjection
open Microsoft.Extensions.Hosting
open Microsoft.Extensions.Options
open Microsoft.FSharp.Core
open Microsoft.IdentityModel.Tokens

module Seedwork =
    exception WebException of string

    let panic (s: string) : 't = raise (WebException(s))

    // By default only a public top-level type ending in Controller is
    // considered one. It means controllers inside a module aren't found. As a
    // module compiles to a class with nested classes for controllers, we can
    // find controllers that way.
    type ControllerWithinModule() =
        inherit ControllerFeatureProvider()

        override _.IsController(typeInfo: TypeInfo) : bool =
            base.IsController(typeInfo)
            || typeInfo.FullName.StartsWith("Bugfree.NemLogInLite.Web.Controller")

open Seedwork

module Saml =
    let (|SamlResponse|SamlRequest|) (request: HttpRequest) =
        if not (String.IsNullOrWhiteSpace(request.Query["SamlResponse"])) then
            SamlResponse ""
        else if not (String.IsNullOrWhiteSpace(request.Query["returnUrl"])) then
            // If no query parameter starting with "saml", assume login request
            SamlRequest(request.Query["returnUrl"] |> Seq.toList |> Seq.exactlyOne |> Uri)
        else
            panic ""

module Configuration =
    [<AllowNullLiteral>]
    type Federation() =
        [<Required>]
        member val SessionCookieName: string = null with get, set

    [<AllowNullLiteral>]
    type IdentityProvider() =
        [<Required>]
        member val Foo: string = null with get, set
        
    
    type NemLogInSettings() =
        static member NemLogIn: string = nameof NemLogInSettings.NemLogIn
        [<Required>]
        member val Federation: Federation = null with get, set
        [<Required>]
        member val IdentityProvider: IdentityProvider = null with get, set
    
    type JwtAuthenticationSettings() =
        static member JwtAuthentication: string = nameof JwtAuthenticationSettings.JwtAuthentication
        [<Required>]
        member val Issuer: Uri = null with get, set
        [<Required>]
        member val Audience: Uri = null with get, set
        [<Required>]
        member val SigningKey: string = null with get, set
        [<Range(60, 86400)>]
        member val ExpirationInSeconds: uint = 0ul with get, set

open Configuration
open Saml

module Controller =
    type NemLoginLiteController(configuration: IConfiguration) =
        inherit ControllerBase()

    [<Route("[controller]")>]
    type AuthenticationController(configuration: IConfiguration, jwtAuthenticationSettings: IOptions<JwtAuthenticationSettings>) as x =
        inherit NemLoginLiteController(configuration)

    [< (*Authorize;*) Route("[controller]")>]
    type TestController(configuration: IConfiguration) =
        inherit NemLoginLiteController(configuration)

        [<HttpGet>]
        member x.Get() : Task<string> = task { return "Hello World" }

    // Metadata for the demo service provider specifies that for login, the IdP is to redirect
    // back to https://oiosaml-net.dk:20002/login.ashx. So even though this isn't an ashx handler,
    // it must appear as such. For a new service provider, don't carry over ashx and port is
    // usually 443.
    [<Route("login.ashx")>]
    type NemLogInController(configuration: IConfiguration, nemLogInSettings: IOptions<NemLogInSettings>) =
        inherit NemLoginLiteController(configuration)

        let nemLogInSettings = nemLogInSettings.Value

        // Session state is required to correlate the sending of an IdP request with a response.
        // The SP only ever communicates with the IdP through the client's browser, so we need
        // a piece of identifying information to be passed along to identify the current client
        // session.
        let ensureAspNetSessionState () : bool = false

        let constructIdPRequest () : unit = ()

        [<HttpGet>]
        member x.Handle() : ActionResult =
            match x.HttpContext.Request with
            | SamlResponse r -> ()
            | SamlRequest returnUrl ->
                // Create new session, disregarding any existing one (not the ASP.NET session).
                let sessionId = Guid.NewGuid()
                x.Response.Cookies.Append(
                    nemLogInSettings.Federation.SessionCookieName,
                    sessionId.ToString(),
                    CookieOptions(Secure = true, HttpOnly = true, SameSite = SameSiteMode.None)
                )

                // Construct IdP request.
                // Only redirect to whitelisted URLs to prevent an open redirect attack.
                if returnUrl <> Uri("/") then
                    panic ""

                x.HttpContext.Session.SetString("returnUrl", returnUrl.ToString())
                //let request = createAuthenticationRequest()
                
                
                
                ()
            | _ as r -> panic "Unsupported request"

            panic "TODO"

type Startup(configuration: IConfiguration) =
    // This method gets called by the runtime. Use this method to add services
    // to the container. For more information on how to configure your
    // application, visit https://go.microsoft.com/fwlink/?LinkID=398940
    member _.ConfigureServices(services: IServiceCollection) : unit =
        services
            .AddOptions<JwtAuthenticationSettings>()
            .BindConfiguration(JwtAuthenticationSettings.JwtAuthentication)
            .ValidateDataAnnotations()
            .ValidateOnStart()
        |> ignore

        services
            .AddOptions<NemLogInSettings>()
            .BindConfiguration(NemLogInSettings.NemLogIn)
            .ValidateDataAnnotations()
            .ValidateOnStart()
        |> ignore

        let serviceProvider = services.BuildServiceProvider()
        let jwtAuthenticationSettings =
            serviceProvider.GetService<IOptions<JwtAuthenticationSettings>>().Value

        services
            .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(fun options ->
                options.TokenValidationParameters <-
                    TokenValidationParameters(
                        ValidateIssuer = true,
                        ValidateAudience = true,
                        ValidateIssuerSigningKey = true,
                        ValidIssuer = jwtAuthenticationSettings.Issuer.ToString(),
                        ValidAudience = jwtAuthenticationSettings.Audience.ToString(),
                        ClockSkew = TimeSpan.Zero,
                        IssuerSigningKey = SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtAuthenticationSettings.SigningKey))
                    )

                // Leave in callbacks for troubleshooting JWT issues. Set a
                // breakpoint on lines below to track the JWT authentication
                // process.
                options.Events <-
                    JwtBearerEvents(
                        OnAuthenticationFailed = (fun _ -> Task.CompletedTask),
                        OnTokenValidated = (fun _ -> Task.CompletedTask),
                        OnForbidden = (fun _ -> Task.CompletedTask),
                        OnChallenge = (fun _ -> Task.CompletedTask)
                    ))
        |> ignore

        services.AddCors(fun options ->
            options.AddDefaultPolicy(fun builder -> builder.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod() |> ignore))
        |> ignore

        services
            .AddMvc(fun options -> options.EnableEndpointRouting <- false)
            .ConfigureApplicationPartManager(fun pm -> pm.FeatureProviders.Add(ControllerWithinModule()))
            .AddJsonOptions(fun options ->
                let o = options.JsonSerializerOptions
                o.PropertyNamingPolicy <- JsonNamingPolicy.SnakeCaseLower
                o.WriteIndented <- true)
        |> ignore

        services.AddControllers() |> ignore
        services.AddEndpointsApiExplorer() |> ignore

        services.AddDistributedMemoryCache() |> ignore
        services.AddSession(fun options ->
            options.IdleTimeout <- TimeSpan.FromMinutes(30)
            options.Cookie.HttpOnly <- true
            options.Cookie.IsEssential <- true)
        |> ignore

    // This method gets called by the runtime. Use this method to configure the
    // HTTP request pipeline.
    member _.Configure (app: IApplicationBuilder) (env: IWebHostEnvironment) : unit =
        if env.IsDevelopment() then app.UseDeveloperExceptionPage() |> ignore else ()

        app.UseHttpsRedirection() |> ignore
        app.UseCors() |> ignore
        app.UseRouting() |> ignore
        app.UseAuthentication() |> ignore
        app.UseAuthorization() |> ignore
        app.UseMvcWithDefaultRoute() |> ignore
        app.UseSession() |> ignore

module Program =
    // Avoid the application using the host's (unexpected) culture. This can
    // make parsing unexpectedly go wrong.
    CultureInfo.DefaultThreadCurrentCulture <- CultureInfo.InvariantCulture
    CultureInfo.DefaultThreadCurrentUICulture <- CultureInfo.InvariantCulture

    // Top-level handler for unobserved task exceptions
    // https://social.msdn.microsoft.com/Forums/vstudio/en-US/bcb2b3fa-9fcd-4a90-9f9c-9ef24332451e/how-to-handle-exceptions-with-taskschedulerunobservedtaskexception?forum=parallelextensions
    TaskScheduler.UnobservedTaskException.Add(fun (e: UnobservedTaskExceptionEventArgs) ->
        e.SetObserved()
        e.Exception.Handle(fun e ->
            printfn $"Unobserved %s{e.GetType().Name}: %s{e.Message}. %s{e.StackTrace}"
            true))

    [<EntryPoint>]
    let main args =
        let host =
            Host
                .CreateDefaultBuilder(args)
                .ConfigureWebHostDefaults(fun builder -> builder.UseStartup<Startup>() |> ignore)
                .Build()
        host.Run()
        0
