# Adding Identity to Blazor Server

In this module I'll show you how to get basic authentication and authorization working for an existing Blazor Server application using the **ASP.NET Core Identity** subsystem. I'll show you how to authorize markup, entire pages, and even code actions based on roles. I'll also show you how to manage roles for users.

## Prerequisites

The following prerequisites are needed for this demo.

### .NET 7.0

.NET 7 is installed with Visual Studio, but you can always download the latest version of the .NET 7.0 SDK [here](https://dotnet.microsoft.com/en-us/download).

### Visual Studio 2022

For this demo, we are going to use the latest version of [Visual Studio 2022](https://visualstudio.microsoft.com/vs/community/).

## Definitions:

**Authentication**: The process of confirming that a user is the person that they say they are. The user is represented by an *Identity*.

**Authorization**: Now that we know the user's *Identity*, what are we going to allow them to do? Authorization is allowing the user to access aspects of your application based on their *Identity*, and the roles or claims they present.

**Role**: A *Role* is simply a name, like *admin*, *supervisor*, or *content_manager*. You can assign users to one or more roles, and then check those roles at runtime to authorize the user to do or see an aspect of the application. We will use roles in this module.

**Claim**: A *Claim* is an assertion by the user, such as their *name*, or *email address*. It can also be very specific to an aspect of the application, such as "canClickTheCounterButton". A *Claim* is like a *Role*, but more specific to the action they want to perform or the aspect they want to access. Claims are being favored over roles, but role-based authentication is still very useful and very powerful.

There are many ways to do authentication and authorization in a Blazor Server application. 

We are going to use the **ASP.NET Core Identity** subsystem including support for roles.

The default Blazor Server template does not include support for Identity, but we are going to add everything needed to generate an identity database, a standard schema used by the ASP.NET Core Identity subsystem. Well, almost everything. 

When we're done, our Blazor Server application will allow users to register, log in, and log out. We can then authorize sections of markup, entire pages, and even code, based on whether or not the user is authenticated and what roles they are in. 

In order to create roles and assign them to users, we'll need a little [helper application](https://github.com/carlfranklin/IdentityManagerLibrary) which I've already written and discussed in [BlazorTrain episode 84, Identity Management](https://www.youtube.com/watch?v=Q0dMdQtQduc).

## Demo

Create a new **Blazor Server App** project called **BasicAuth**.

![image-20230717123735287](images/image-20230717123735287.png)

![image-20230717123748814](images/image-20230717123748814.png)

![image-20230717123831836](images/image-20230717123831836.png)

Add the following packages to the .csproj file:

```xml
<ItemGroup>
    <PackageReference Include="Microsoft.VisualStudio.Web.CodeGeneration.Design" Version="7.0.8" />
    <PackageReference Include="Microsoft.AspNetCore.Diagnostics.EntityFrameworkCore" Version="7.0.9" />
</ItemGroup>
```

### Scaffolding

Visual Studio has a great scaffolding wizard for adding ASP.NET Core Identity features. However, as of this writing (Mid-July 2023) the generated code has not caught up to what's in the template. We'll start with the scaffolding, and fix what we need to along the way.

Check out the Identity database name in *appsettings.json*. It defaults to the name of the project. In our case, BasicAuth.

```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning"
    }
  },
  "AllowedHosts": "*",
  "ConnectionStrings": {
    "BasicAuthContextConnection": "Server=(localdb)\\mssqllocaldb;Database=BasicAuth;Trusted_Connection=True;MultipleActiveResultSets=true"
  }
}
```

Right-click on the project name, and select the **Add New Scaffolded Item...** menu option.

Select **Identity** from the list on the left, and **Identity** from the result list, then select the **Add** button.

![image-20230717151101185](images/image-20230717151101185.png)

Select the options **Account\\Login**, **Account\Logout**, and **Account\Register**.

Also, press the **Plus** button

![image-20230717150845065](images/image-20230717150845065.png)



<img src="images/image-20230717150957468.png" alt="image-20230717150957468" style="zoom:67%;" />

Generate the database script code by executing the following command in the **Package Manager Console**:

```
add-migration CreateIdentitySchema
```

Create the database by executing the following command:

```
update-database
```

Replace *App.razor* with the following:

```xml
<CascadingAuthenticationState>
    <Router AppAssembly="@typeof(App).Assembly">
        <Found Context="routeData">
            <AuthorizeRouteView RouteData="@routeData" DefaultLayout="@typeof(MainLayout)" />
            <FocusOnNavigate RouteData="@routeData" Selector="h1" />
        </Found>
        <NotFound>
            <PageTitle>Not found</PageTitle>
            <LayoutView Layout="@typeof(MainLayout)">
                <p role="alert">Sorry, there's nothing at this address.</p>
            </LayoutView>
        </NotFound>
    </Router>
</CascadingAuthenticationState>
```

The two main changes we made were

1. Changing the `RouteView` component to an `AuthorizeRouteView` component
2. Wrapping the `Router` component in a `CascadingAuthenticationState` component.

Add the following class to the *Areas\Identity* folder.

*RevalidatingIdentityAuthenticationStateProvider.cs*:

```c#
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using System.Security.Claims;

namespace BasicAuth.Areas.Identity;

public class RevalidatingIdentityAuthenticationStateProvider<TUser>
    : RevalidatingServerAuthenticationStateProvider where TUser : class
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly IdentityOptions _options;

    public RevalidatingIdentityAuthenticationStateProvider(
        ILoggerFactory loggerFactory,
        IServiceScopeFactory scopeFactory,
        IOptions<IdentityOptions> optionsAccessor)
        : base(loggerFactory)
    {
        _scopeFactory = scopeFactory;
        _options = optionsAccessor.Value;
    }

    protected override TimeSpan RevalidationInterval => TimeSpan.FromMinutes(30);

    protected override async Task<bool> ValidateAuthenticationStateAsync(
        AuthenticationState authenticationState, CancellationToken cancellationToken)
    {
        // Get the user manager from a new scope to ensure it fetches fresh data
        var scope = _scopeFactory.CreateScope();
        try
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<TUser>>();
            return await ValidateSecurityStampAsync(userManager, authenticationState.User);
        }
        finally
        {
            if (scope is IAsyncDisposable asyncDisposable)
            {
                await asyncDisposable.DisposeAsync();
            }
            else
            {
                scope.Dispose();
            }
        }
    }

    private async Task<bool> ValidateSecurityStampAsync(UserManager<TUser> userManager, ClaimsPrincipal principal)
    {
        var user = await userManager.GetUserAsync(principal);
        if (user == null)
        {
            return false;
        }
        else if (!userManager.SupportsUserSecurityStamp)
        {
            return true;
        }
        else
        {
            var principalStamp = principal.FindFirstValue(_options.ClaimsIdentity.SecurityStampClaimType);
            var userStamp = await userManager.GetSecurityStampAsync(user);
            return principalStamp == userStamp;
        }
    }
}
```

This class inherits [RevalidatingServerAuthenticationStateProvider](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.components.server.revalidatingserverauthenticationstateprovider?view=aspnetcore-7.0), a base class for [AuthenticationStateProvider](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.components.authorization.authenticationstateprovider?view=aspnetcore-7.0) services that receive an authentication state from the host environment, and revalidate it at regular intervals. This file would get added if we selected **Individual Accounts** when creating the project in Visual Studio.

Replace *Program.cs* with the following:

```c#
using BasicAuth.Areas.Identity;
using BasicAuth.Data;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);
var connectionString = builder.Configuration.GetConnectionString("BasicAuthContextConnection") ?? throw new InvalidOperationException("Connection string 'AddIdentityContextConnection' not found.");

// Add services to the container.
builder.Services.AddDbContext<BasicAuthContext>(options => options.UseSqlServer(connectionString));
builder.Services.AddDatabaseDeveloperPageExceptionFilter();
builder.Services.AddDefaultIdentity<IdentityUser>(options => options.SignIn.RequireConfirmedAccount = true)
    .AddRoles<IdentityRole>()
    .AddEntityFrameworkStores<BasicAuthContext>();
builder.Services.AddRazorPages();
builder.Services.AddServerSideBlazor();
builder.Services.AddScoped<AuthenticationStateProvider, 
	RevalidatingIdentityAuthenticationStateProvider<IdentityUser>>();
builder.Services.AddSingleton<WeatherForecastService>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseStaticFiles();

app.UseRouting();

app.UseAuthorization();

app.MapControllers();
app.MapBlazorHub();
app.MapFallbackToPage("/_Host");

app.Run();
```

Add to the *\Shared* folder:

*LoginDisplay.razor*:

```xml
<AuthorizeView>
    <Authorized>
        <a href="Identity/Account/Manage">Hello, @context.User.Identity?.Name!</a>
        <form method="post" action="Identity/Account/Logout">
            <button type="submit" class="nav-link btn btn-link">Log out</button>
        </form>
    </Authorized>
    <NotAuthorized>
        <a href="Identity/Account/Register">Register</a>
        <a href="Identity/Account/Login">Log in</a>
    </NotAuthorized>
</AuthorizeView>
```

This shows our login status, and gives us links for registering, logging in, and logging out.  This file would get added if we selected **Individual Accounts** when creating the project in Visual Studio.

Replace *MainLayout.razor* with the following:

```xml
@inherits LayoutComponentBase

<PageTitle>BasicAuth</PageTitle>

<div class="page">
    <div class="sidebar">
        <NavMenu />
    </div>

    <main>
        <div class="top-row px-4">
            <LoginDisplay />
            <a href="https://docs.microsoft.com/aspnet/" target="_blank">About</a>
        </div>

        <article class="content px-4">
            @Body
        </article>
    </main>
</div>
```

We added the `LoginDisplay` component in the top bar.

If you run the app now, it will not run. We need to make a change.

Replace *Areas\Identity\Pages\Account\Logout.cshtml* with the following:

```c#
@page
@using Microsoft.AspNetCore.Identity
@attribute [IgnoreAntiforgeryToken]
@inject SignInManager<IdentityUser> SignInManager
@functions {
    public async Task<IActionResult> OnPost()
    {
        if (SignInManager.IsSignedIn(User))
        {
            await SignInManager.SignOutAsync();
        }

        return Redirect("~/");
    }
}
```

### Authorization

Let's start by doing a little authorization of markup.

Replace *\Shared\NavMenu.razor* with the following:

```c#
<div class="top-row ps-3 navbar navbar-dark">
    <div class="container-fluid">
        <a class="navbar-brand" href="">BasicAuth</a>
        <button title="Navigation menu" class="navbar-toggler" @onclick="ToggleNavMenu">
            <span class="navbar-toggler-icon"></span>
        </button>
    </div>
</div>

<div class="@NavMenuCssClass nav-scrollable" @onclick="ToggleNavMenu">
    <nav class="flex-column">
        <div class="nav-item px-3">
            <NavLink class="nav-link" href="" Match="NavLinkMatch.All">
                <span class="oi oi-home" aria-hidden="true"></span> Home
            </NavLink>
        </div>
        <AuthorizeView>
            <div class="nav-item px-3">
                <NavLink class="nav-link" href="counter">
                    <span class="oi oi-plus" aria-hidden="true"></span> Counter
                </NavLink>
            </div>
        </AuthorizeView>
        <AuthorizeView Roles="admin">
            <div class="nav-item px-3">
                <NavLink class="nav-link" href="fetchdata">
                    <span class="oi oi-list-rich" aria-hidden="true"></span> Fetch data
                </NavLink>
            </div>
        </AuthorizeView>
    </nav>
</div>

@code {
    private bool collapseNavMenu = true;

    private string? NavMenuCssClass => collapseNavMenu ? "collapse" : null;

    private void ToggleNavMenu()
    {
        collapseNavMenu = !collapseNavMenu;
    }
}
```

You can see that I've enclosed the `NavLink` to **Counter** in an `<AuthorizeView>` component:

```xml
<AuthorizeView>
    <div class="nav-item px-3">
        <NavLink class="nav-link" href="counter">
            <span class="oi oi-plus" aria-hidden="true"></span> Counter
        </NavLink>
    </div>
</AuthorizeView>
```

This means the user must be authenticated (logged in) before they can see that `NavLink`.

Also, look at the `<AuthorizeView>` I put around the link to the **FetchData** `NavLink`:

```xml
<AuthorizeView Roles="admin">
    <div class="nav-item px-3">
        <NavLink class="nav-link" href="fetchdata">
            <span class="oi oi-list-rich" aria-hidden="true"></span> Fetch data
        </NavLink>
    </div>
</AuthorizeView>
```

Not only does the user need to be logged in to see this `NavLink`, but they must be in the **admin** role. More on roles later. 

> :point_up: You can use `<AuthorizeView>` around any bit of markup in any component or page to restrict it.

Run the app to ensure we can't see these `NavLink`s:

![image-20230717122758493](images/image-20230717122758493.png)

However, you should note that the user can still use the **Counter** and **FetchData** pages just by specifying the route in the URL:

![image-20230717122810385](images/image-20230717122810385.png)

This is possible because we only restricted the `NavLink` objects. In order to really secure the app, we will need to restrict those pages. More on that in a few minutes.

Click the **Register** link in the top-right. You'll be presented with a screen that looks like this:

![image-20230717122822185](images/image-20230717122822185.png)

Enter a user name and password. It doesn't have to be secure, but it does have to meet the basic password requirements. This is your private database on your local machine. My password is "P@ssword1".

Click the **Register** button and you'll be asked to click on a link in order to confirm your account.

This is a shortcut because you don't have an email sender registered, so the app can't do an email verification.

![image-20230717122838144](images/image-20230717122838144.png)

Once you click this link, you can look in the **dbo.AspNetUsers** table, and see that the **EmailConfirmed** field in your user record has been set to *True*. If you do not do this, authentication will fail.

![image-20230717122858261](images/image-20230717122858261.png)

After successfully registering, you can log in.

![image-20230717122913720](images/image-20230717122913720.png)

Now you can see that the `NavLink` for the **Counter** page is enabled, but the **FetchData** `NavLink` is still not showing. That's because we require the user to be in the **admin** role, remember?

![image-20230717122925930](images/image-20230717122925930.png)

However, we can still navigate to the **FetchData** page by specifying the route:

![image-20230717122938604](images/image-20230717122938604.png)

Let's button up our two authorized pages now.

Add the following to *Counter.razor* at line 2:

```c#
@attribute [Authorize]
```

This will require the user to be authenticated (logged in) in order to see the page.

Add this to *FetchData.razor* at line 2:

```c#
@attribute [Authorize(Roles = "admin")]
```

This requires the user to be authenticated AND in the **admin** role.

Log out and log in again. Now you can not:

- access either **Counter** or **FetchData** if you are not logged in, even if you specify the route in the url
- access **FetchData** if you are not in the **admin** role

## Adding Roles

The Visual Studio template doesn't provide a means to manage roles and users. To address this, I built a `netstandard` class library based on [this GitHub repo by mguinness](https://github.com/mguinness/IdentityManagerUI). 

It's called [IdentityManagerLibrary](https://github.com/carlfranklin/IdentityManagerLibrary). Download or clone the repo, and set **IdentityManagerBlazorServer** as the startup project.

All you have to do is set the ConnectionString to the Identity Database in the *appsettings.json* file to the **BasicAuth** database, run it, and you'll be able to add roles and users.

After changing the connection string, run the app:

![image-20230717122959770](images/image-20230717122959770.png)

Click on the **Users** `NavLink`.

![image-20230717123011697](images/image-20230717123011697.png)

There's my user with no roles set.

Click the **Roles** `NavLink` and then click the **New** button to add a role:

![image-20230717123021593](images/image-20230717123021593.png)

Enter **admin** as the role name, and click the **Save** button:

![image-20230717123030921](images/image-20230717123030921.png)

Now, navigate back to the **Users** page and click the **Edit** button to edit our user:

![image-20230717123040937](images/image-20230717123040937.png)

Select the **admin** role, and click the **Save** button:

![image-20230717123050745](images/image-20230717123050745.png)

Leave this app running if you can, and run the **BasicAuth** app again.

> :point_up: If you are logged in, you must log out and log in again in order to get a current authentication token.

Now we can see both `Navlink`s on the left, and we can also access both **Counter** and **FetchData**:

![image-20230717123102409](images/image-20230717123102409.png)

## Authorizing Code

So far we have been authorizing markup with `<AuthorizeView>` and entire pages using the `@attribute [Authorize]` attribute. We can also inspect the logged-in user to determine whether they are authenticated and what roles they are in. That let's us use code logic to determine if the user has permission to execute specific code.

Take a look at *App.razor*:

```xml
<CascadingAuthenticationState>
    <Router AppAssembly="@typeof(App).Assembly">
        <Found Context="routeData">
            <AuthorizeRouteView RouteData="@routeData" DefaultLayout="@typeof(MainLayout)" />
            <FocusOnNavigate RouteData="@routeData" Selector="h1" />
        </Found>
        <NotFound>
            <PageTitle>Not found</PageTitle>
            <LayoutView Layout="@typeof(MainLayout)">
                <p role="alert">Sorry, there's nothing at this address.</p>
            </LayoutView>
        </NotFound>
    </Router>
</CascadingAuthenticationState>
```

When you're using ASP.NET Core Identity, your entire application has access to the authentication state as a cascading parameter.

Replace *Counter.razor* with the following:

```c#
@page "/counter"
@attribute [Authorize]
@using System.Security.Claims

<PageTitle>Counter</PageTitle>

<h1>Counter</h1>

<p role="status">Current count: @currentCount</p>

<button class="btn btn-primary" @onclick="IncrementCount">Click me</button>

<br/><br/>
<div style="color:red;">
    @errorMessage
</div>

@code {
    private int currentCount = 0;
    string errorMessage = string.Empty;

    ClaimsPrincipal user = null;

    [CascadingParameter]
    private Task<AuthenticationState>? authenticationState { get; set; }

    private void IncrementCount()
    {
        errorMessage = "";

        // this should never happen because viewing the page is authorized
        if (user == null) return;

        // this should also never happen because viewing the page is authorized
        if (!user.Identity.IsAuthenticated) return;

        if (user.IsInRole("counterClicker"))
        {
            // success!
            currentCount++;
        }
        else
        {
            // wah-wah
            errorMessage = "You do not have permission to increment the counter.";
        }
    }

    protected override async Task OnInitializedAsync()
    {
        if (authenticationState is not null)
        {
            var authState = await authenticationState;
            user = authState?.User;
        }
    }
}
```

In the `@code` block we've added a couple things:

```c#
string errorMessage = string.Empty;

ClaimsPrincipal user = null;

[CascadingParameter]
private Task<AuthenticationState>? authenticationState { get; set; }
```

We will use the `errorMessage` to display an error if the user does not have access.

The `ClaimsPrincipal` represents the logged in user.

The `AuthenticationState` cascading parameter lets us access the `ClaimsPrincipal`. This is done in the `OnInitializedAsync()` method:

```c#
protected override async Task OnInitializedAsync()
{
    if (authenticationState is not null)
    {
        var authState = await authenticationState;
        user = authState?.User;
    }
}
```

The real magic happens here:

```c#
private void IncrementCount()
{
    errorMessage = "";

    // this should never happen because viewing the page is authorized
    if (user == null) return;

    // this should also never happen because viewing the page is authorized
    if (!user.Identity.IsAuthenticated) return;

    if (user.IsInRole("counterClicker"))
    {
        // success!
        currentCount++;
    }
    else
    {
        // wah-wah
        errorMessage = "You do not have permission to increment the counter.";
    }
}
```

According to this, the user has to be in the **counterClicker** role in order to increment the counter. This check is done like so:

```c#
if (user.IsInRole("counterClicker"))
{
   ...
```

But before we can do that check, we have to make sure `user` is not null, and that the `user` is authenticated. These checks are likely not to fail, but it's good practice to check for every contingency. 

Run the app, log out if you're logged-in, log in, go to the **Counter** page, and click the button:

![image-20230717123253129](images/image-20230717123253129.png)

That's what we expected! 

Now run the **IdentityManagerBlazorServer** app, add the **counterClicker** role, then assign it to our user. 

Run the **AuthDemo** app again, log out, log in, and try the counter button again. It now works as expected:

![image-20230717123309353](images/image-20230717123309353.png)

## Summary

In this module we:

- Created a new Blazor Server project without any authentication template code.
- Added support for Identity Roles in *Program.cs*
- Modified the Identity Database connection string in *appsettings.json*
- Generated the migration to create the database with the `add-migration` command
- Generated the database with the `update-database` command
- Added support code and markup for server-based authentication and authorization
- Ran the app and registered a new user
- Authorized markup in *NavMenu.razor*
- Authorized the *Counter.razor* and *FetchData.razor* pages
- Used the **IdentityManagerBlazorServer** app to add roles and assign them
- Authorized access to code using a `ClaimsPrincipal` object representing the user

To watch a video of me creating this code from scratch check out [BlazorTrain episode 55](https://youtu.be/cAie4PCfeqc). 

The complete list of videos with links to code can be found at https://blazortrain.com