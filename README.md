# Pwned Passwords
This library provides a simple `HttpClient` instance that consumes Troy Hunt's [PwnedPasswords API v3](https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange) and checks a password's integrity whether it has previously appeared in a data breach or not. It also includes ASP.NET Core Identity `IPasswordValidator` implementation along with an extension method to inject it  using Dependency Injection principle.
## Installation
In Package Manager Console (Visual Studio), select a specified project into which you want to install the package and enter the command `Install-Package Matrixsoft.PwnedPasswords` or [use any of these methods](https://docs.microsoft.com/en-us/nuget/consume-packages/overview-and-workflow#ways-to-install-a-nuget-package) according to your development environment. 
## Usage
### For .NET Core app:
```csharp
var _client = new PwnedPasswordsClient();
var flag = await _client.IsPasswordPwnedAsync(password);
if (flag)
{
    // TODO: Failed
}
else
{
    // TODO: Success
}
```
### For ASP.NET Core Web app:
Add the password validator to [ASP.NET Core Identity](https://docs.microsoft.com/en-us/aspnet/core/security/authentication/identity) configuration using the `IdentityBuilder` extension method in `Startup.cs`
```csharp
public void ConfigureServices(IServiceCollection services)
{
    services.AddDbContext<ApplicationDbContext>(options =>
        options.UseSqlite(
            Configuration.GetConnectionString("DefaultConnection")));
    services.AddDefaultIdentity<IdentityUser>(options => options.SignIn.RequireConfirmedAccount = true)
        .AddPwnedPasswordsValidator<IdentityUser>()
        .AddEntityFrameworkStores<ApplicationDbContext>();
    services.AddControllersWithViews();
    services.AddRazorPages();

    services.AddTransient<PwnedPasswordsClient>();
}
```
## Thanks
- [Troy Hunt](https://www.troyhunt.com/)
## Problems
If you run into bugs / have feature suggestions / have questions, please file a Github bug.
