# Pwned Passwords
This library provides a simple `HttpClient` instance that consumes Troy Hunt's [PwnedPasswords API v2](https://haveibeenpwned.com/API/v2#PwnedPasswords) and checks a password's integrity whether it has previously appeared in a data breach or not. It also includes ASP.NET Core Identity `IPasswordValidator` implementation along with an extension method to inject it  using Dependency Injection principle.
## Installation
In Package Manager Console (Visual Studio), select a specified project into which you want to install the package and enter the command `Install-Package Matrixsoft.PwnedPasswords` or [use any of these methods](https://docs.microsoft.com/en-us/nuget/consume-packages/ways-to-install-a-package) according to your development environment. 
## Usage
### For .NET Core app:
```csharp
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
Add the password validator to [ASP.NET Core Identity](https://github.com/aspnet/Identity) configuration using the `IdentityBuilder` extension method in `Startup.cs`
```csharp
public void ConfigureServices(IServiceCollection services)
{
    services.AddDbContext<ApplicationDbContext>(options =>
        options.UseSqlite(Configuration.GetConnectionString("DefaultConnection")));

    services.AddIdentity<ApplicationUser, IdentityRole>()
        .AddPwnedPasswordsValidator<ApplicationUser>() // <-- Add this line
        .AddEntityFrameworkStores<ApplicationDbContext>()
        .AddDefaultTokenProviders();

    services.AddTransient<PwnedPasswordsClient>(); // <-- Add this line
    services.AddTransient<IEmailSender, EmailSender>();

    services.AddMvc();
}
```
## Thanks
- [Troy Hunt](https://www.troyhunt.com/)
## Problems
If you run into bugs / have feature suggestions / have questions, please file a Github bug.
