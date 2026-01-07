using ExamManagement.Data;
using ExamManagement.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews(options =>
{
    // Enable CSRF protection globally
    options.Filters.Add(new Microsoft.AspNetCore.Mvc.AutoValidateAntiforgeryTokenAttribute());
}); // MVC

// Add Antiforgery service
builder.Services.AddAntiforgery(options =>
{
    options.HeaderName = "X-CSRF-TOKEN";
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
    options.Cookie.SameSite = SameSiteMode.Strict;
});

builder.Services.AddControllers(); // API

// Ensure WebRoot exists for Docker
var webRoot = Path.Combine(builder.Environment.ContentRootPath, "wwwroot");
if (!Directory.Exists(webRoot)) Directory.CreateDirectory(webRoot);

// Ensure Storage exists
var storageRoot = Path.Combine(builder.Environment.ContentRootPath, "Storage");
if (!Directory.Exists(storageRoot)) Directory.CreateDirectory(storageRoot);

// DB Context
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// Services
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<IUserService, UserService>();
builder.Services.AddScoped<IExamService, ExamService>();

// JWT Configuration
var jwtKey = builder.Configuration["Jwt:Key"] ?? throw new InvalidOperationException("JWT Key missing");
var key = Encoding.ASCII.GetBytes(jwtKey);

builder.Services.AddAuthentication(options =>
{
    // We use a custom scheme or just set default to Cookie, but strictly use JWT logic?
    // The requirement is "SSR, use JWT". 
    // Best approach: Use Cookie Authentication for the Scheme, but the Ticket is created from JWT validation?
    // Or: Standard JWT Bearer for API, and a Middleware that reads Cookie -> Header for SSR views.
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.RequireHttpsMetadata = false;
    options.SaveToken = true;
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(key),
        ValidateIssuer = true,
        ValidIssuer = builder.Configuration["Jwt:Issuer"],
        ValidateAudience = true,
        ValidAudience = builder.Configuration["Jwt:Audience"]
    };
    
    // Allow reading from Cookie for SSR
    options.Events = new JwtBearerEvents
    {
        OnMessageReceived = context =>
        {
            var token = context.Request.Cookies["access_token"];
            if (!string.IsNullOrEmpty(token))
            {
                context.Token = token;
            }
            return Task.CompletedTask;
        }
    };
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
}
app.UseStaticFiles();

app.UseRouting();

// Custom Middleware to redirect to Login if 401 (for SSR UX)
app.Use(async (context, next) =>
{
    await next();

    if (context.Response.StatusCode == 401 && !context.Request.Path.StartsWithSegments("/api"))
    {
        // If it's a View request and Unauthorized, redirect to Login
        var returnUrl = context.Request.Path + context.Request.QueryString;
        context.Response.Redirect($"/Auth/Login?ReturnUrl={System.Net.WebUtility.UrlEncode(returnUrl)}");
    }
});

app.UseAuthentication();
app.UseAuthorization();

// Map Controller Routes
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

// Ensure DB is created (Migration on startup - risky for prod but good for this prototype)
using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    var db = services.GetRequiredService<AppDbContext>();
    var authService = services.GetRequiredService<IAuthService>();
    var logger = services.GetRequiredService<ILogger<Program>>();

    int maxRetries = 10;
    for (int i = 0; i < maxRetries; i++)
    {
        try
        {
            // Seed Admin User
            await ExamManagement.Data.DbInitializer.Initialize(db, authService);
            logger.LogInformation("Database initialized successfully.");
            break;
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Database not ready yet. Retrying in 3 seconds... ({RetryCount}/{MaxRetries})", i + 1, maxRetries);
            if (i == maxRetries - 1) throw;
            await Task.Delay(3000);
        }
    }
}

app.Run();
