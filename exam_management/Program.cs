using ExamManagement.Data;
using ExamManagement.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.Data.SqlClient;
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
builder.Services.AddControllers(); // API

// Add Antiforgery service
builder.Services.AddAntiforgery(options =>
{
    options.HeaderName = "X-CSRF-TOKEN";
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = builder.Environment.IsDevelopment() 
        ? CookieSecurePolicy.SameAsRequest 
        : CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;
});

// Ensure WebRoot exists for Docker
var webRoot = Path.Combine(builder.Environment.ContentRootPath, "wwwroot");
if (!Directory.Exists(webRoot)) Directory.CreateDirectory(webRoot);

// Ensure Storage exists
var storageRoot = Path.Combine(builder.Environment.ContentRootPath, "Storage");
if (!Directory.Exists(storageRoot)) Directory.CreateDirectory(storageRoot);

// DB Context - Use environment variable for connection string
// Docker Compose sets ConnectionStrings__DefaultConnection which ASP.NET Core maps automatically
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
if (string.IsNullOrEmpty(connectionString))
{
    // Fallback: Build connection string from environment variables
    var dbPassword = Environment.GetEnvironmentVariable("DB_PASSWORD") ?? "YourStrong@Password123!";
    // SQL Server connection string - password with special characters needs to be properly escaped
    // Use SqlConnectionStringBuilder for proper escaping
    var builder_cs = new SqlConnectionStringBuilder
    {
        DataSource = "db",
        InitialCatalog = "ExamDB",
        UserID = "sa",
        Password = dbPassword,
        TrustServerCertificate = true,
        ConnectTimeout = 30
    };
    connectionString = builder_cs.ConnectionString;
}

builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer(connectionString));

// Services
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<IUserService, UserService>();
builder.Services.AddScoped<IExamService, ExamService>();

// JWT Configuration - Use environment variables for security
var jwtKey = Environment.GetEnvironmentVariable("JWT_KEY")
    ?? builder.Configuration["Jwt:Key"]
    ?? throw new InvalidOperationException("JWT Key missing. Set JWT_KEY environment variable.");
var key = Encoding.ASCII.GetBytes(jwtKey);

// Validate JWT key length
if (key.Length < 32)
{
    throw new InvalidOperationException("JWT Key must be at least 32 characters long.");
}

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
    // Require HTTPS in production
    options.RequireHttpsMetadata = !builder.Environment.IsDevelopment();
    options.SaveToken = true;
    var jwtIssuer = Environment.GetEnvironmentVariable("JWT_ISSUER") ?? builder.Configuration["Jwt:Issuer"] ?? "ExamManagement";
    var jwtAudience = Environment.GetEnvironmentVariable("JWT_AUDIENCE") ?? builder.Configuration["Jwt:Audience"] ?? "ExamManagementUsers";
    
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(key),
        ValidateIssuer = true,
        ValidIssuer = jwtIssuer,
        ValidateAudience = true,
        ValidAudience = jwtAudience
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
// Check if HTTPS redirection should be enabled (default: false for Docker compatibility)
var enableHttpsRedirection = app.Configuration.GetValue<bool>("EnableHttpsRedirection", false);

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // Enable HSTS in production (only if HTTPS is configured)
    if (enableHttpsRedirection)
    {
        app.UseHsts();
    }
}
else
{
    app.UseDeveloperExceptionPage();
}

// Security Headers Middleware
app.Use(async (context, next) =>
{
    // Remove server header
    context.Response.Headers.Remove("Server");
    
    // Security headers
    context.Response.Headers.Append("X-Content-Type-Options", "nosniff");
    context.Response.Headers.Append("X-Frame-Options", "DENY");
    context.Response.Headers.Append("X-XSS-Protection", "1; mode=block");
    context.Response.Headers.Append("Referrer-Policy", "strict-origin-when-cross-origin");
    
    // Content Security Policy - Allow CDN resources for Bootstrap, jQuery, Font Awesome
    var csp = "default-src 'self'; " +
              "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://code.jquery.com https://cdn.jsdelivr.net; " +
              "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; " +
              "img-src 'self' data: blob: https://via.placeholder.com https://cdnjs.cloudflare.com; " +
              "font-src 'self' https://cdnjs.cloudflare.com data:; " +
              "connect-src 'self'; " +
              "frame-ancestors 'none';";
    context.Response.Headers.Append("Content-Security-Policy", csp);
    
    await next();
});

// Force HTTPS in production (skip in Docker/Development)
// Only enable HTTPS redirection if explicitly configured
if (!app.Environment.IsDevelopment() && enableHttpsRedirection)
{
    app.UseHttpsRedirection();
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
        context.Response.Redirect("/Auth/Login");
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

    int maxRetries = 30; // Increased retries for Docker
    for (int i = 0; i < maxRetries; i++)
    {
        try
        {
            // Test connection first
            await db.Database.CanConnectAsync();
            // Seed Admin User
            await ExamManagement.Data.DbInitializer.Initialize(db, authService);
            logger.LogInformation("Database initialized successfully.");
            break;
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Database not ready yet. Retrying in 5 seconds... ({RetryCount}/{MaxRetries})", i + 1, maxRetries);
            if (i == maxRetries - 1)
            {
                logger.LogError(ex, "Failed to connect to database after {MaxRetries} attempts. Application will continue but database operations may fail.", maxRetries);
                // Don't throw - let app start even if DB is not ready
                break;
            }
            await Task.Delay(5000); // Increased delay to 5 seconds
        }
    }
}

app.Run();
