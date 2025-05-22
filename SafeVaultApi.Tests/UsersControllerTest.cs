using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using SafeVaultApi.Api.Controllers;
using SafeVaultApi.Api.Data;
using SafeVaultApi.Api.Models;
using SafeVaultApi.Api.Utils;

namespace SafeVaultApi.Tests
{
    public class UsersControllerTest
    {
        private UsersController GetController(out ApiDbContext context, IConfiguration? config = null, ClaimsPrincipal? user = null)
        {
            var options = new DbContextOptionsBuilder<ApiDbContext>()
                .UseInMemoryDatabase(databaseName: "SafeVaultTestDB_" + System.Guid.NewGuid())
                .Options;

            context = new ApiDbContext(options);
            return GetController(context, config, user);
        }

        private UsersController GetController(ApiDbContext context, IConfiguration? config, ClaimsPrincipal? user)
        {
            if (config == null)
            {
                var inMemorySettings = new Dictionary<string, string> {
                    {"Jwt:Key", "0c553abe-8d42-4b44-b033-7762e22bb0d7"},
                    {"Jwt:Issuer", "SafeVaultApi"},
                    {"Jwt:Audience", "SafeVaultApiUsers"}
                };
                config = new ConfigurationBuilder()
                    .AddInMemoryCollection(inMemorySettings!)
                    .Build();
            }

            var controller = new UsersController(context, config);
            if (user != null)
                controller.ControllerContext = new ControllerContext
                {
                    HttpContext = new DefaultHttpContext { User = user }
                };

            return controller;
        }

        [Theory]
        [InlineData("<script>alert('XSS')</script>", "xss@test.com")]
        [InlineData("Robert'); DROP TABLE Users;--", "sql@test.com")]
        public async Task Create_ShouldSanitizeMaliciousInputs(string maliciousName, string email)
        {
            var controller = GetController(out var db);
            var user = new Users { UserName = maliciousName, Email = email };

            var result = await controller.Create(user);

            var savedUser = await db.Users.FirstOrDefaultAsync(u => u.Email == email);
            Assert.NotNull(savedUser);
            Assert.DoesNotContain("<script>", savedUser.UserName, System.StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("DROP TABLE", savedUser.UserName, System.StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public async Task Create_ShouldRejectInvalidEmail()
        {
            var controller = GetController(out var db);
            var user = new Users { UserName = "SafeUser", Email = "not-an-email" };

            var result = await controller.Create(user);

            var badRequest = Assert.IsType<BadRequestObjectResult>(result);
            Assert.Equal(400, badRequest.StatusCode);
        }

        [Fact]
        public async Task Anonymous_ShouldReturnToken_ForValidCredentials()
        {
            var controller = GetController(out var db);
            var password = "Admin.2025";
            var user = new Users { UserName = "Admin", Email = "admin@site.com", Passwd = Passwd.HashPassword(password), IsAdmin = true };
            db.Users.Add(user);
            await db.SaveChangesAsync();

            var loginUser = new Users { UserName = user.UserName, Passwd = password };
            var result = await controller.Authentication(loginUser);

            var okResult = Assert.IsType<OkObjectResult>(result);
            Assert.Contains("token", okResult.Value!.ToString());
        }

        [Fact]
        public async Task Anonymous_ShouldRejectInvalidPassword()
        {
            var controller = GetController(out var db);
            db.Users.Add(new Users { UserName = "Admin", Passwd = Passwd.HashPassword("Admin.2025"), IsAdmin = true });
            await db.SaveChangesAsync();

            var loginUser = new Users { UserName = "Admin", Passwd = "wrongpass" };
            var result = await controller.Authentication(loginUser);

            var unauthorized = Assert.IsType<UnauthorizedObjectResult>(result);
            Assert.Equal(401, unauthorized.StatusCode);
        }

        [Fact]
        public async Task GetOne_ShouldReturnCurrentUser()
        {
            var controller = GetController(out var db);
            var user = new Users { Email = "user@site.com", UserName = "User", Passwd = "", IsAdmin = false };
            db.Users.Add(user);
            await db.SaveChangesAsync();

            var identity = new ClaimsIdentity(new[]
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()!),
                new Claim(ClaimTypes.Role, "User")
            }, "TestAuth");

            var principal = new ClaimsPrincipal(identity);
            var controllerWithUser = GetController(db, null, principal);

            db.Entry(user).State = EntityState.Detached;
            var result = await controllerWithUser.GetOne();

            var okResult = Assert.IsType<OkObjectResult>(result);
            var returnedUser = Assert.IsType<Users>(okResult.Value);
            Assert.Equal(user.Email, returnedUser.Email);
        }
    }
}