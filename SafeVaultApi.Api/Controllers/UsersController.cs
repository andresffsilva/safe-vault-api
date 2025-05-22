using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using SafeVaultApi.Api.Data;
using SafeVaultApi.Api.Models;
using SafeVaultApi.Api.Utils;

namespace SafeVaultApi.Api.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UsersController : ControllerBase
    {
        private readonly ApiDbContext _dbContext;
        private readonly IConfiguration _configuration;

        public UsersController(ApiDbContext dbContext, IConfiguration configuration)
        {
            _dbContext = dbContext;
            _configuration = configuration;
        }

        [HttpGet]
        [Route("GetAll")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> GetAll()
        {
            var users = await _dbContext.Users.ToListAsync();
            return Ok(users);
        }

        [HttpPost]
        [Route("Create")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> Create(Users users)
        {
            if (!Utils.Validators.IsValidEmail(users.Email))
                ModelState.AddModelError(nameof(users.Email), "Invalid Email.");

            if (!ModelState.IsValid)
                return BadRequest(users);

            users.UserName = Utils.Validators.SanitizeInput(users.UserName);
            users.Passwd = Passwd.HashPassword(Passwd.GenerateRandomPassphrase());
            users.IsAdmin = false;

            _dbContext.Users.Add(users);
            await _dbContext.SaveChangesAsync();
            return Ok(users);
        }

        [HttpPost("Authentication")]
        [AllowAnonymous]
        public async Task<IActionResult> Authentication(Users loginUser)
        {
            if (String.IsNullOrEmpty(loginUser.UserName) || String.IsNullOrEmpty(loginUser.Passwd))
                return BadRequest("UserName and Passwd are required");

            var user = await _dbContext.Users.FirstOrDefaultAsync(u => u.UserName == Utils.Validators.SanitizeInput(loginUser.UserName));
            if (user == null || !Passwd.VerifyPassword(loginUser.Passwd, user.Passwd ?? String.Empty))
                return Unauthorized("Invalid credentials");

            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()!),
                new Claim(ClaimTypes.Role, user.IsAdmin == true ? "Admin" : "User")
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddHours(1),
                signingCredentials: creds
            );

            return Ok(new { token = new JwtSecurityTokenHandler().WriteToken(token) });
        }

        [HttpGet("GetOne")]
        [Authorize(Roles = "Admin,User")]
        public async Task<IActionResult> GetOne()
        {
            var userIdClaim = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier);
            if (userIdClaim == null) return Unauthorized();

            int userId = int.Parse(userIdClaim.Value);
            var user = await _dbContext.Users.FindAsync(userId);

            if (user == null) return NotFound();

            return Ok(user);
        }
    }
}