using Microsoft.EntityFrameworkCore;
using SafeVaultApi.Api.Models;

namespace SafeVaultApi.Api.Data
{
    public class ApiDbContext : DbContext
    {
        public ApiDbContext(DbContextOptions<ApiDbContext> options) : base(options) { }

        public DbSet<Users> Users { get; set; }
    }
}