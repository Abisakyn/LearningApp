using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace LearningApp.Models
{
    public class ApplicationDbContext : IdentityDbContext <IdentityUser>
    {
        public ApplicationDbContext (DbContextOptions<ApplicationDbContext> options) : base(options) 
        { 

        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
            seedRoles(builder);
        }

        private static void seedRoles (ModelBuilder builder)
        {
            builder.Entity<IdentityRole>().HasData
                (
                new IdentityRole() { Name = "Admin", ConcurrencyStamp = "1", NormalizedName = "Admin" },
                new IdentityRole() { Name = "User", ConcurrencyStamp = "2", NormalizedName = "User" },
                new IdentityRole() { Name = "Surveyor", ConcurrencyStamp = "3", NormalizedName = "Surveyor" },
                new IdentityRole() { Name = "Editor", ConcurrencyStamp = "4", NormalizedName = "Editor" }
                );
        }
    }
}
