namespace HE.API.DbContexts
{
    using Microsoft.AspNet.Identity.EntityFramework;
    using System.Data.Entity;
    using HE.API.Models;

    public partial class HE_IdentityDbContext : IdentityDbContext<CustomerProfile>
    {
        public HE_IdentityDbContext()
            : base("name=HE_DbContext")
        {
            //Database.SetInitializer(new HE_DbContextInitializer());
        }

        protected override void OnModelCreating(DbModelBuilder modelBuilder)
        {
            //this is generated by Microsoft EF that specifies the relationships between tables
            //modelBuilder.Entity<CustomerProfile>()
            //    .HasMany(e => e.Roles)
            //    .WithMany(e => e.CustomerProfiles)
            //    .Map(m => m.ToTable("UserRole").MapLeftKey("CustomerProfileID").MapRightKey("RoleId"));


            #region Currently not sure if I need to map ASP Identity entities to my customized tables as I already have tables inheriting from ASP Identity
            base.OnModelCreating(modelBuilder);

            ////Customize IdentityUser for Homemade Eats DB - Define the mappings

            //this is DEFININTELY NEEDED
            modelBuilder.Entity<IdentityUser>().ToTable("CustomerProfile").Property(p => p.Id).HasColumnName("CustomerProfileID");
            modelBuilder.Entity<CustomerProfile>().Property(p => p.LockoutEndDateUtc).HasColumnName("LockoutEndDateUTC");
            modelBuilder.Entity<CustomerProfile>().Property(p => p.Email).HasColumnName("EmailAddress");
            modelBuilder.Entity<CustomerProfile>().Property(p => p.PhoneNumber).HasMaxLength(50);
            modelBuilder.Entity<CustomerProfile>().Property(p => p.EmailConfirmed).HasColumnName("EmailAddressConfirmed");
            modelBuilder.Entity<CustomerProfile>().Property(p => p.TwoFactorEnabled).HasColumnName("TwoFactorAuthEnabled");
            modelBuilder.Entity<CustomerProfile>().Property(p => p.UserName).HasMaxLength(50);

            ////may not have a need for the table IdentityUserRole since Homemade Eats should give the owner full priviledges?
            ////will keep this just in case I find a need for it in the future
            ////Customize table name as well as field UserId to CustomerProfileID all at once
            modelBuilder.Entity<IdentityUserRole>().ToTable("UserRole").Property(p => p.UserId).HasColumnName("CustomerProfileID");

            modelBuilder.Entity<IdentityUserLogin>().ToTable("CustomerLogin").Property(p => p.UserId).HasColumnName("CustomerProfileID");

            ////will keep this just in case I find a need for it in the future
            modelBuilder.Entity<IdentityUserClaim>().ToTable("UserClaim").Property(p => p.Id).HasColumnName("UserClaimID");
            //modelBuilder.Entity<IdentityUserClaim>().Property(p => p.UserId).HasColumnName("CustomerProfileID");

            ////may not have a need for the table IdentityUserRole since Homemade Eats should give the owner full priviledges?
            ////will keep this just in case I find a need for it in the future
            modelBuilder.Entity<IdentityRole>().ToTable("Role").Property(p => p.Id).HasColumnName("RoleID");
            #endregion
        }
        
        public static HE_IdentityDbContext Create()
        {
            return new HE_IdentityDbContext();
        }
    }
}
