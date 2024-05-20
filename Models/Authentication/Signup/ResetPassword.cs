using System.ComponentModel.DataAnnotations;

namespace LearningApp.Models.Authentication.Signup
{
    public class ResetPassword
    {
        [Required]
        public string? Password { get; set; }

        [Compare("Password",ErrorMessage ="Password  should match")]
        public string? ConfirmPassword { get; set; }

        public string? Token { get; set; }

        public string? Email { get; set; }

    }
}
