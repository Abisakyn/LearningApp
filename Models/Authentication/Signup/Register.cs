using System.ComponentModel.DataAnnotations;

namespace LearningApp.Models.Authentication.Signup
{
    public class Register
    {
        [Required(ErrorMessage ="Username cant be empty")]
        public string? Username { get; set; }

        [Required(ErrorMessage = "Email cant be empty")]
        [EmailAddress(ErrorMessage ="Email address should be in the correct format")]
        public string? Email { get; set; }

        [Required(ErrorMessage = "Password  cant be empty")]
        public string? Password { get; set; }
        
    }
}
