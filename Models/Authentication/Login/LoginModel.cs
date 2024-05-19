using System.ComponentModel.DataAnnotations;

namespace LearningApp.Models.Authentication.Login
{
    public class LoginModel
    {
        [Required(ErrorMessage ="Cant be empty")]
        public string? Username { get; set; }

        [Required(ErrorMessage = "Cant be empty")]
        public string? Password { get; set; }
    }
}
