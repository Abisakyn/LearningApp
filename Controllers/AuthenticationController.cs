using LearningApp.Models;
using LearningApp.Models.Authentication.Signup;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace LearningApp.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;


        public AuthenticationController(UserManager<IdentityUser> userManager,SignInManager<IdentityUser> signInManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;

            _configuration = configuration;

        }

        [HttpPost]

        public async Task<IActionResult> Register(Register register , string role)
        {
            if(ModelState.IsValid ==false)
            {
                string errrorMessage = string.Join("", ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage));
                return Problem(errrorMessage);
            }
            //check if user exists in the database
             var userExists  = await _userManager.FindByEmailAsync(register.Email!);
             if(userExists != null)
            { 
                return StatusCode (StatusCodes.Status403Forbidden, new Response
                {
                    Status ="Error",Message = "User already Exists!!"
                });
            }

            //create user in the database
            IdentityUser user = new()
            {
                Email = register.Email,
                UserName = register.Username
            };
            var results = await _userManager.CreateAsync(user,register.Password!);
            if(results.Succeeded)
            {
                return StatusCode(StatusCodes.Status201Created, new Response
                {
                    Status = "Success",
                    Message = "User Created Successfully"
                });
            }
            else
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new Response
                {
                    Status = "Error",
                    Message = "User Failed to create"
                });
            }

            //Asign role

        }
    }
}
