using LearningApp.Models;
using LearningApp.Models.Authentication.Signup;
using LearningApp.Service.Models;
using LearningApp.Service.Services;
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
        private readonly IEmailService _emailService;


        public AuthenticationController(UserManager<IdentityUser> userManager,SignInManager<IdentityUser> signInManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration, IEmailService emailService)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;

            _configuration = configuration;
            _emailService = emailService;

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

            if(await _roleManager.RoleExistsAsync(role))
            {
                var results = await _userManager.CreateAsync(user, register.Password!);

                if (!results.Succeeded)
                {
                    return StatusCode(StatusCodes.Status500InternalServerError, new Response
                    {
                        Status = "Error",
                        Message = "User Failed to create"
                    });
                }

                //add role to the user.....
               await _userManager.AddToRoleAsync(user, role);

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
                    Message = "This role does not exist"
                });
            }

            //Asign role

        }

        [HttpGet]

        public IActionResult TestEmail()
        {
            var message = new Message(new string[] { "abisakyn@gmail.com" }, "Test", "Subscribe to my youtube channel");
            return StatusCode(StatusCodes.Status200OK, new Response
            {
                Status = "Success",
                Message = "Email sent successfully"
            });

        }
    }
}
