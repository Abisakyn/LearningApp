using LearningApp.Data.Models;
using LearningApp.Models;
//using LearningApp.Models.Authentication.Login;
//using LearningApp.Models.Authentication.Signup;
using LearningApp.Service.Models;
using LearningApp.Service.Models.Authentication.Login;
using LearningApp.Service.Models.Authentication.Signup;
using LearningApp.Service.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace LearningApp.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly IEmailService _emailService;
        private readonly IUserManagement _user;

        public AuthenticationController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration, IEmailService emailService, IUserManagement user)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
            _configuration = configuration;
            _emailService = emailService;
            _user = user;
        }

        [HttpPost]
        public async Task<IActionResult> Register(Register register)
        {
            var tokenResponse = await _user.CreateUserWithTokenAsyc(register);

            if (tokenResponse.IsSuccess)
            {
               var roleAssignmentResponse= await _user.AssignRoleAsync(register.Roles!, tokenResponse.Response!.User);

                // Check if the role assignment was successful or partially successful
                if (!roleAssignmentResponse.IsSuccess)
                {
                    // If the role assignment failed, delete the user
                    await _userManager.DeleteAsync(tokenResponse.Response.User);

                    // Return an error response with the message from the role assignment
                    return StatusCode(roleAssignmentResponse.StatusCode,
                        new Response { Status = "Error", Message = roleAssignmentResponse.Message });
                }
                var confirmationLink = Url.Action(nameof(ConfirmEmail), "Authentication", new { tokenResponse.Response.Token, email = register.Email }, Request.Scheme);
                var message = new Message(new string[] { register.Email! }, "Confirmation Email Link", confirmationLink!);
                _emailService.SendEmail(message);

                return StatusCode(StatusCodes.Status200OK,
                new Response { Status = "Success", Message = "Email sent for confirmation" ,IsSuccess=true});
            }
            return StatusCode(StatusCodes.Status500InternalServerError,
            new Response {  Message = tokenResponse.Message ,IsSuccess=false});

        }

        [HttpGet("ConfirmEmail")]
        public async Task<IActionResult> ConfirmEmail(string token, string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user != null)
            {
                var result = await _userManager.ConfirmEmailAsync(user, token);
                if (result.Succeeded)
                {
                    return StatusCode(StatusCodes.Status200OK,
                        new Response { Status = "Success", Message = "Email verified successfully" });
                }
            }
            return StatusCode(StatusCodes.Status500InternalServerError,
                new Response { Status = "Error", Message = "This user does not exist" });
        }

        [HttpPost]
        [Route("Login")]
        public async Task<IActionResult>Login(LoginModel loginModel)
        {


                var loginOtpResponse = await _user.GetOtpByLoginAsync(loginModel);

                var user = loginOtpResponse.Response!.User;
            if (user != null)
            {

                if (user.TwoFactorEnabled)
                {
                    var token = loginOtpResponse.Response.Token;

                    var message = new Message(new string[] { user.Email! }, "OTP Confirmation", token!);

                    _emailService.SendEmail(message);

                    return StatusCode(StatusCodes.Status200OK, new Response
                    {

                        Status = "Success",
                        Message = $"We have sent an OTP to ypu email: {user.Email}."
                    });

                }

                // Generate and return the JWT token

                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName!),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                };

                // Retrieve the user's roles and add them to the claims list
                var userRoles = await _userManager.GetRolesAsync(user);
                foreach (var role in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, role));
                }

                // Generate the JWT token with the claims and refresh token
                var jwtToken = _user.GetToken(authClaims);
                var refreshToken = GenerateRefreshToken();
                _ = int.TryParse(_configuration["JWT:RefreshTokenValidity"], out int refreshTokenValidity);
                var refreshTokenExpiry = DateTime.UtcNow.AddDays(refreshTokenValidity);

                // Attach the token to user
                user.RefreshToken = refreshToken;
                user.RefreshTokenExpiry = refreshTokenExpiry;

                // Update
                await _userManager.UpdateAsync(user);

                // Return the JWT token and its expiration time
                return Ok(new
                {
                    AccessToken = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                    AccessTokenExpiration = jwtToken.ValidTo,
                    RefreshToken = refreshToken,
                    RefreshTokenExpiration = refreshTokenExpiry
                });
            }

            return Unauthorized();
        }

        [HttpPost]
        [Route("Login-2FA")]
        public async Task<IActionResult> LoginwithOTP(string code,string username)
        {
            var signIn = await _signInManager.TwoFactorSignInAsync("Email", code, false, false);
              if (signIn.Succeeded)
              {
                var user = await _userManager.FindByNameAsync(username);

                //checking the password
                if (user != null)
                {
                    //create claim list
                    var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName!),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                };

                    //add role to the list
                    var userRoles = await _userManager.GetRolesAsync(user);
                    foreach (var role in userRoles)
                    {
                        authClaims.Add(new Claim(ClaimTypes.Role, role));
                    }

                    if (user.TwoFactorEnabled)
                    {

                        var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");

                        var message = new Message(new string[] { user.Email! }, "OTP Confirmation", token!);

                        _emailService.SendEmail(message);

                        //generate the token with the claims..
                        var jwtToken = GetToken(authClaims);
                        var refreshToken = GenerateRefreshToken();
                        _ = int.TryParse(_configuration["JWT:RefreshTokenValidity"], out int refreshTokenValidity);
                        var refreshTokenExpiry = DateTime.UtcNow.AddDays(refreshTokenValidity);
                        // Attach the token to user
                        user.RefreshToken = refreshToken;
                        user.RefreshTokenExpiry = refreshTokenExpiry;

                        //returning the token
                        return Ok(new
                        {
                            token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                            expiration = jwtToken.ValidTo,
                            RefreshToken = refreshToken,
                            RefreshTokenExpiration = refreshTokenExpiry
                        });

                    }


                }
                return StatusCode(StatusCodes.Status404NotFound, new Response
                {

                    Status = "Error",
                    Message = $"Invalid code"
                });

              }

            return StatusCode(StatusCodes.Status500InternalServerError, new Response
            {

                Status = "Error",
                Message = $"Internal Server Error"
            });


        }

        [HttpPost]
        [AllowAnonymous]
        [Route("Forgot-Password")]
        public async Task<IActionResult> ForgotPassword([Required] string email)
        {
            if (string.IsNullOrEmpty(email))
            {
                return StatusCode(StatusCodes.Status400BadRequest, new Response
                {
                    Status = "Error",
                    Message = "Email is required."
                });
            }

            var user = await _userManager.FindByEmailAsync(email);

            if (user == null)
            {
                return StatusCode(StatusCodes.Status400BadRequest, new Response
                {
                    Status = "Error",
                    Message = "User with the specified email does not exist."
                });
            }

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var forgotPasswordLink = Url.Action(nameof(ResetPassword), "Authentication", new { token, email = user.Email }, Request.Scheme);

            if (forgotPasswordLink == null)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new Response
                {
                    Status = "Error",
                    Message = "Failed to generate the password reset link."
                });
            }

            var message = new Message(new string[] { user.Email! }, "Forgot Password Link", forgotPasswordLink);
            _emailService.SendEmail(message);

            return StatusCode(StatusCodes.Status200OK, new Response
            {
                Status = "Success",
                Message = $"Password change request sent to email: {user.Email}. Please click the link below to verify."
            });
        }

        [HttpGet("Reset-Password")]
        [AllowAnonymous]
        public async Task<IActionResult> ResetPassword(string token, string email)
        {
            var model = new ResetPassword { Token = token, Email = email };
            return Ok(new
            {
                model
            });

        }


        [HttpPost]
        [AllowAnonymous]
        [Route("Reset-Password")]
        public async Task<IActionResult> ResetPasswod(ResetPassword resetPassword)
        {

            var user = await _userManager.FindByEmailAsync(resetPassword.Email!);

            if (user != null)
            {
                var resetPassResult = await _userManager.ResetPasswordAsync(user, resetPassword.Token!, resetPassword.Email!);

                if (!resetPassResult.Succeeded)
                {
                    foreach (var error in resetPassResult.Errors)
                    {
                        ModelState.AddModelError(error.Code, error.Description);

                    }
                    //return Ok(ModelState);
                }
                return StatusCode(StatusCodes.Status200OK, new Response
                {
                    Status = "Success",
                    Message = "Password has been changed successfully."
                });

            }
            return StatusCode(StatusCodes.Status400BadRequest, new Response
            {
                Status = "Error",
                Message = "User with the specified email does not exist."
            });


        }


        


        private JwtSecurityToken GetToken(List<Claim> authClaim )
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!));
            _ = int.TryParse(_configuration["Jwt:EXPIRATION_MINUTES"], out int EXPIRATION_MINUTES);

            var token = new JwtSecurityToken(
                _configuration["Jwt:Issuer"],
                _configuration["Jwt:Audience"],
                claims:authClaim,
                expires: DateTime.Now.AddMinutes(EXPIRATION_MINUTES),
                signingCredentials: new SigningCredentials(authSigningKey,SecurityAlgorithms.HmacSha256)
          );
            return token;
        }


        private string GenerateRefreshToken()
        {
            var randomNumber = new Byte[64];
            var range = RandomNumberGenerator.Create();
            range.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }
    }
}
