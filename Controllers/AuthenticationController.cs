using Apiauthentication.Models;
using Apiauthentication.Models.Authentication.Login;
using Apiauthentication.Models.Authentication.SignUp;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Apiauthentication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        public AuthenticationController(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;



        }
        [HttpPost]
        [Route("Register")]
        public async Task<IActionResult> Register([FromBody] RegisterUser model)
        {
            var userExist = await _userManager.FindByNameAsync(model.Username);
            if (userExist != null)
            {
                return StatusCode(StatusCodes.Status409Conflict, new Response { Status = "Error", Message = "User already exists" });
            }

            ApplicationUser user = new ApplicationUser()
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.Username,
            };

            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User creation failed" });
            }

            // Assuming "User" is a default role you might want everyone to have
            if (!await _roleManager.RoleExistsAsync(UserRoles.User))
            {
                await _roleManager.CreateAsync(new IdentityRole(UserRoles.User));
            }

            var roleResult = await _userManager.AddToRoleAsync(user, UserRoles.User);
            if (!roleResult.Succeeded)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "Failed to assign role" });
            }

            return Ok(new Response { Status = "Success", Message = "User created successfully." });



        }
        [HttpPost]
        [Route("Login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            var user = await _userManager.FindByNameAsync(model.UserName);
            if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
            {
                var userRoles = await _userManager.GetRolesAsync(user);
                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name,user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString()),
                };
                foreach (var userRole in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, userRole));
                }
                var authSigninKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));

                var token = new JwtSecurityToken(
                    issuer: _configuration["JWT:ValidIssuer"],
                    audience: _configuration["JWT:ValidAudience"],
                    expires: DateTime.Now.AddHours(1),
                    claims: authClaims,
                    signingCredentials: new SigningCredentials(authSigninKey, SecurityAlgorithms.HmacSha256Signature)
                    );
                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(token),

                });
            }

            return Unauthorized("Wrong Credentials.");
        }
        //    [Authorize(Roles = "Admin")]
        //    [HttpPost]
        //    [Route("Register-admin")]
        //    public async Task<IActionResult> RegisterAdmin([FromBody] RegisterUser model)
        //    {
        //        var userExist = await _userManager.FindByNameAsync(model.Username);
        //        if (userExist != null)
        //        {
        //            return StatusCode(StatusCodes.Status409Conflict, new Response { Status = "Error", Message = "User already exists" });
        //        }

        //        ApplicationUser user = new ApplicationUser()
        //        {
        //            Email = model.Email,
        //            SecurityStamp = Guid.NewGuid().ToString(),
        //            UserName = model.Username,
        //        };

        //        var result = await _userManager.CreateAsync(user, model.Password);
        //        if (!result.Succeeded)
        //        {
        //            return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User creation failed" });
        //        }

        //        if (!await _roleManager.RoleExistsAsync(UserRoles.Admin))
        //        {
        //            await _roleManager.CreateAsync(new IdentityRole(UserRoles.Admin));
        //        }

        //        var roleResult = await _userManager.AddToRoleAsync(user, UserRoles.Admin);
        //        if (!roleResult.Succeeded)
        //        {
        //            return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "Failed to assign role" });
        //        }

        //        return Ok(new Response { Status = "Success", Message = "Admin created successfully." });

        //    }



        //    [Authorize(Roles ="Admin")]
        //[HttpPost]
        //[Route("Register-employee")]
        //public async Task<IActionResult> RegisterEmployee([FromBody] RegisterUser model)
        //{
        //    var userExist = await _userManager.FindByNameAsync(model.Username);
        //    if (userExist != null)
        //    {
        //        return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User already exists" });
        //    }

        //    // Create a new ApplicationUser object
        //    ApplicationUser user = new ApplicationUser()
        //    {
        //        Email = model.Email,
        //        SecurityStamp = Guid.NewGuid().ToString(),
        //        UserName = model.Username,
        //    };

        //    // Attempt to create the user with the specified password
        //    var result = await _userManager.CreateAsync(user, model.Password);
        //    if (!result.Succeeded)
        //    {
        //        return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "Some error occurred" });
        //    }

        //    // Check if the Employee role exists, create it if not
        //    if (!await _roleManager.RoleExistsAsync(UserRoles.Employee))
        //    {
        //        await _roleManager.CreateAsync(new IdentityRole(UserRoles.Employee));
        //    }

        //    // Assign the user to the Employee role
        //    var roleResult = await _userManager.AddToRoleAsync(user, UserRoles.Employee);
        //    if (!roleResult.Succeeded)
        //    {
        //        return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "Failed to assign role" });
        //    }

        //    // If everything is successful
        //    return Ok(new Response { Status = "Success", Message = "Employee created successfully." });
        //}
        [HttpPost]
        //[Authorize(Roles = "Admin")]

        [Route("updateRoles")]
        
        public async Task<IActionResult> AddUserRoles([FromBody] UpdateUserRoleModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            // Find the user by username
            var user = await _userManager.FindByNameAsync(model.Username);
            if (user == null)
            {
                return NotFound("User not found");
            }

            // Split the roles string into an array of role names
            var roleNames = model.Roles.Split(',');

            foreach (var roleName in roleNames)
            {
                // Check if the role exists
                var roleExists = await _roleManager.RoleExistsAsync(roleName.Trim());
                if (!roleExists)
                {
                    return BadRequest($"Role '{roleName}' does not exist");
                }
            }

            // Assign the user to the new roles
            var result = await _userManager.AddToRolesAsync(user, roleNames);
            if (result.Succeeded)
            {
                return Ok("User roles updated successfully");
            }
            return StatusCode(500, "Failed to update user roles");

        }

        [Authorize(Roles = "Admin")]
        [HttpPut("removeRoles")]

        public async Task<IActionResult> RemoveUserRoles([FromBody] RemoveUserRolesModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            // Find the user by username
            var user = await _userManager.FindByNameAsync(model.Username);
            if (user == null)
            {
                return NotFound("User not found");
            }

            // Split the roles string into an array of role names
            var roleNames = model.Roles.Split(',');

            // Remove the user from the specified roles
            var result = await _userManager.RemoveFromRolesAsync(user, roleNames);
            if (result.Succeeded)
            {
                return Ok("User roles removed successfully");
            }

            return StatusCode(500, "Failed to remove user roles");
        }

        [Authorize(Roles = "Admin")]
        [HttpPost("getUserRoles")]
        public async Task<IActionResult> GetUserRoles([FromBody] GetUserRolesModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            // Find the user by username
            var user = await _userManager.FindByNameAsync(model.Username);
            if (user == null)
            {
                return NotFound("User not found");
            }

            // Get the roles of the user
            var roles = await _userManager.GetRolesAsync(user);

            return Ok(roles);
        }



    }

}



