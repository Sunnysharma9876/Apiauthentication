using Apiauthentication.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace Apiauthentication.Controllers
{




    [Route("api/[controller]")]
    [ApiController]
    public class apidataController : ControllerBase
    {

        private readonly RoleManager<IdentityRole> _roleManager;

        public apidataController(RoleManager<IdentityRole> roleManager)
        {
            _roleManager = roleManager;
        }

        [HttpGet]
        [Route("editpage")]
        [Authorize(Roles = "Admin,Employee")]
        public IActionResult edit()
        {
            // You can replace this message with any content you want to return
            string message = "Hello, this is edit page!";
            return Ok(message);
        }

        [HttpGet]
        [Route("delete")]
        [Authorize(Roles ="Admin,Employee")]
        public IActionResult update()
        {
            // You can replace this message with any content you want to return
            string message = "Hello, this is delete page!";
            return Ok(message);
        }

        [HttpGet]
        [Route("everyone")]
        [Authorize(Roles = "Admin,Employee,User")]
        public IActionResult details()
        {
            // You can replace this message with any content you want to return
            string message = "Hello, this is details page!";
            return Ok(message);
        }
        [HttpPost]
        [Route("createRole")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> CreateRole([FromBody] RoleCreateModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            // Check if the role already exists
            if (await _roleManager.RoleExistsAsync(model.Name))
            {
                return Conflict("Role already exists");
            }

            // Create the role
            var role = new IdentityRole { Name = model.Name };
            var result = await _roleManager.CreateAsync(role);

            if (result.Succeeded)
            {
                return Ok("Role created successfully");
            }
            else
            {
                return StatusCode(StatusCodes.Status500InternalServerError, "Failed to create role");
            }
        }
        [HttpGet]
        [Route("getallRoles")]
        [Authorize(Roles = "Admin")]
        public IActionResult GetRoles()
        {
            var roles = _roleManager.Roles;
            return Ok(roles);
        }



    }
}
