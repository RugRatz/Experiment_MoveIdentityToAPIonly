using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;

namespace HE.API.Controllers
{
    [Authorize]
    public class NewController : ApiController
    {
        public IHttpActionResult Get()
        {
            return Ok("Hi Lisa");
        }
    }
}
