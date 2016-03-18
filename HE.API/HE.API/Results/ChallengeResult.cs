using Microsoft.Owin.Security;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Http;

namespace HE.API.Results
{
    #region ORIGINAL ChallengeResult
    //public class ChallengeResult : IHttpActionResult
    //{
    //    public ChallengeResult(string loginProvider, ApiController controller)
    //    {
    //        LoginProvider = loginProvider;
    //        Request = controller.Request;
    //    }

    //    public string LoginProvider { get; set; }
    //    public HttpRequestMessage Request { get; set; }

    //    public Task<HttpResponseMessage> ExecuteAsync(CancellationToken cancellationToken)
    //    {
    //        Request.GetOwinContext().Authentication.Challenge(LoginProvider);

    //        HttpResponseMessage response = new HttpResponseMessage(HttpStatusCode.Unauthorized);
    //        response.RequestMessage = Request;
    //        return Task.FromResult(response);
    //    }
    //}
    #endregion 


    #region another version of ChallengeResult similar to Client side
    public class ChallengeResult : IHttpActionResult
    {
        private const string XsrfKey = "XsrfId";
        public ChallengeResult(string provider, string redirectUri, ApiController controller) : this(provider, redirectUri, null, controller)
        {
        }

        public ChallengeResult(string loginProvider, string redirectUri, string userId, ApiController controller)
        {
            LoginProvider = loginProvider;
            RedirectUri = redirectUri;
            UserId = userId;
            Request = controller.Request;
        }

        public string LoginProvider { get; set; }
        public HttpRequestMessage Request { get; set; }
        public string RedirectUri { get; set; }
        public string UserId { get; private set; }

        public Task<HttpResponseMessage> ExecuteAsync(CancellationToken cancellationToken)
        {
            var properties = new AuthenticationProperties { RedirectUri = RedirectUri };

            if (UserId != null)
            {
                properties.Dictionary[XsrfKey] = UserId;
            }

            Request.GetOwinContext().Authentication.Challenge(properties, LoginProvider);

            HttpResponseMessage response = new HttpResponseMessage(HttpStatusCode.Unauthorized);
            response.RequestMessage = Request;
            return Task.FromResult(response);
        }
    }
    #endregion
}
