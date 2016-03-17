using Microsoft.Owin.Security;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Http;

namespace HE.API.Results
{
    public class ChallengeResult : IHttpActionResult
    {
        private const string XsrfKey = "XsrfId";

        public ChallengeResult(string provider, string redirectUri, HttpRequestMessage request)
          : this(provider, redirectUri, null, request)
        {
        }

        public ChallengeResult(string provider, string redirectUri, string userId, HttpRequestMessage request)
        {
            LoginProvider = provider;
            RedirectUri = redirectUri;
            UserId = userId;
            Request = request;
        }

        public string LoginProvider { get; private set; }

        public string RedirectUri { get; private set; }

        public string UserId { get; private set; }

        public HttpRequestMessage Request { get; private set; }

        public Task<HttpResponseMessage> ExecuteAsync(CancellationToken cancellationToken)
        {
            var properties = new AuthenticationProperties() { RedirectUri = this.RedirectUri };
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
}
