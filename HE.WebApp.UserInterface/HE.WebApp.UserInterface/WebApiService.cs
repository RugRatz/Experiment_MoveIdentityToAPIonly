using System.Collections.Generic;
using System.Configuration;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using Microsoft.Ajax.Utilities;
using Newtonsoft.Json;
using System;
using HE.WebApp.UserInterface.Models;

namespace HE.WebApp.UserInterface
{
    public class WebApiService
    {
        private WebApiService(string baseUri)
        {
            BaseUri = baseUri;
        }

        private static WebApiService _instance;

        public static WebApiService Instance
        {
            get { return _instance ?? (_instance = new WebApiService(ConfigurationManager.AppSettings["HE_ApiURI"])); }
        }

        public string BaseUri { get; private set; }

        public async Task<T> AuthenticateAndGetTokenAsync<T>(string userName, string password)
        {
            using (var client = new HttpClient())
            {
                var result = await client.PostAsync(BuildActionUri("/Token"), new FormUrlEncodedContent(new List<KeyValuePair<string, string>>
                {
                    new KeyValuePair<string, string>("grant_type", "password"),
                    new KeyValuePair<string, string>("userName", userName),
                    new KeyValuePair<string, string>("password", password)
                }));

                string json = await result.Content.ReadAsStringAsync();
                if (result.IsSuccessStatusCode)
                {
                    return JsonConvert.DeserializeObject<T>(json);
                }
                return JsonConvert.DeserializeObject<T>(json);
                //throw new Exception(result.StatusCode + " " + JsonConvert.DeserializeObject<T>(json));
            }
        }

        public async Task<T> GetAsync<T>(string action, string authToken = null)
        {
            using (var client = new HttpClient())
            {
                if (!authToken.IsNullOrWhiteSpace())
                {
                    //Add the authorization header
                    client.DefaultRequestHeaders.Authorization = AuthenticationHeaderValue.Parse("Bearer " + authToken);
                }

                var result = await client.GetAsync(BuildActionUri(action));

                string json = await result.Content.ReadAsStringAsync();
                if (result.IsSuccessStatusCode)
                {
                    return JsonConvert.DeserializeObject<T>(json);
                }

                return JsonConvert.DeserializeObject<T>(json);
            }
        }

        //public async Task PutAsync<T>(string action, T data, string authToken = null)
        //{
        //    using (var client = new HttpClient())
        //    {
        //        if (!authToken.IsNullOrWhiteSpace())
        //        {
        //            //Add the authorization header
        //            client.DefaultRequestHeaders.Authorization = AuthenticationHeaderValue.Parse("Bearer " + authToken);
        //        }

        //        var result = await client.PutAsJsonAsync(BuildActionUri(action), data);
        //        if (result.IsSuccessStatusCode)
        //        {
        //            return;
        //        }

        //        string json = await result.Content.ReadAsStringAsync();
        //        throw new ApiException(result.StatusCode, json);
        //    }
        //}

        public async Task PostAsync<T>(string action, T data, string authToken = null)
        {
            using (var client = new HttpClient())
            {
                if (!authToken.IsNullOrWhiteSpace())
                {
                    //Add the authorization header
                    client.DefaultRequestHeaders.Authorization = AuthenticationHeaderValue.Parse("Bearer " + authToken);
                }

                var result = await client.PostAsJsonAsync(BuildActionUri(action), data);

                string json = await result.Content.ReadAsStringAsync();

                if (result.IsSuccessStatusCode)
                {
                    return; //JsonConvert.DeserializeObject<T>(json);
                }
                throw new Exception(result.StatusCode + " " + json);
            }
        }

        /// <summary>
        /// Make an async call to api/Account/ExternalLogins?returnUrl=%2F&generateState=true
        /// This method will return a list of external logins that are available
        /// If there are no external logins available, NULL will be returned
        /// </summary>
        /// <param name="action"></param>
        /// <returns></returns>
        public async Task<List<ExternalLoginViewModel>> GetExternalLoginsAvailableAsync(string action)
        {
            using (var client = new HttpClient())
            {
                HttpResponseMessage response = await client.GetAsync(BuildActionUri(action));

                string json = await response.Content.ReadAsStringAsync();
                
                if (response.IsSuccessStatusCode)
                {
                    List<ExternalLoginViewModel> externalLogins = await response.Content.ReadAsAsync<List<ExternalLoginViewModel>>();
                    return externalLogins;
                }

                return null;
            }
        }

        public string BuildActionUri(string action)
        {
            return BaseUri + action;
        }
    }
}