

namespace DotNetOpenAuth.ApplicationBlock {
	using System;
	using System.Collections.Generic;
	using System.Diagnostics;
	using System.Globalization;
	using System.IO;
	using System.Linq;
	using System.Net;
	using System.Security.Cryptography.X509Certificates;
	using System.Text;
	using System.Text.RegularExpressions;
	using System.Xml;
	using System.Xml.Linq;
	using DotNetOpenAuth.Messaging;
	using DotNetOpenAuth.OAuth;
	using DotNetOpenAuth.OAuth.ChannelElements;
    using System.Web.Helpers;
    using System.Dynamic;   
    using System.Web.Script.Serialization;
	/// <summary>
	/// A consumer capable of communicating with Xing Data APIs.
	/// </summary>
	public static class XingClient {
		/// <summary>
		/// The Consumer to use for accessing Xing data APIs.
		/// </summary>
		public static readonly ServiceProviderDescription ServiceDescription = new ServiceProviderDescription {
            RequestTokenEndpoint = new MessageReceivingEndpoint("https://api.xing.com/v1/request_token", HttpDeliveryMethods.AuthorizationHeaderRequest | HttpDeliveryMethods.GetRequest),
            UserAuthorizationEndpoint = new MessageReceivingEndpoint("https://api.xing.com/v1/authorize", HttpDeliveryMethods.AuthorizationHeaderRequest | HttpDeliveryMethods.GetRequest),
            AccessTokenEndpoint = new MessageReceivingEndpoint("https://api.xing.com/v1/access_token", HttpDeliveryMethods.AuthorizationHeaderRequest | HttpDeliveryMethods.GetRequest),
			TamperProtectionElements = new ITamperProtectionChannelBindingElement[] { new PlaintextSigningBindingElement() },			
		};
/// <summary>
		/// The URI to get contacts once authorization is granted.
		/// </summary>
        private static readonly MessageReceivingEndpoint GetContactsEndpoint = new MessageReceivingEndpoint("https://api.xing.com/v1/users/me/contacts", HttpDeliveryMethods.GetRequest);

        /// <summary>
        /// The URI to get me one authorization is granted.
        /// </summary>
        private static readonly MessageReceivingEndpoint GetMeEndpoint = new MessageReceivingEndpoint("https://api.xing.com/v1/users/me/", HttpDeliveryMethods.GetRequest);
/// <summary>
		/// The service description to use for accessing xing data APIs using an X509 certificate.
		/// </summary>
		/// <param name="signingCertificate">The signing certificate.</param>
		/// <returns>A service description that can be used to create an instance of
		/// <see cref="DesktopConsumer"/> or <see cref="WebConsumer"/>. </returns>
		public static ServiceProviderDescription CreateRsaSha1ServiceDescription(X509Certificate2 signingCertificate) {
			if (signingCertificate == null) {
				throw new ArgumentNullException("signingCertificate");
			}

			return new ServiceProviderDescription {
                RequestTokenEndpoint = new MessageReceivingEndpoint("https://api.xing.com/v1/request_token", HttpDeliveryMethods.AuthorizationHeaderRequest | HttpDeliveryMethods.GetRequest),
                UserAuthorizationEndpoint = new MessageReceivingEndpoint("https://api.xing.com/v1/authorize", HttpDeliveryMethods.AuthorizationHeaderRequest | HttpDeliveryMethods.GetRequest),
                AccessTokenEndpoint = new MessageReceivingEndpoint("https://api.xing.com/v1/access_token", HttpDeliveryMethods.AuthorizationHeaderRequest | HttpDeliveryMethods.GetRequest),
                TamperProtectionElements = new ITamperProtectionChannelBindingElement[] { new RsaSha1ConsumerSigningBindingElement(signingCertificate) },
			};
		}

		/// <summary>
		/// Requests authorization from Google to access data from a set of Google applications.
		/// </summary>
		/// <param name="consumer">The Google consumer previously constructed using <see cref="CreateWebConsumer"/> or <see cref="CreateDesktopConsumer"/>.</param>
		/// <param name="requestedAccessScope">The requested access scope.</param>
		public static void RequestAuthorization(WebConsumer consumer, Applications requestedAccessScope) {
			if (consumer == null) {
				throw new ArgumentNullException("consumer");
			}

			var extraParameters = new Dictionary<string, string> {
				{ "scope", GetScopeUri(requestedAccessScope) },
			};
			Uri callback = Util.GetCallbackUrlFromContext();
			var request = consumer.PrepareRequestUserAuthorization(callback, extraParameters, null);
			consumer.Channel.Send(request);
		}

		/// <summary>
		/// Requests authorization from Google to access data from a set of Google applications.
		/// </summary>
		/// <param name="consumer">The Google consumer previously constructed using <see cref="CreateWebConsumer"/> or <see cref="CreateDesktopConsumer"/>.</param>
		/// <param name="requestedAccessScope">The requested access scope.</param>
		/// <param name="requestToken">The unauthorized request token assigned by Google.</param>
		/// <returns>The request token</returns>
		public static Uri RequestAuthorization(DesktopConsumer consumer, Applications requestedAccessScope, out string requestToken) {
			if (consumer == null) {
				throw new ArgumentNullException("consumer");
			}

			var extraParameters = new Dictionary<string, string> {
				{ "scope", GetScopeUri(requestedAccessScope) },
			};

			return consumer.RequestUserAuthorization(extraParameters, null, out requestToken);
		}

		/// <summary>
		/// Gets the Xing ress book's contents.
		/// </summary>
		/// <param name="consumer">The Google consumer.</param>
		/// <param name="accessToken">The access token previously retrieved.</param>
		/// <param name="maxResults">The maximum number of entries to return. If you want to receive all of the contacts, rather than only the default maximum, you can specify a very large number here.</param>
		/// <param name="startIndex">The 1-based index of the first result to be retrieved (for paging).</param>
		/// <returns>json eturns>
         public static Object GetMyCotacts(ConsumerBase consumer, string accessToken, string felds, int maxResults/* = 25*/, int startIndex/* = 1*/)
        {
            if (consumer == null)
            {
                throw new ArgumentNullException("consumer");
            }
            var extraData = new Dictionary<string, string>() {
				{ "offset", startIndex.ToString(CultureInfo.InvariantCulture) },
				{ "limit", maxResults.ToString(CultureInfo.InvariantCulture) },
                { "user_fields",felds },
			};
            var request = consumer.PrepareAuthorizedRequest(GetContactsEndpoint, accessToken, extraData);
            
            // Enable gzip compression.  Google only compresses the response for recognized user agent headers. - Mike Lim
            //request.AutomaticDecompression = DecompressionMethods.GZip;
            request.UserAgent = "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.151 Safari/534.16";
            var response = consumer.Channel.WebRequestHandler.GetResponse(request);
            string body = response.GetResponseReader().ReadToEnd();
            var serializer = new JavaScriptSerializer();
            serializer.RegisterConverters(new[] { new DynamicJsonConverter() });
            dynamic obj = serializer.Deserialize(body, typeof(object));
            return obj.contacts[0];
        }
		
        /// <summary>
        /// Gets Me at xing.
        /// </summary>
        /// <param name="consumer">The Xing consumer.</param>
        /// <param name="accessToken">The access token previously retrieved.</param>
        /// <param name="maxResults">The maximum number of entries to return. If you want to receive all of the contacts, rather than only the default maximum, you can specify a very large number here.</param>
        /// <param name="startIndex">The 1-based index of the first result to be retrieved (for paging).</param>
        /// <returns>An dynamic ent returned by Xing.</returns>
        public static Object GetMe(ConsumerBase consumer, string accessToken)
        {
            if (consumer == null)
            {
                throw new ArgumentNullException("consumer");
            }           
            var request = consumer.PrepareAuthorizedRequest(GetMeEndpoint, accessToken);
            // Enable gzip compression.  Google only compresses the response for recognized user agent headers. - Mike Lim
            //request.AutomaticDecompression = DecompressionMethods.GZip;
            request.UserAgent = "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.151 Safari/534.16";
            var response = consumer.Channel.WebRequestHandler.GetResponse(request);
            string body = response.GetResponseReader().ReadToEnd();
            var serializer = new JavaScriptSerializer();
            serializer.RegisterConverters(new[] { new DynamicJsonConverter() });
            dynamic obj = serializer.Deserialize(body, typeof(object));
            return obj.users[0];
        }
/// <summary>
		/// Gets the scope URI in Google's format.
		/// </summary>
		/// <param name="scope">The scope, which may include one or several Google applications.</param>
		/// <returns>A space-delimited list of URIs for the requested Google applications.</returns>
		public static string GetScopeUri(Applications scope) {
			return string.Join(" ", Util.GetIndividualFlags(scope).Select(app => DataScopeUris[(Applications)app]).ToArray());
		}
	}
}
