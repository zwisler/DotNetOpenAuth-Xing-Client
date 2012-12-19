//-----------------------------------------------------------------------
// <copyright file="XingClient  company="Citaurus">
//     Copyright (c) Citaurus Foundation. All rights reserved.
// </copyright>
//-----------------------------------------------------------------------

namespace DotNetOpenAuth.ApplicationBlock
{
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
    public static class XingClient
    {
        /// <summary>
        /// The Consumer to use for accessing Xing data APIs.
        /// </summary>
        public static readonly ServiceProviderDescription ServiceDescription = new ServiceProviderDescription
        {
            RequestTokenEndpoint = new MessageReceivingEndpoint("https://api.xing.com/v1/request_token", HttpDeliveryMethods.AuthorizationHeaderRequest | HttpDeliveryMethods.GetRequest),
            UserAuthorizationEndpoint = new MessageReceivingEndpoint("https://api.xing.com/v1/authorize", HttpDeliveryMethods.AuthorizationHeaderRequest | HttpDeliveryMethods.GetRequest),
            AccessTokenEndpoint = new MessageReceivingEndpoint("https://api.xing.com/v1/access_token", HttpDeliveryMethods.AuthorizationHeaderRequest | HttpDeliveryMethods.GetRequest),
            TamperProtectionElements = new ITamperProtectionChannelBindingElement[] { new PlaintextSigningBindingElement() },
        };

        /// <summary>
        /// A mapping between Google's applications and their URI scope values.
        /// </summary>
        private static readonly Dictionary<Applications, string> DataScopeUris = new Dictionary<Applications, string> {
			{ Applications.Contacts, "https://api.xing.com/v1/users/me/contacts" },
            { Applications.me, "https://api.xing.com/v1/users/me" },
			{ Applications.users, "https://api.xing.com/v1/users/" },
			
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
        /// The many specific authorization scopes Google offers.
        /// </summary>
        [Flags]
        public enum Applications : long
        {
            /// <summary>
            /// The Gmail address book.
            /// </summary>
            Contacts = 0x1,

            /// <summary>
            /// Abot me
            /// </summary>
            me = 0x4000,

            /// <summary>
            /// users
            /// </summary>
            users = 0x8000,
        }

        /// <summary>
        /// The service description to use for accessing Google data APIs using an X509 certificate.
        /// </summary>
        /// <param name="signingCertificate">The signing certificate.</param>
        /// <returns>A service description that can be used to create an instance of
        /// <see cref="DesktopConsumer"/> or <see cref="WebConsumer"/>. </returns>
        public static ServiceProviderDescription CreateRsaSha1ServiceDescription(X509Certificate2 signingCertificate)
        {
            if (signingCertificate == null)
            {
                throw new ArgumentNullException("signingCertificate");
            }

            return new ServiceProviderDescription
            {
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
        public static void RequestAuthorization(WebConsumer consumer, Applications requestedAccessScope)
        {
            if (consumer == null)
            {
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
        public static Uri RequestAuthorization(DesktopConsumer consumer, Applications requestedAccessScope, out string requestToken)
        {
            if (consumer == null)
            {
                throw new ArgumentNullException("consumer");
            }

            var extraParameters = new Dictionary<string, string> {
				{ "scope", GetScopeUri(requestedAccessScope) },
			};

            return consumer.RequestUserAuthorization(extraParameters, null, out requestToken);
        }

        /// <summary>
        /// Gets the Xing adress book's contents.
        /// </summary>
        /// <param name="consumer">The Xing consumer.</param>
        /// <param name="accessToken">The access token previously retrieved.</param>
        /// <param name="maxResults">The maximum number of entries to return. If you want to receive all of the contacts, rather than only the default maximum, you can specify a very large number here.</param>
        /// <param name="startIndex">The 1-based index of the first result to be retrieved (for paging).</param>
        /// <param name="field">user_fields of info on https://dev.xing.com/docs/get/users/:id </param>
        /// <returns>An dynamic Object returned by Xing.</returns>
        public static Object GetMyCotacts(ConsumerBase consumer, string accessToken, string field, int maxResults/* = 25*/, int startIndex/* = 1*/)
        {
            if (consumer == null)
            {
                throw new ArgumentNullException("consumer");
            }
            var extraData = new Dictionary<string, string>() {
				{ "offset", startIndex.ToString(CultureInfo.InvariantCulture) },
				{ "limit", maxResults.ToString(CultureInfo.InvariantCulture) },
                { "user_fields",field },
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
            return obj;
        }

        /// <summary>
        /// Gets a Xing user contents.
        /// </summary>
        /// <param name="consumer">The Xing consumer.</param>
        /// <param name="accessToken">The access token previously retrieved.</param>
        /// <param name="id">ID(s) of requested user(s). </param>
        /// <param name="field">user_fields info on https://dev.xing.com/docs/get/users/:id </param>
        /// <returns>An dynamic Object returned by Xing.</returns>
        public static Object GetUser(ConsumerBase consumer, string accessToken, string id, string field)
        {
            if (consumer == null)
            {
                throw new ArgumentNullException("consumer");
            }
            MessageReceivingEndpoint Endpoint = new MessageReceivingEndpoint("https://api.xing.com/v1/users/" + id, HttpDeliveryMethods.GetRequest);
            var extraData = new Dictionary<string, string>()
             {
             { "fields",field },
             };

            var request = consumer.PrepareAuthorizedRequest(Endpoint, accessToken, extraData);

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
        /// Gets a Xing user contents.
        /// </summary>
        /// <param name="consumer">The Xing consumer.</param>
        /// <param name="accessToken">The access token previously retrieved.</param>
        /// <param name="id">ID(s) of requested user(s). </param>        
        /// <returns>An dynamic Object returned by Xing.</returns>
        public static Object GetUser(ConsumerBase consumer, string accessToken, string id)
        {
            if (consumer == null)
            {
                throw new ArgumentNullException("consumer");
            }
            MessageReceivingEndpoint Endpoint = new MessageReceivingEndpoint("https://api.xing.com/v1/users/" + id, HttpDeliveryMethods.GetRequest);
            

            var request = consumer.PrepareAuthorizedRequest(Endpoint, accessToken);

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
        /// Gets Me at xing.
        /// </summary>
        /// <param name="consumer">The Xing consumer.</param>
        /// <param name="accessToken">The access token previously retrieved.</param>
        /// <param name="maxResults">The maximum number of entries to return. If you want to receive all of the contacts, rather than only the default maximum, you can specify a very large number here.</param>
        /// <param name="startIndex">The 1-based index of the first result to be retrieved (for paging).</param>
        /// <returns>An dynamic Object returned by Xing.</returns>
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


        public static void PostBlogEntry(ConsumerBase consumer, string accessToken, string blogUrl, string title, XElement body)
        {
            string feedUrl;
            var getBlogHome = WebRequest.Create(blogUrl);
            using (var blogHomeResponse = getBlogHome.GetResponse())
            {
                using (StreamReader sr = new StreamReader(blogHomeResponse.GetResponseStream()))
                {
                    string homePageHtml = sr.ReadToEnd();
                    Match m = Regex.Match(homePageHtml, @"http://www.blogger.com/feeds/\d+/posts/default");
                    Debug.Assert(m.Success, "Posting operation failed.");
                    feedUrl = m.Value;
                }
            }
            const string Atom = "http://www.w3.org/2005/Atom";
            XElement entry = new XElement(
                XName.Get("entry", Atom),
                new XElement(XName.Get("title", Atom), new XAttribute("type", "text"), title),
                new XElement(XName.Get("content", Atom), new XAttribute("type", "xhtml"), body),
                new XElement(XName.Get("category", Atom), new XAttribute("scheme", "http://www.blogger.com/atom/ns#"), new XAttribute("term", "oauthdemo")));

            MemoryStream ms = new MemoryStream();
            XmlWriterSettings xws = new XmlWriterSettings()
            {
                Encoding = Encoding.UTF8,
            };
            XmlWriter xw = XmlWriter.Create(ms, xws);
            entry.WriteTo(xw);
            xw.Flush();

            WebRequest request = consumer.PrepareAuthorizedRequest(new MessageReceivingEndpoint(feedUrl, HttpDeliveryMethods.PostRequest | HttpDeliveryMethods.AuthorizationHeaderRequest), accessToken);
            request.ContentType = "application/atom+xml";
            request.Method = "POST";
            request.ContentLength = ms.Length;
            ms.Seek(0, SeekOrigin.Begin);
            using (Stream requestStream = request.GetRequestStream())
            {
                ms.CopyTo(requestStream);
            }
            using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
            {
                if (response.StatusCode == HttpStatusCode.Created)
                {
                    // Success
                }
                else
                {
                    // Error!
                }
            }
        }

        /// <summary>
        /// Gets the scope URI in Google's format.
        /// </summary>
        /// <param name="scope">The scope, which may include one or several Google applications.</param>
        /// <returns>A space-delimited list of URIs for the requested Google applications.</returns>
        public static string GetScopeUri(Applications scope)
        {
            return string.Join(" ", Util.GetIndividualFlags(scope).Select(app => DataScopeUris[(Applications)app]).ToArray());
        }
    }
}
