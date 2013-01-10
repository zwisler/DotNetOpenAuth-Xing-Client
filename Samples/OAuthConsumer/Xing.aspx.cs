namespace C1_net.Web
{
    using System;
    using System.Configuration;
    using System.Linq;
    using System.Text;
    using System.Web;
    using System.Web.UI;
    using System.Web.UI.WebControls;
    using System.Xml.Linq;
    using DotNetOpenAuth.ApplicationBlock;
    using DotNetOpenAuth.OAuth;
    using System.Runtime.Serialization.Json;
    /// <summary>
    /// A page to demonstrate downloading a Gmail address book using OAuth.
    /// </summary>
    public partial class Xing : System.Web.UI.Page
    {
        private string AccessToken
        {
            get { return (string)Session["XingAccessToken"]; }
            set { Session["XingAccessToken"] = value; }
        }

        private InMemoryTokenManager TokenManager
        {
            get
            {
                var tokenManager = (InMemoryTokenManager)Application["XingTokenManager"];
                if (tokenManager == null)
                {
                    string consumerKey = "consumerKey"; 
                    string consumerSecret = "consumerSecret"; 
                    if (!string.IsNullOrEmpty(consumerKey))
                    {
                        tokenManager = new InMemoryTokenManager(consumerKey, consumerSecret);
                        Application["XingTokenManager"] = tokenManager;
                    }
                }

                return tokenManager;
            }
        }

        protected void Page_Load(object sender, EventArgs e)
        {
            if (this.TokenManager != null)
            {
                this.MultiView1.ActiveViewIndex = 1;

                if (!IsPostBack)
                {
                    var xing = new WebConsumer(XingClient.ServiceDescription, this.TokenManager);

                    // Is Google calling back with authorization?
                    var accessTokenResponse = xing.ProcessUserAuthorization();
                    if (accessTokenResponse != null)
                    {
                        this.AccessToken = accessTokenResponse.AccessToken;
                        //Response.Redirect("/C1_netTestPage.aspx#/Home");
                        dynamic result = XingClient.GetMe(xing, this.AccessToken);
                        string display_name = result.display_name;
                        string id = result.id;
                        string first_name = result.first_name;
                        string last_name = result.last_name;
                        string picurl = result.photo_urls.maxi_thumb;
                        dynamic result2 = XingClient.GetMyContacts(xing, this.AccessToken, "display_name", 50, 0);
                        dynamic a = result2.contacts;
                        int b = a.total;
                        dynamic c = a.users;
                        int d = c.Count;

                        string display_name1 = c[0].display_name;
                        string id1 = c[0].id;

                        dynamic result3 = XingClient.GetUser(xing, this.AccessToken, id1, "photo_urls.medium_thumb");
                        string urli = result3.photo_urls.medium_thumb;
                        dynamic result4 = XingClient.GetUser(xing, this.AccessToken, id1, "active_email");
                        string mail = result3.active_email;
                        dynamic result5 = XingClient.GetUser(xing, this.AccessToken, c[12].id);
                        string url = XingClient.GetScopeUri(XingClient.Applications.me);
                        bool result6 = XingClient.PostStatus(xing, this.AccessToken, "Hura fertig!!! ", id);
                        
                        
                        
                        
                        //Response.Redirect("/#/Home"); 

                    }
                    else if (this.AccessToken == null)
                    {
                        // If we don't yet have access, immediately request it.
                        XingClient.RequestAuthorization(xing, XingClient.Applications.Contacts);
                    }
                }
            }
        }

        protected void getAddressBookButton_Click(object sender, EventArgs e)
        {


            // XDocument contactsDocument = XingConsumer.GetContacts(google, this.AccessToken, 100, 1);
            //var contacts = from entry in contactsDocument.Root.Elements(XName.Get("entry", "http://www.w3.org/2005/Atom"))
            //               select new
            //               {
            //                   Name = entry.Element(XName.Get("title", "http://www.w3.org/2005/Atom")).Value,
            //                   Email =  entry.Element(XName.Get("email", "http://schemas.google.com/g/2005")) != null ? entry.Element(XName.Get("email", "http://schemas.google.com/g/2005")).Attribute("address").Value  : "no Mail"
            //                   //Email = entry.Element(XName.Get("email", "http://schemas.google.com/g/2005")).Attribute("address").Value  ?? ""
            //               };
            //StringBuilder tableBuilder = new StringBuilder();
            //tableBuilder.Append("<table><tr><td>Name</td><td>Email</td></tr>");
            //foreach (var contact in contacts) {
            //    tableBuilder.AppendFormat(
            //        "<tr><td>{0}</td><td>{1}</td></tr>",
            //        HttpUtility.HtmlEncode(contact.Name),
            //        HttpUtility.HtmlEncode(contact.Email));
            //}
            //tableBuilder.Append("</table>");

        }
    }
}