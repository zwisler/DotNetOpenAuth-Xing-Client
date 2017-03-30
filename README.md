DotNetOpenAuth-Xing-Client
==========================
# The largest heading
## The second largest heading
###### The smallest heading
DotNetOpenAuth Xing Client
This site was built using [GitHub Pages](https://pages.github.com/).
@test
@github/support What do you think about these updates?

<pre style="font-size:157%">
[BROADCAST_RECEIVER_RULES]
RULE0 = *;/euro_essernet/c20
RULE1 = 
</pre>

# one #
DotNetOpenAuth-Xing-Client
=
1. Make my changes
  1. Fix bug
  2. Improve formatting
    * Make the headings bigger
2. Push my commits to GitHub
3. Open a pull request
  * Describe my changes
  * Mention all the members of my team
    * Ask for feedback
1. test
    1. its
    
@octocat :+1: This PR looks great - it's ready to merge! :shipit:
example Code:

``` C#
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
                { // new Client
                    var xing = new WebConsumer(XingClient.ServiceDescription, this.TokenManager);

                    // Is xing calling back with authorization?
                    var accessTokenResponse = xing.ProcessUserAuthorization();
                    if (accessTokenResponse != null)
                    
                    {
                        this.AccessToken = accessTokenResponse.AccessToken;
                        // The Token is Back To somting´else
                        //Response.Redirect("/C1_netTestPage.aspx#/Home");
                        // get me
                        dynamic result = XingClient.GetMe(xing, this.AccessToken);
                        string display_name = result.display_name;
                        string id = result.id;
                        string first_name = result.first_name;
                        string last_name = result.last_name;
                        string picurl = result.photo_urls.maxi_thumb;
                        // get my contacts
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
}
```
