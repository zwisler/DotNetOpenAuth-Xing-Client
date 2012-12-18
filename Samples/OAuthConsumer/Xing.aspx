<%@ Page Title="Xing Login" Language="C#" MasterPageFile="~/MasterPage.master"
	AutoEventWireup="true" Inherits="C1_net.Web.Xing" Codebehind="Xing.aspx.cs" %>

<asp:Content ID="Content2" ContentPlaceHolderID="Body" runat="Server">
	<asp:MultiView ID="MultiView1" runat="server" ActiveViewIndex="0">
		<asp:View runat="server">
			<h2>Xing Setup</h2>
			<p>Not joined XING yet? </p>
			<ol>
				<li><a target="_blank" href="https://www.xing.com/app/signup">Visit Xing</a>. </li>				
			</ol>
		</asp:View>
		<asp:View runat="server">
			
		</asp:View>
	</asp:MultiView>
</asp:Content>
