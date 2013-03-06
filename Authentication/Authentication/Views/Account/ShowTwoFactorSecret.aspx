<%@ Page Title="" Language="C#" MasterPageFile="~/Views/Shared/Site.Master" Inherits="System.Web.Mvc.ViewPage<dynamic>" %>

<asp:Content ID="Content1" ContentPlaceHolderID="TitleContent" runat="server">
	ShowTwoFactorSecret
</asp:Content>

<asp:Content ID="Content2" ContentPlaceHolderID="MainContent" runat="server">
    <h2>Show Two Factor Secret</h2>

    <p>
        Add the code below to Google Authenticator:
    </p>
    <p>
        <img src="http://chart.apis.google.com/chart?cht=qr&chs=300x300&chl=otpauth://totp/<%: Page.User.Identity.Name %>@authframework.com?secret=<%: Model.EncodedSecret %>" alt="QRcode" />
    </p>
    <p>
        <%: Model.EncodedSecret %>
    </p>
</asp:Content>
