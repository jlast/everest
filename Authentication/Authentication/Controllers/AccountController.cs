using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Principal;
using System.Web;
using System.Web.Mvc;
using System.Web.Routing;
using System.Web.Security;
using Authentication.Models;
using System.Security.Cryptography;
using System.Text;

namespace Authentication.Controllers
{

    [HandleError]
    public class AccountController : Controller
    {

        public IFormsAuthenticationService FormsService { get; set; }
        public IMembershipService MembershipService { get; set; }

        protected override void Initialize(RequestContext requestContext)
        {
            if (FormsService == null) { FormsService = new FormsAuthenticationService(); }
            if (MembershipService == null) { MembershipService = new AccountMembershipService(); }

            base.Initialize(requestContext);
        }

        // **************************************
        // URL: /Account/LogOn
        // **************************************

        public ActionResult LogOn()
        {
            return View();
        }

        [HttpPost]
        public ActionResult LogOn(LogOnModel model, string returnUrl)
        {
            if (ModelState.IsValid)
            {
                if (Membership.ValidateUser(model.UserName, model.Password))
                {
                    var profile = TwoFactorProfile.GetByUserName(model.UserName);

                    if (profile != null && !string.IsNullOrEmpty(profile.TwoFactorSecret))
                    {
                        if (HashedOneTimePassword.IsValid(profile.TwoFactorSecret, model.TwoFactorCode))
                        {
                            FormsAuthentication.SetAuthCookie(model.UserName, model.RememberMe);
                            if (returnUrl != null && returnUrl.Length > 1 && returnUrl.StartsWith("/")
                                && !returnUrl.StartsWith("//") && !returnUrl.StartsWith("/\\"))
                            {
                                return Redirect(returnUrl);
                            }
                            else
                            {
                                return RedirectToAction("Index", "Home");
                            }
                        }
                        else
                        {
                            ModelState.AddModelError("", "The two factor code is incorrect.");
                        }
                    }
                    else
                    {
                        ModelState.AddModelError("", "The two factor code is incorrect.");
                    }
                }
                else
                {
                    ModelState.AddModelError("", "The user name or password provided is incorrect.");
                }
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }

        // **************************************
        // URL: /Account/LogOff
        // **************************************

        public ActionResult LogOff()
        {
            FormsService.SignOut();

            return RedirectToAction("Index", "Home");
        }

        // **************************************
        // URL: /Account/Register
        // **************************************

        public ActionResult Register()
        {
            ViewData["PasswordLength"] = MembershipService.MinPasswordLength;
            return View();
        }

        [HttpPost]
        public ActionResult Register(RegisterModel model)
        {
            if (ModelState.IsValid)
            {
                // Attempt to register the user
                MembershipCreateStatus createStatus = MembershipService.CreateUser(model.UserName, model.Password, model.Email);

                if (createStatus == MembershipCreateStatus.Success)
                {
                    FormsService.SignIn(model.UserName, false /* createPersistentCookie */);
                    return RedirectToAction("ShowTwoFactorSecret", "Account");
                }
                else
                {
                    ModelState.AddModelError("", AccountValidation.ErrorCodeToString(createStatus));
                }
            }

            // If we got this far, something failed, redisplay form
            ViewData["PasswordLength"] = MembershipService.MinPasswordLength;
            return View(model);
        }

        // **************************************
        // URL: /Account/ChangePassword
        // **************************************

        [Authorize]
        public ActionResult ChangePassword()
        {
            ViewData["PasswordLength"] = MembershipService.MinPasswordLength;
            return View();
        }

        [Authorize]
        [HttpPost]
        public ActionResult ChangePassword(ChangePasswordModel model)
        {
            if (ModelState.IsValid)
            {
                if (MembershipService.ChangePassword(User.Identity.Name, model.OldPassword, model.NewPassword))
                {
                    return RedirectToAction("ChangePasswordSuccess");
                }
                else
                {
                    ModelState.AddModelError("", "The current password is incorrect or the new password is invalid.");
                }
            }

            // If we got this far, something failed, redisplay form
            ViewData["PasswordLength"] = MembershipService.MinPasswordLength;
            return View(model);
        }

        // **************************************
        // URL: /Account/ChangePasswordSuccess
        // **************************************

        public ActionResult ChangePasswordSuccess()
        {
            return View();
        }

        [Authorize]
        public ActionResult ShowTwoFactorSecret()
        {
            string secret = TwoFactorProfile.CurrentUser.TwoFactorSecret;

            if (string.IsNullOrEmpty(secret))
            {
                byte[] buffer = new byte[9];

                using (RandomNumberGenerator rng = RNGCryptoServiceProvider.Create())
                {
                    rng.GetBytes(buffer);
                }

                // Generates a 10 character string of A-Z, a-z, 0-9
                // Don't need to worry about any = padding from the
                // Base64 encoding, since our input buffer is divisible by 3
                TwoFactorProfile.CurrentUser.TwoFactorSecret = Convert.ToBase64String(buffer).Substring(0, 10).Replace('/', '0').Replace('+', '1');

                secret = TwoFactorProfile.CurrentUser.TwoFactorSecret;
            }

            var enc = new Base32Encoder().Encode(Encoding.ASCII.GetBytes(secret));

            return View(new TwoFactorSecret { EncodedSecret = enc });
        }
    }
}
