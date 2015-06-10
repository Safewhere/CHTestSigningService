#region

using System.Web.Mvc;

#endregion

namespace Kombit.Samples.CHTestSigningService.Controllers
{
    /// <summary>
    ///     A home controller which can display the welcome page with some useful information on it.
    /// </summary>
    public class HomeController : Controller
    {
        /// <summary>
        ///     The default index action
        /// </summary>
        /// <returns>
        ///     Return the Index view which contains text to explain what this application is about and where the endpoints
        ///     are
        /// </returns>
        public ActionResult Index()
        {
            ViewBag.Title = "Home Page";

            return View();
        }
    }
}