using System.Web.Mvc;
using System.Web.Routing;

namespace Kombit.Samples.CHTestSigningService
{
    /// <summary>
    ///     This class is responsible for configuring routes
    /// </summary>
    public class RouteConfig
    {
        /// <summary>
        ///     Registers routes to the routing collection. One route to ignore resource requests and one to route request to the
        ///     correct controller/action
        /// </summary>
        /// <param name="routes">Routes collection</param>
        public static void RegisterRoutes(RouteCollection routes)
        {
            routes.IgnoreRoute("{resource}.axd/{*pathInfo}");

            routes.MapRoute(
                name: "Default",
                url: "{controller}/{action}/{id}",
                defaults: new {controller = "Home", action = "Index", id = UrlParameter.Optional}
                );
        }
    }
}