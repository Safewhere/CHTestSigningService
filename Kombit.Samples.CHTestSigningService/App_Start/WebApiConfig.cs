#region

using System.Web.Http;
using Kombit.Samples.Common;

#endregion

namespace Kombit.Samples.CHTestSigningService
{
    /// <summary>
    ///     This class is responsible for registering CHRestSigningService Web Api configuration
    /// </summary>
    public static class WebApiConfig
    {
        /// <summary>
        ///     Registers route for CHRestSigningService Web Api
        /// </summary>
        /// <param name="config">HttpConfiguration object</param>
        public static void Register(HttpConfiguration config)
        {
            // Web API configuration and services

            // Web API routes
            config.MapHttpAttributeRoutes();

            config.Routes.MapHttpRoute(
                name: "DefaultApi",
                routeTemplate: "api/{controller}/{thumbprint}",
                defaults: new {thumbprint = RouteParameter.Optional}
                );

            config.Formatters.Add(new BrowserJsonFormatter());
        }
    }
}