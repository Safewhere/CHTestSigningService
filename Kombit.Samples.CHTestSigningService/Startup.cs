using System.Web.Http;
using Owin;

namespace Kombit.Samples.CHTestSigningService
{
    /// <summary>
    ///     A startup class which is used by OWIN to configure the TestSigningService Web Api
    /// </summary>
    public class Startup
    {
        /// <summary>
        ///     This code configures Web API. The Startup class is specified as a type
        ///     parameter in the WebApp.Start method.
        /// </summary>
        /// <param name="appBuilder">Builder object of OWIN</param>
        public void Configuration(IAppBuilder appBuilder)
        {
            //// Configure Web API for self-host. 
            HttpConfiguration config = new HttpConfiguration();
            WebApiConfig.Register(config);

            appBuilder.UseWebApi(config);
            GlobalConfiguration.Configuration.IncludeErrorDetailPolicy = IncludeErrorDetailPolicy.Always;
        }
    }
}