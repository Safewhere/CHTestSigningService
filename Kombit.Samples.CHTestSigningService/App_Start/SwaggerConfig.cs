#region

using System.Web.Http;
using Kombit.Samples.CHTestSigningService;
using Swashbuckle.Application;
using WebActivatorEx;

#endregion

[assembly: PreApplicationStartMethod(typeof (SwaggerConfig), "Register")]

namespace Kombit.Samples.CHTestSigningService
{
    /// <summary>
    ///     This class is responsible for registering the interactive Swagger documentation for the CHTestSigningService
    ///     endpoint.
    /// </summary>
    public class SwaggerConfig
    {
        /// <summary>
        ///     Registers documentation file for interactive Swagger documentation
        /// </summary>
        public static void Register()
        {
            GlobalConfiguration.Configuration.Routes.IgnoreRoute("api-docs", "content/api-docs.json");
            GlobalConfiguration.Configuration
                .EnableSwagger("content/api-docs.json", c =>
                {
                    c.Schemes(new[] {"https"});

                    c.SingleApiVersion("", "JsonAPI");

                    c.UseFullTypeNameInSchemaIds();
                })
                .EnableSwaggerUi(c =>
                {
                    c.DocExpansion(DocExpansion.List);
                    c.InjectJavaScript(typeof (SwaggerConfig).Assembly,
                        "Kombit.Samples.CHTestSigningService.Scripts.swagger-ui.js");
                });
        }
    }
}