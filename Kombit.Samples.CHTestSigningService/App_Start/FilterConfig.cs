#region

using System.Web.Mvc;

#endregion

namespace Kombit.Samples.CHTestSigningService
{
    /// <summary>
    ///     This class is responsible for configuring filters
    /// </summary>
    public class FilterConfig
    {
        /// <summary>
        ///     Registers the HandleError filter to the global filter list
        /// </summary>
        /// <param name="filters"></param>
        public static void RegisterGlobalFilters(GlobalFilterCollection filters)
        {
            filters.Add(new HandleErrorAttribute());
        }
    }
}