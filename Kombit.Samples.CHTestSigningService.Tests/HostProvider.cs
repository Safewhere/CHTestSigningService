#region

using System;
using Microsoft.Owin.Hosting;

#endregion

namespace Kombit.Samples.CHTestSigningService.Tests
{
    /// <summary>
    ///     Provides hosting for the service. This class can be used to make sure we can easily switch the hosting options for
    ///     the tests.
    /// </summary>
    public static class HostProvider
    {
        /// <summary>
        ///     Starts hosting. When in debug mode, returns OWIN host. In release mode, IIS will be used so this just returns an
        ///     empty host
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="url"></param>
        /// <returns></returns>
        public static IDisposable Start<T>(string url)
        {
#if DEBUG
            return WebApp.Start<Startup>(url);
#endif
#if !DEBUG
            return new EmptyWebApp();
#endif
        }

        /// <summary>
        ///     An empty host that does nothing
        /// </summary>
        private class EmptyWebApp : IDisposable
        {
            public void Dispose()
            {
                // no-op
            }
        }
    }
}