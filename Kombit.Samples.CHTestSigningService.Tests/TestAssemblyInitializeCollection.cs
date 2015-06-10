#region

using Xunit;

#endregion

namespace Kombit.Samples.CHTestSigningService.Tests
{
    /// <summary>
    ///     This class has no code, and is never created. Its purpose is simply
    ///     to be the place to apply [CollectionDefinition] and all the
    ///     ICollectionFixture<> interfaces.
    ///     A mean for Xunit to execute Assembly initialize.
    /// </summary>
    [CollectionDefinition("TestAssemblyInitialize collection")]
    public class TestAssemblyInitializeCollection : ICollectionFixture<TestAssemblyInitializeFixture>
    {
    }
}