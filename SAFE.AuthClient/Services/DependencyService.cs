using System;
using System.Collections.Concurrent;

namespace SAFE.AuthClient.Helpers
{
    public class DependencyService
    {
        static ConcurrentDictionary<string, object> _pairs = new ConcurrentDictionary<string, object>();

        public static void Register<TInterface, TConcrete>()
            => _pairs[typeof(TInterface).AssemblyQualifiedName] = Activator.CreateInstance<TConcrete>();

        public static void Register<TInterface, TConcrete>(TConcrete concrete)
            => _pairs[typeof(TInterface).AssemblyQualifiedName] = concrete;

        internal static T Get<T>()
            => (T)_pairs[typeof(T).AssemblyQualifiedName];
    }
}