using System;
using System.Linq;

namespace AtlusScriptLibrary.Common.Reflection
{
    public static class TypeExtensions
    {
        public static T[] GetCustomAttributes<T>( this Type type, bool inherit = false )
        {
            return type.GetCustomAttributes( typeof( T ), inherit ).Cast<T>().ToArray();
        }

        public static T GetCustomAttribute<T>( this Type type, bool inherit = false )
        {
            var customAttributes = type.GetCustomAttributes<T>( inherit );

            if ( customAttributes.Length > 1 )
            {
                throw new Exception( "More than one attribute of type present" );
            }
            if ( customAttributes.Length == 1 )
            {
                return customAttributes[0];
            }
            return default( T );
        }
    }
}
