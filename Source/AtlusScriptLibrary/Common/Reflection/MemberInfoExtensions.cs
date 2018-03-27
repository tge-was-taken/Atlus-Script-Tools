using System;
using System.Reflection;

namespace AtlusScriptLibrary.Common.Reflection
{
    public static class MemberInfoExtensions
    {
        public static Type GetMemberType( this MemberInfo memberInfo )
        {
            switch ( memberInfo.MemberType )
            {
                case MemberTypes.Field:
                    return ( ( FieldInfo )memberInfo ).FieldType;
                case MemberTypes.Property:
                    return ( ( PropertyInfo )memberInfo ).PropertyType;
                default:
                    throw new ArgumentException( "Member must be a field or a property", nameof( memberInfo ) );
            }
        }

        public static Type GetElementType( this MemberInfo memberInfo )
        {
            switch ( memberInfo.MemberType )
            {
                case MemberTypes.Field:
                    return ( ( FieldInfo )memberInfo ).GetElementType();
                case MemberTypes.Property:
                    return ( ( PropertyInfo )memberInfo ).GetElementType();
                default:
                    throw new ArgumentException( "Member must be a field or a property", nameof( memberInfo ) );
            }
        }

        public static T GetValue<T>( this MemberInfo memberInfo, object instance )
        {
            switch ( memberInfo.MemberType )
            {
                case MemberTypes.Field:
                    return ( T )( ( FieldInfo )memberInfo ).GetValue( instance );
                case MemberTypes.Property:
                    return ( T )( ( PropertyInfo )memberInfo ).GetValue( instance );
                default:
                    throw new ArgumentException( "Member must be a field or a property", nameof( memberInfo ) );
            }
        }

        public static object GetValue( this MemberInfo memberInfo, object instance )
        {
            switch ( memberInfo.MemberType )
            {
                case MemberTypes.Field:
                    return ( ( FieldInfo )memberInfo ).GetValue( instance );
                case MemberTypes.Property:
                    return ( ( PropertyInfo )memberInfo ).GetValue( instance );
                default:
                    throw new ArgumentException( "Member must be a field or a property", nameof( memberInfo ) );
            }
        }

        public static void SetValue( this MemberInfo memberInfo, object instance, object value )
        {
            switch ( memberInfo.MemberType )
            {
                case MemberTypes.Field:
                    ( ( FieldInfo )memberInfo ).SetValue( instance, value );
                    break;
                case MemberTypes.Property:
                    ( ( PropertyInfo )memberInfo ).SetValue( instance, value );
                    break;
                default:
                    throw new ArgumentException( "Member must be a field or a property", nameof( memberInfo ) );
            }
        }
    }
}
