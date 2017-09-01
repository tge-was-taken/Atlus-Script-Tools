using System;
using System.Reflection;

namespace AtlusScriptLib.CLI
{
    public class CommandLineArgumentValueTarget
    {
        public Type TargetType { get; }

        public object TargetInstance { get; }

        public MemberInfo TargetMember { get; }

        public CommandLineArgumentValueTarget(object instance, string memberName)
        {
            TargetType = instance.GetType();
            TargetInstance = instance;
            TargetMember = GetMemberInfo(memberName);
        }

        public CommandLineArgumentValueTarget(Type type, string memberName)
        {
            TargetType = type;
            TargetMember = GetMemberInfo(memberName);
        }

        private MemberInfo GetMemberInfo(string memberName)
        {
            var members = TargetType.GetMember(memberName, BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static);

            if (members.Length == 0)
            {
                throw new Exception($"No member with name {memberName} found for type {TargetType.FullName}");
            }
            else if (members.Length == 1)
            {
                return members[0];
            }
            else
            {
                throw new Exception($"More than one member with name {memberName} found for type {TargetType.FullName}");
            }
        }
    }
}
