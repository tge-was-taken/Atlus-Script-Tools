using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;

namespace AtlusScriptLib.Common
{
    public class CommandLineArgument<TValue> : ICommandLineArgument
        where TValue : IConvertible
    {
        public string Key { get; }

        public string Description { get; set; }

        public bool Required { get; set; }

        public bool TakesParameters { get; set; }

        public bool IsValueProvided { get; set; } 

        private TValue mValue;

        public TValue Value
        {
            get { return mValue; }
            set
            {
                mValue = value;
                AssignValueToTarget();
            }
        }

        private TValue mDefaultValue;

        public TValue DefaultValue
        {
            get { return mDefaultValue; }
            set
            {
                mDefaultValue = value;

                // Only set the value if the value hasn't already been assigned by the parser
                if (!IsValueProvided)
                    Value = mDefaultValue;
            }
        }

        public List<TValue> PossibleValues { get; set; }

        public CommandLineArgumentValueTarget Target { get; set; }

        IConvertible ICommandLineArgument.Value
        {
            get { return Value; }
            set { Value = (TValue)Convert.ChangeType(value, typeof(TValue)); }
        }

        IConvertible ICommandLineArgument.DefaultValue
        {
            get { return DefaultValue; }
            set { DefaultValue = (TValue)value; }
        }

        List<IConvertible> ICommandLineArgument.PossibleValues
        {
            get
            {
                if (PossibleValues == null)
                    return null;

                return PossibleValues.Cast<IConvertible>().ToList();
            }
            set
            {
                PossibleValues = value.Select(x => (TValue)Convert.ChangeType(x, typeof(TValue))).ToList();
            }
        }

        public CommandLineArgument(string key)
        {
            if (!key.StartsWith("-"))
                key = "-" + key;

            Key = key;
            Required = false;
            TakesParameters = true;
            IsValueProvided = false;
        }
        
        private void AssignValueToTarget()
        {
            if (Target == null)
                return;

            switch (Target.TargetMember.MemberType)
            {
                case MemberTypes.Field:
                    ((FieldInfo)Target.TargetMember).SetValue(Target.TargetInstance, Value);
                    break;
                case MemberTypes.Property:
                    ((PropertyInfo)Target.TargetMember).SetValue(Target.TargetInstance, Value);
                    break;
            }
        }
    }
}
