using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace AtlusScriptLibrary.Common.Libraries.Serialization;

[JsonSourceGenerationOptions(AllowTrailingCommas = true)]
[JsonSerializable(typeof(Library))]
[JsonSerializable(typeof(List<FlowScriptModule>))]
[JsonSerializable(typeof(List<FlowScriptModuleConstant>))]
[JsonSerializable(typeof(List<FlowScriptModuleEnum>))]
[JsonSerializable(typeof(List<FlowScriptModuleFunction>))]
[JsonSerializable(typeof(List<MessageScriptLibrary>))]
internal partial class LibraryJsonContext : JsonSerializerContext
{
}
