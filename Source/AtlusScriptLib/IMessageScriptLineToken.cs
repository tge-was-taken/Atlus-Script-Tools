using System;
using System.Text;
using System.Threading.Tasks;

namespace AtlusScriptLib
{
    public interface IMessageScriptLineToken
    {
        MessageScriptTokenType Type { get; }
    }
}
