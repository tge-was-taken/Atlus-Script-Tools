using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AtlusScriptLib
{
    public class MessageScript
    {
        /// <summary>
        /// Gets or sets the user id. Serves as metadata.
        /// </summary>
        public short UserId { get; set; }

        /// <summary>
        /// Gets the list of <see cref="IMessageScriptMessage"/> in this script.
        /// </summary>
        public List<IMessageScriptMessage> Messages { get; }
    }
}
