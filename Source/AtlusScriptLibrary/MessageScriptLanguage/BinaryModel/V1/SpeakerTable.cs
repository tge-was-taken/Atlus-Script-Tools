using System.Collections.Generic;
using System.Linq;

namespace AtlusScriptLibrary.MessageScriptLanguage.BinaryModel.V1;

/// <summary>
/// The speaker name table as the builder fills it: entries in order of first use, plus entries
/// pinned to a fixed index. Also used to work out which entries a rebuild cannot place on its own.
/// </summary>
internal class SpeakerTable
{
    private readonly List<byte[]> mNames = new();
    private readonly List<bool> mShareable = new();
    private readonly Dictionary<int, (byte[] Name, bool Shareable)> mPins = new();

    public IReadOnlyList<byte[]> Names => mNames;

    public void Pin(int index, byte[] name, bool shareable)
    {
        mPins[index] = (name, shareable);
        FlushPins();
    }

    public int Add(byte[] name, bool shareable)
    {
        FlushPins();

        if (shareable)
        {
            for (int i = 0; i < mNames.Count; i++)
            {
                if (mShareable[i] && mNames[i].SequenceEqual(name))
                    return i;
            }
        }

        var index = mNames.Count;
        mNames.Add(name);
        mShareable.Add(true);
        FlushPins();
        return index;
    }

    // A pinned entry sits at a fixed index, so place it as soon as the table reaches that index.
    public void FlushPins()
    {
        while (mPins.TryGetValue(mNames.Count, out var pin))
        {
            mNames.Add(pin.Name);
            mShareable.Add(pin.Shareable);
        }
    }
}
