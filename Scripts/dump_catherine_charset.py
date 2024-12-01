def ttf_to_tsv_with_unicode(ttf_path, tsv_path):
    """
    Convert a TTF font's glyphs to a TSV file with Unicode equivalents.

    Args:
        ttf_path (str): Path to the TTF font file.
        tsv_path (str): Path to save the TSV file.
    """
    from fontTools.ttLib import TTFont

    # Load the TTF font file
    font = TTFont(ttf_path)
    
    # Extract glyph to Unicode mappings
    cmap = font.getBestCmap()
    
    # Reverse the cmap for glyph-to-unicode mapping
    unicode_mapping = {glyph: codepoint for codepoint, glyph in cmap.items()}
    
    # Open the TSV file for writing
    with open(tsv_path, 'w', encoding='utf-8') as tsv_file:
        row = []
        for index, glyph_name in enumerate(font.getGlyphOrder()):
            # Use Unicode equivalent or the glyph index in hex
            index_escaped = f"\\u{index:04X}"
            output_code = unicode_mapping.get(glyph_name)
            if output_code is None or output_code < 20:
                output = index_escaped
            else:
                output = chr(output_code)

            row.append(output)
            
            # Write 16 glyphs per row
            if (index + 1) % 16 == 0:
                tsv_file.write("\t".join(row) + "\n")
                row = []
        
        # Write any remaining glyphs
        if row:
            tsv_file.write("\t".join(row) + "\n")

    print(f"Glyphs and Unicode values have been written to {tsv_path}")

# Example usage
font = 'Catherine'
ttf_path = f"../{font}.ttf"  # Replace with the path to your TTF file
tsv_path = f"Source/AtlusScriptLibrary/Charsets/{font}.tsv"  # Replace with the desired output path
ttf_to_tsv_with_unicode(ttf_path, tsv_path)
