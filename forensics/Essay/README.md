Writeup: Essay Challenge (Forensics, 368 Points)
Challenge Description
Name: EssayCategory: ForensicsPoints: 368Description:"I've written an essay for my assignment. Could you please take a look at it?"Author: ZwiqueProvided File: Essay.docm
The challenge provides a Microsoft Word document with macros (Essay.docm) and hints at a hidden flag, typical of a Capture The Flag (CTF) forensics challenge. The goal is to extract a secret flag, likely in the format Blitz{...}, by analyzing the document's contents.
Solution
The Essay.docm file is a Word document with macros, suggesting the flag is hidden within its structure, VBA code, or embedded objects. Here’s the step-by-step process to uncover the flag:
Step 1: Initial Analysis

File Inspection: The provided file is a .docm (Word document with macros). Using binwalk, the file is identified as a ZIP archive containing OpenXML components, including word/document.xml (main text), word/vbaProject.bin (VBA macros), and others.
Unzip the Document:unzip Essay.docm -d extracted_doc

This extracts files like [Content_Types].xml, word/document.xml, word/vbaProject.bin, and word/vbaData.xml.

Step 2: Examine the Document Content

The essay text mentions flag.txt as a hyperlink in word/document.xml. Checking word/_rels/document.xml.rels reveals the hyperlink (rId6) points to https://www.youtube.com/watch?v=dQw4w9WgXcQ (a Rickroll), indicating a red herring.

Step 3: Analyze VBA Macros

Tool Used: olevba (from oletools) to inspect macros in word/vbaProject.bin:olevba Essay.docm


Key Findings:
ThisDocument.cls: Contains an AutoOpen macro that runs RunCounter (displays a message box five times) and EmbedDesktopZip, which attempts to embed a secret.zip file from the desktop. A comment states: "The real flag is in the embedded ZIP; Try to extract it If you can :)".
Part5.cls: Includes an obfuscated string: Chr(83) & Chr(117) & Chr(112) & Chr(51) & ..., decoding to Sup3rS3cretPassW0RD, suggesting a password or potential flag.
Other Modules: Part1 to Part7 and References contain essay text and a decoy function, but no additional secrets.



Step 4: Search for Embedded ZIP

Check for Embedded Objects: Run oleobj to find embedded files:oleobj Essay.docm

No embedded secret.zip is found, only the Rickroll hyperlink.
Inspect vbaProject.bin:binwalk extracted_doc/word/vbaProject.bin
xxd extracted_doc/word/vbaProject.bin | grep "50 4b 03 04"

Both commands show no ZIP signatures, suggesting secret.zip is a misdirection.
Strings Search:strings extracted_doc/word/vbaProject.bin | grep -E "CTF|flag|secret|Sup3rS3cretPassW0RD|base64"

This reveals secret.zip references and the comment about the flag in the ZIP, but no actual ZIP file.

Step 5: Identify and Decode the Flag

Base64 String: The strings output includes QmxpdHp7MGwzX0QzTXBfTTNsMTBzfQo^, a base64-like string.
Fix Padding: The ^ at the end is invalid for base64; replace it with = to get QmxpdHp7MGwzX0QzTXBfTTNsMTBzfQo=.
Decode:echo "QmxpdHp7MGwzX0QzTXBfTTNsMTBzfQo=" | base64 -d

Output: Blitz{0l3_D3Mp_M3l10s}.
Analysis: The decoded string matches the CTF flag format Blitz{...}, where Blitz is likely the challenge name, and 0l3_D3Mp_M3l10s is a leetspeak string (possibly "OLE Dump Melios"), fitting the macro-based context.

Step 6: Verify and Conclude

Password Check: The password Sup3rS3cretPassW0RD was tested as CTF{Sup3rS3cretPassW0RD} and flag{Sup3rS3cretPassW0RD}, but these are less likely as they don’t match the decoded flag format.
No ZIP Found: The repeated absence of secret.zip (via binwalk, oleobj, xxd) and the Rickroll hyperlink confirm these as distractions.
Final Flag: The base64 string’s decoded value, Blitz{0l3_D3Mp_M3l10s}, is the flag, hidden in the macro strings.

Final Answer
The flag for the Essay challenge is:
Blitz{0l3_D3Mp_M3l10s}
Key Takeaways

Red Herrings: The flag.txt hyperlink (Rickroll) and secret.zip references were misdirection, common in CTF forensics challenges.
Obfuscation: The password Sup3rS3cretPassW0RD and base64 string required careful inspection of macro strings.
Tools Used: unzip, olevba, oleobj, binwalk, xxd, strings, and base64 decoding were critical for analysis.

This challenge highlights the importance of thoroughly analyzing all document components and recognizing CTF misdirection tactics.
