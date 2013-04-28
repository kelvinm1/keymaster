
KeyMaster is a C# .NET application for generating AES encryption keys and 
encrypting data. This project was created using the Visual Studio 2010 IDE.
To run KeyMaster from the command line, you will need to go to the folder
location of the KeyMaster.exe file and type the following:

KeyMaster.exe -jar "prometheus.jar" <stream-url> [options]

/v                        Displays the current version of KeyMaster
/c    					  Creates a new AES encrypted key
/d <cipher> <key>         Decrypts the cipher with specified key
/e <text> <key>	          Encrypts the plain text with specified key
/df <file>                Decrypts the specified file
/ef <file>                Encrypts the specified file
