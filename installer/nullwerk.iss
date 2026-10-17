#define AppName "NULLWERK"
#define AppVersion "4.2.0"
[Setup]
AppId={{126AB68D-4C6F-4F92-8723-0D822B047C71}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher=NULLWERK contributors
DefaultDirName={localappdata}\Programs\NULLWERK
DefaultGroupName=NULLWERK
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\dist
OutputBaseFilename=NULLWERK-{#AppVersion}-Windows-Setup
SetupIconFile=..\assets\nullwerk.ico
UninstallDisplayIcon={app}\GUI\NULLWERK.exe
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
LicenseFile=..\LICENSE
InfoBeforeFile=..\NOTICE.txt
DisableProgramGroupPage=yes
CloseApplications=yes
[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
[Files]
Source: "..\dist\NULLWERK\*"; DestDir: "{app}\GUI"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\dist\nullwerk-cli\*"; DestDir: "{app}\CLI"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\LEGAL.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\NOTICE.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\THIRD_PARTY_NOTICES.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\docs\*.md"; DestDir: "{app}\docs"; Flags: ignoreversion
[Icons]
Name: "{group}\NULLWERK"; Filename: "{app}\GUI\NULLWERK.exe"
Name: "{group}\Uninstall NULLWERK"; Filename: "{uninstallexe}"
[Run]
Filename: "{app}\GUI\NULLWERK.exe"; Description: "Launch NULLWERK"; Flags: nowait postinstall skipifsilent unchecked
