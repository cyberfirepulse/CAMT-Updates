; ================================================================
; CAMT Professional Edition 1.2.0 Beta 9
; Build: 120B9-LIC-20260916
; Full / extended installer
; ================================================================
;
; This script restores the extended installer layer used by the
; earlier full CAMT installer while preserving the established full-installer functionality.
;
; Expected project layout:
;   CAMT_Beta6_InnoSetup_Complete.iss
;   CAMT.ico
;   License.rtf
;   CAMT_PRE_INSTALL.txt
;   CAMT_POST_INSTALL.txt
;   CAMT_BETA_DISCLAIMER.txt
;   wizard_logo.bmp
;   wizard_icon.bmp
;   dist\CAMT\...
;   prerequisites\nmap-7.99-setup.exe
;   prerequisites\npcap-1.88.exe
;   prerequisites\vc_redist.x64.exe
;   prerequisites\vc_redist.x86.exe
;
#define MyAppName "CAMT"
#define MyAppVersion "1.2.0 Beta 9"
#define MyAppBuild "120B9-LIC-20260916"
#define MyAppPublisher "CyberFirePulse"
#define MyAppURL "https://github.com/cyberfirepulse/CAMT-Updates"
#define MyAppExeName "CAMT.exe"

; Use the directory containing this .iss file as the build root.
#define BaseDir "D:\scripts\scan\CAMT_B5_FIX_v3\CAMT_B5_FIX"

; Keep the long-lived CAMT installer identity.
#define MyAppId "{{AE34C930-D943-4FB7-B8D4-A4F2F1969A3C}"

; ================================================================
; FULL INSTALLER
; Clean/offline/air-gapped CAMT installation.
; Includes prerequisite checks and installers.
; ================================================================

[Setup]
AppId={#MyAppId}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} Professional Edition {#MyAppVersion}

AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}

; Inno version fields must be numeric.
VersionInfoVersion=1.2.0.6
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription=CAMT Professional Edition {#MyAppVersion}
VersionInfoProductName=CAMT Professional Edition
VersionInfoProductVersion=1.2.0.6

DefaultDirName={autopf}\CAMT
DefaultGroupName=CAMT
DisableProgramGroupPage=No
UsePreviousAppDir=yes
DisableDirPage=no

UninstallDisplayIcon={app}\{#MyAppExeName}
UninstallDisplayName=CAMT Professional Edition {#MyAppVersion}

ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

ChangesAssociations=yes

PrivilegesRequired=admin

CloseApplications=yes
RestartApplications=no

LicenseFile={#BaseDir}\License.rtf
InfoBeforeFile={#BaseDir}\CAMT_PRE_INSTALL.txt
InfoAfterFile={#BaseDir}\CAMT_POST_INSTALL.txt

OutputDir={#BaseDir}\installer
OutputBaseFilename=CAMT_Professional_Edition_1.2.0_Beta9_Setup

SetupIconFile={#BaseDir}\snoop.ico
WizardImageFile={#BaseDir}\wizard_icon.bmp
WizardSmallImageFile={#BaseDir}\wizard_logo.bmp

Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern



MinVersion=10.0

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "dutch"; MessagesFile: "compiler:Languages\Dutch.isl"

[Types]
Name: "full"; Description: "Volledige installatie"
Name: "compact"; Description: "CAMT zonder optionele snelkoppelingen"
Name: "custom"; Description: "Aangepaste installatie"; Flags: iscustom

[Components]
Name: "core"; Description: "CAMT Application (required)"; Types: full compact custom; Flags: fixed
Name: "shortcuts"; Description: "Start Menu Shortcuts"; Types: full custom
Name: "associations"; Description: "CAMT File Associations"; Types: full custom

[Tasks]
Name: "desktopicon"; \
Description: "{cm:CreateDesktopIcon}"; \
GroupDescription: "{cm:AdditionalIcons}"; \
Components: shortcuts; \
Flags: unchecked

[CustomMessages]
english.DesktopShortcut=Desktop shortcut
english.ExtraShortcuts=Additional shortcuts:
dutch.DesktopShortcut=Bureaublad-snelkoppeling
dutch.ExtraShortcuts=Extra snelkoppelingen:

[Files]

; ================================================================
; COMPLETE PYINSTALLER DISTRIBUTION
; ================================================================
Source: "{#BaseDir}\dist\CAMT\*"; \
DestDir: "{app}"; \
Components: core; \
Flags: ignoreversion recursesubdirs createallsubdirs

; Do not install portable.flag: installed CAMT uses its normal
; central application-data directory.

; ================================================================
; DOCUMENTATION
; ================================================================
Source: "{#BaseDir}\CAMT_BETA_DISCLAIMER.txt"; \
DestDir: "{app}\docs"; \
Components: core; \
Flags: ignoreversion

Source: "{#BaseDir}\README.md"; \
DestDir: "{app}\docs"; \
Components: core; \
Flags: ignoreversion skipifsourcedoesntexist

Source: "{#BaseDir}\README_BETA.md"; \
DestDir: "{app}\docs"; \
Components: core; \
Flags: ignoreversion skipifsourcedoesntexist

Source: "{#BaseDir}\CAMT_RELEASE_NOTES_1_1_0_BETA_8.md"; \
DestDir: "{app}\docs"; \
Components: core; \
Flags: ignoreversion skipifsourcedoesntexist

Source: "{#BaseDir}\QuickStart.pdf"; \
DestDir: "{app}\docs"; \
Components: core; \
Flags: ignoreversion skipifsourcedoesntexist

; ================================================================
; OFFLINE PREREQUISITES
; ================================================================
Source: "{#BaseDir}\prerequisites\nmap-7.991-setup.exe"; \
DestDir: "{tmp}"; \
Flags: deleteafterinstall

Source: "{#BaseDir}\prerequisites\npcap-1.88.exe"; \
DestDir: "{tmp}"; \
Flags: deleteafterinstall

Source: "{#BaseDir}\prerequisites\vc_redist.x64.exe"; \
DestDir: "{tmp}"; \
Flags: deleteafterinstall

Source: "{#BaseDir}\prerequisites\vc_redist_x86.exe"; \
DestDir: "{tmp}"; \
Flags: deleteafterinstall

[Registry]

; ================================================================
; CAMT FILE ASSOCIATIONS
; ================================================================
Root: HKA; \
Subkey: "Software\Classes\.camtmodule\OpenWithProgids"; \
ValueType: string; \
ValueName: "CAMT.camtmodule"; \
ValueData: ""; \
Components: associations; \
Flags: uninsdeletevalue

Root: HKA; \
Subkey: "Software\Classes\CAMT.camtmodule"; \
ValueType: string; \
ValueName: ""; \
ValueData: "CAMT Module"; \
Components: associations; \
Flags: uninsdeletekey

Root: HKA; \
Subkey: "Software\Classes\CAMT.camtmodule\DefaultIcon"; \
ValueType: string; \
ValueName: ""; \
ValueData: "{app}\{#MyAppExeName},0"; \
Components: associations

Root: HKA; \
Subkey: "Software\Classes\CAMT.camtmodule\shell\open\command"; \
ValueType: string; \
ValueName: ""; \
ValueData: """{app}\{#MyAppExeName}"" ""%1"""; \
Components: associations

Root: HKA; \
Subkey: "Software\Classes\.camtpack\OpenWithProgids"; \
ValueType: string; \
ValueName: "CAMT.camtpack"; \
ValueData: ""; \
Components: associations; \
Flags: uninsdeletevalue

Root: HKA; \
Subkey: "Software\Classes\CAMT.camtpack"; \
ValueType: string; \
ValueName: ""; \
ValueData: "CAMT Intelligence Pack"; \
Components: associations; \
Flags: uninsdeletekey

Root: HKA; \
Subkey: "Software\Classes\CAMT.camtpack\DefaultIcon"; \
ValueType: string; \
ValueName: ""; \
ValueData: "{app}\{#MyAppExeName},0"; \
Components: associations

Root: HKA; \
Subkey: "Software\Classes\CAMT.camtpack\shell\open\command"; \
ValueType: string; \
ValueName: ""; \
ValueData: """{app}\{#MyAppExeName}"" ""%1"""; \
Components: associations

Root: HKA; \
Subkey: "Software\Classes\.camtprofile\OpenWithProgids"; \
ValueType: string; \
ValueName: "CAMT.camtprofile"; \
ValueData: ""; \
Components: associations; \
Flags: uninsdeletevalue

Root: HKA; \
Subkey: "Software\Classes\CAMT.camtprofile"; \
ValueType: string; \
ValueName: ""; \
ValueData: "CAMT Analysis Profile"; \
Components: associations; \
Flags: uninsdeletekey

Root: HKA; \
Subkey: "Software\Classes\CAMT.camtprofile\DefaultIcon"; \
ValueType: string; \
ValueName: ""; \
ValueData: "{app}\{#MyAppExeName},0"; \
Components: associations

Root: HKA; \
Subkey: "Software\Classes\CAMT.camtprofile\shell\open\command"; \
ValueType: string; \
ValueName: ""; \
ValueData: """{app}\{#MyAppExeName}"" ""%1"""; \
Components: associations

[Icons]
Name: "{autoprograms}\CAMT"; \
Filename: "{app}\{#MyAppExeName}"; \
WorkingDir: "{app}"; \
Components: shortcuts

Name: "{autodesktop}\CAMT"; \
Filename: "{app}\{#MyAppExeName}"; \
WorkingDir: "{app}"; \
Tasks: desktopicon; \
Components: shortcuts

[Run]

; ================================================================
; MICROSOFT VC++ RUNTIMES
; ================================================================
Filename: "{tmp}\vc_redist.x64.exe"; \
Parameters: "/install /quiet /norestart"; \
StatusMsg: "Microsoft Visual C++ Runtime (x64) wordt gecontroleerd/geinstalleerd..."; \
Flags: waituntilterminated; \
Check: not IsVCRedistX64Installed

Filename: "{tmp}\vc_redist.x86.exe"; \
Parameters: "/install /quiet /norestart"; \
StatusMsg: "Microsoft Visual C++ Runtime (x86) wordt gecontroleerd/geinstalleerd..."; \
Flags: waituntilterminated; \
Check: not IsVCRedistX86Installed

; ================================================================
; NPCAP
; ================================================================
Filename: "{tmp}\npcap-1.88.exe"; \
StatusMsg: "Npcap wordt geinstalleerd..."; \
Flags: waituntilterminated; \
Check: not IsNpcapInstalled

; ================================================================
; NMAP
; ================================================================
Filename: "{tmp}\nmap-7.991-setup.exe"; \
StatusMsg: "Nmap wordt geinstalleerd..."; \
Flags: waituntilterminated; \
Check: not IsNmapInstalled

; ================================================================
; POST INSTALL
; ================================================================
Filename: "{app}\{#MyAppExeName}"; \
Description: "{cm:LaunchProgram,CAMT Professional Edition}"; \
WorkingDir: "{app}"; \
Flags: nowait postinstall skipifsilent

Filename: "{app}\docs\QuickStart.pdf"; \
Description: "Open Quick Start Guide"; \
Flags: shellexec postinstall skipifsilent unchecked skipifdoesntexist

[Code]

function UiText(EnglishText, DutchText: String): String;
begin
  if ActiveLanguage = 'dutch' then
    Result := DutchText
  else
    Result := EnglishText;
end;

const
  CAMT_GUID_CURRENT = 'AE34C930-D943-4FB7-B8D4-A4F2F1969A3C';
  CAMT_GUID_LEGACY  = '5C4450B8-9EB2-4C7F-A6A7-110B10000001';

var
  DetectedCAMTDir: String;


function IsNmapInstalled(): Boolean;
begin
  Result :=
    FileExists(ExpandConstant('{pf}\Nmap\nmap.exe')) or
    FileExists(ExpandConstant('{pf32}\Nmap\nmap.exe')) or
    FileExists(ExpandConstant('{localappdata}\Programs\Nmap\nmap.exe'));
end;


function IsNpcapInstalled(): Boolean;
begin
  Result :=
    FileExists(ExpandConstant('{sys}\Npcap\NPFInstall.exe')) or
    FileExists(ExpandConstant('{sys}\Npcap\npcap.cat')) or
    RegKeyExists(HKLM, 'SYSTEM\CurrentControlSet\Services\npcap') or
    RegKeyExists(HKLM, 'SYSTEM\CurrentControlSet\Services\npf');
end;


function IsVCRedistX64Installed(): Boolean;
begin
  Result :=
    RegKeyExists(HKLM64,
      'SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64');
end;


function IsVCRedistX86Installed(): Boolean;
begin
  Result :=
    RegKeyExists(HKLM32,
      'SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x86');
end;


function CheckInstallKey(
  RootKey: Integer;
  const Guid: String;
  var InstallDir: String
): Boolean;
var
  KeyName: String;
  P: String;
begin
  Result := False;

  KeyName :=
    'Software\Microsoft\Windows\CurrentVersion\Uninstall\{' +
    Guid + '}_is1';

  if RegQueryStringValue(RootKey, KeyName, 'InstallLocation', P) then
  begin
    P := RemoveBackslashUnlessRoot(P);

    if FileExists(AddBackslash(P) + '{#MyAppExeName}') then
    begin
      InstallDir := P;
      Result := True;
    end;
  end;
end;


function DetectCAMTInstall(var InstallDir: String): Boolean;
begin
  Result := False;
  InstallDir := '';

  { Current CAMT installer identity, machine installation }
  if CheckInstallKey(HKLM64, CAMT_GUID_CURRENT, InstallDir) then
  begin
    Result := True;
    Exit;
  end;

  { Current CAMT installer identity, per-user installation }
  if CheckInstallKey(HKCU, CAMT_GUID_CURRENT, InstallDir) then
  begin
    Result := True;
    Exit;
  end;

  { Legacy CAMT installer identity }
  if CheckInstallKey(HKLM64, CAMT_GUID_LEGACY, InstallDir) then
  begin
    Result := True;
    Exit;
  end;

  if CheckInstallKey(HKCU, CAMT_GUID_LEGACY, InstallDir) then
  begin
    Result := True;
    Exit;
  end;

  { Fallback checks for known CAMT locations }
  if FileExists(ExpandConstant('{autopf}\CAMT\{#MyAppExeName}')) then
  begin
    InstallDir := ExpandConstant('{autopf}\CAMT');
    Result := True;
    Exit;
  end;

  if FileExists(
       ExpandConstant('{localappdata}\Programs\CAMT\{#MyAppExeName}')
     ) then
  begin
    InstallDir := ExpandConstant('{localappdata}\Programs\CAMT');
    Result := True;
    Exit;
  end;
end;


function CAMTIsRunning(): Boolean;
var
  ResultCode: Integer;
begin
  Result := False;

  if Exec(
       ExpandConstant('{cmd}'),
       '/C tasklist /FI "IMAGENAME eq {#MyAppExeName}" | find /I "{#MyAppExeName}" >nul',
       '',
       SW_HIDE,
       ewWaitUntilTerminated,
       ResultCode
     ) then
  begin
    Result := ResultCode = 0;
  end;
end;


function CloseRunningCAMT(): Boolean;
var
  ResultCode: Integer;
begin
  Result := True;

  if not CAMTIsRunning() then
    Exit;

  if MsgBox(
       'CAMT is currently running.' + #13#10#13#10 +
       'Save any open work before continuing.' + #13#10 +
       'Setup must close CAMT before application files can be replaced.' + #13#10#13#10 +
       'Close CAMT now?',
       mbConfirmation,
       MB_YESNO
     ) <> IDYES then
  begin
    Result := False;
    Exit;
  end;

  if not Exec(
       ExpandConstant('{cmd}'),
       '/C taskkill /F /IM "{#MyAppExeName}"',
       '',
       SW_HIDE,
       ewWaitUntilTerminated,
       ResultCode
     ) then
  begin
    Result := False;
    Exit;
  end;

  Sleep(1000);

  if CAMTIsRunning() then
  begin
    MsgBox(
      'CAMT is still running.' + #13#10#13#10 +
      'Close CAMT manually and then start Setup again.',
      mbError,
      MB_OK
    );
    Result := False;
  end;
end;


function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';

  if not CloseRunningCAMT() then
  begin
    Result :=
      'CAMT must be closed before installation can continue.';
    Exit;
  end;
end;


procedure InitializeWizard();
var
  Choice: Integer;
begin
  DetectedCAMTDir := '';

  MsgBox(
    'CAMT Professional Edition {#MyAppVersion}' + #13#10 +
    'Build {#MyAppBuild}' + #13#10#13#10 +

    UiText('This complete CAMT installation contains the application, documentation, file associations and offline prerequisites.', 'Deze volledige CAMT-installatie bevat de applicatie, documentatie, bestandsassociaties en offline prerequisites.') + #13#10#13#10 +

    UiText('Nmap and Npcap are independent software components and remain subject to their own license and redistribution terms.', 'Nmap en Npcap zijn onafhankelijke softwarecomponenten en blijven onder hun eigen licentie- en redistributievoorwaarden vallen.') +#13#10#13#10 +

    UiText('Use CAMT only for authorized evaluation, development, research, testing and security assessment.', 'Gebruik CAMT uitsluitend voor geautoriseerde evaluatie, ontwikkeling, onderzoek, test- en security-assessmentdoeleinden.'),
    mbInformation,
    MB_OK
  );

  if DetectCAMTInstall(DetectedCAMTDir) then
  begin
    Choice := MsgBox(
      UiText('An existing CAMT installation was found:', 'Een bestaande CAMT-installatie is gevonden:') +  #13#10#13#10 +
      DetectedCAMTDir +  #13#10#13#10 +
      UiText('Install/update CAMT at this location?', 'Wilt u CAMT op deze locatie installeren/bijwerken?') + #13#10#13#10 +
      UiText('Yes = use this existing CAMT folder.', 'Ja  = gebruik deze bestaande CAMT-map.') + #13#10 +
      UiText('No = choose another location on the next screen.', 'Nee = kies op het volgende scherm zelf een andere locatie.'),
      mbConfirmation,
      MB_YESNO
    );

    if Choice = IDYES then
      WizardForm.DirEdit.Text := DetectedCAMTDir
    else
      WizardForm.DirEdit.Text := ExpandConstant('{autopf}\CAMT');
  end;

  WizardForm.Caption :=
    'Setup - CAMT Professional Edition {#MyAppVersion}';
end;
