#define MyAppName "CAMT Professional Edition"
#define MyAppVersion "1.2.0 Beta 9"
#define MyAppBuild "120B9-LIC-20260916"
#define MyAppPublisher "CyberFirePulse"
#define MyAppExeName "CAMT.exe"
#define BaseDir "D:\scripts\scan\CAMT_B5_FIX_v3\CAMT_B5_FIX"

; Same long-lived installer identity as the Complete installer.
#define MyAppId "{{AE34C930-D943-4FB7-B8D4-A4F2F1969A3C}"

[Setup]
AppId={#MyAppId}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}

VersionInfoVersion=1.2.0.8
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription=CAMT Professional Edition {#MyAppVersion} Core Update
VersionInfoProductName=CAMT Professional Edition
VersionInfoProductVersion=1.2.0.8

; The detected existing CAMT directory is proposed, but the user can change it.
DefaultDirName={autopf}\CAMT
DefaultGroupName=CAMT
UsePreviousAppDir=yes
DisableDirPage=no
DisableProgramGroupPage=no
DisableReadyPage=no

; Administrator elevation is required when the user selects a protected location
; such as Program Files. There is deliberately no privilege override.
PrivilegesRequired=admin

ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0

; Inno Restart Manager remains enabled, but CAMT is also handled explicitly
; in [Code] so a running CAMT.exe cannot silently block file replacement.
CloseApplications=yes
RestartApplications=no

OutputDir={#BaseDir}\installer
OutputBaseFilename=CAMT_Professional_Edition_1.2.0_Beta9_Setup_core

Compression=lzma2
SolidCompression=yes
WizardStyle=modern

SetupIconFile={#BaseDir}\snoop.ico
WizardImageFile={#BaseDir}\wizard_icon.bmp
WizardSmallImageFile={#BaseDir}\wizard_logo.bmp

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "dutch"; MessagesFile: "compiler:Languages\Dutch.isl"

[CustomMessages]
english.DesktopShortcut=Desktop shortcut
english.ExtraShortcuts=Additional shortcuts:
dutch.DesktopShortcut=Bureaublad-snelkoppeling
dutch.ExtraShortcuts=Extra snelkoppelingen:

[Files]
// Always package the current Beta 9 PyInstaller distribution.
Source: "{#BaseDir}\dist\CAMT\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
// portable.flag is not installed; installed CAMT uses its normal central app-data directory.

[Icons]
Name: "{group}\CAMT"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"
Name: "{autodesktop}\CAMT"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "{cm:DesktopShortcut}"; GroupDescription: "{cm:ExtraShortcuts}"; Flags: unchecked

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,CAMT Professional Edition}"; WorkingDir: "{app}"; Flags: nowait postinstall skipifsilent

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

  // Current installer identity - machine install
  if CheckInstallKey(HKLM64, CAMT_GUID_CURRENT, InstallDir) then
  begin
    Result := True;
    Exit;
  end;

  // Current installer identity - per-user install
  if CheckInstallKey(HKCU, CAMT_GUID_CURRENT, InstallDir) then
  begin
    Result := True;
    Exit;
  end;

  // Older CAMT installer identity - machine install
  if CheckInstallKey(HKLM64, CAMT_GUID_LEGACY, InstallDir) then
  begin
    Result := True;
    Exit;
  end;

  // Older CAMT installer identity - per-user install
  if CheckInstallKey(HKCU, CAMT_GUID_LEGACY, InstallDir) then
  begin
    Result := True;
    Exit;
  end;

  // Fallback: standard administrative installation
  if FileExists(ExpandConstant('{autopf}\CAMT\{#MyAppExeName}')) then
  begin
    InstallDir := ExpandConstant('{autopf}\CAMT');
    Result := True;
    Exit;
  end;

  // Fallback: older per-user installation location
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
       'The Core Update must close CAMT before application files can be replaced.' + #13#10#13#10 +
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
    MsgBox(
      'CAMT could not be closed automatically.' + #13#10#13#10 +
      'Close CAMT manually and run the Core Update again.',
      mbError,
      MB_OK
    );
    Result := False;
    Exit;
  end;

  Sleep(1000);

  if CAMTIsRunning() then
  begin
    MsgBox(
      'CAMT is still running.' + #13#10#13#10 +
      'Close CAMT manually and run the Core Update again.',
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
    Result := 'CAMT must be closed before the Core Update can continue.';
    Exit;
  end;
end;


procedure InitializeWizard();
var
  Choice: Integer;
begin
  DetectedCAMTDir := '';

  WizardForm.Caption :=
    'CAMT Professional Edition {#MyAppVersion} - Core Update';

  if DetectCAMTInstall(DetectedCAMTDir) then
  begin
    Choice := MsgBox(
      UiText('An existing CAMT installation was found:', 'Een bestaande CAMT-installatie is gevonden:') + #13#10#13#10 +
      DetectedCAMTDir + #13#10#13#10 +
      UiText('Install the Core Update at this location?', 'Wilt u de Core Update op deze locatie installeren?') + #13#10#13#10 +
      UiText('Yes = use this existing CAMT folder.', 'Ja  = gebruik deze bestaande CAMT-map.') + #13#10 +
      UiText('No = choose another location on the next screen.', 'Nee = kies op het volgende scherm zelf een andere locatie.'),
      mbConfirmation,
      MB_YESNO
    );

    if Choice = IDYES then
      WizardForm.DirEdit.Text := DetectedCAMTDir
    else
      WizardForm.DirEdit.Text := ExpandConstant('{autopf}\CAMT');
  end
  else
  begin
    MsgBox(
      UiText('No existing CAMT installation was found automatically.', 'Er is geen bestaande CAMT-installatie automatisch gevonden.') + #13#10#13#10 +
      UiText('Choose the CAMT installation folder on the next screen.', 'Kies op het volgende scherm zelf de CAMT-installatiemap.') + #13#10 +
      UiText('The Core Update will not silently redirect to another location.', 'De Core Update zal niets stilzwijgend naar een andere locatie omleiden.'),
      mbInformation,
      MB_OK
    );

    WizardForm.DirEdit.Text := ExpandConstant('{autopf}\CAMT');
  end;
end;