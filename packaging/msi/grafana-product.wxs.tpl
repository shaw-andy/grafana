<?xml version="1.0"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
  <Product Id="*"
    UpgradeCode="${UPGRADE_CODE}"
    Name="${PRODUCT_NAME}"
    Version="${GRAFANA_VERSION}"
    Manufacturer="${MANUFACTURER}"
    Language="1033">
    <Package
      Platform="x64"
      InstallerVersion="500"
      Compressed="yes"
      Comments="Windows Installer Package"/>

    <MediaTemplate EmbedCab="yes" />

    <MajorUpgrade
      DowngradeErrorMessage="A newer version of Grafana is already installed. Uninstall the current version to install this older version. Setup will now exit."/>

    <Icon Id="icon.ico" SourceFile="grafana_icon.ico"/>

    <WixVariable Id="WixUILicenseRtf" Value="${LICENSE}" />
    <WixVariable Id="WixUIBannerBmp" Value="grafana_top_banner_white.bmp" />
    <WixVariable Id="WixUIDialogBmp" Value="grafana_dialog_background.bmp" />

    <Property Id="ARPPRODUCTICON" Value="icon.ico" />
    <Property Id="ARPHELPLINK" Value="https://www.grafana.com" />
    <Property Id="ARPURLINFOABOUT" Value="https://www.grafana.com" />
    <SetProperty Id="ARPINSTALLLOCATION" Value="[ApplicationFolder]"
      After="CostFinalize" />

    <Directory Id="TARGETDIR" Name="SourceDir">
      <Directory Id="ProgramFiles64Folder">
        <Directory Id="INSTALLDIR" Name="GrafanaLabs">
          <Directory Id="GrafanaX64Dir" Name="grafana">
            <Directory Id="GrafanaConfDir" Name="conf" />
            <Directory Id="GrafanaDataDir" Name="data">
              <Directory Id="GrafanaLogDir" Name="log" />
            </Directory>
          </Directory>
          <Directory Id="GrafanaServiceX64Dir" Name="svc-${GRAFANA_VERSION}" />
        </Directory>
      </Directory>
    </Directory>

    <!--
      conf holds secret_key and data holds grafana.db and logs. Without a protected
      DACL they inherit BUILTIN\Users read access from Program Files, and Windows
      ignores the file modes Grafana passes when creating files.
      Sddl on PermissionEx requires InstallerVersion 500.
    -->
    <DirectoryRef Id="GrafanaConfDir">
      <Component Id="GrafanaConfDirAcl" Guid="B2E21335-CA51-452E-91D3-554536A8813F">
        <CreateFolder>
          <PermissionEx Id="GrafanaConfDirSddl" Sddl="D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)" />
        </CreateFolder>
      </Component>
    </DirectoryRef>
    <DirectoryRef Id="GrafanaDataDir">
      <Component Id="GrafanaDataDirAcl" Guid="73EBBCF2-9FC4-44BD-8E5F-40004A2B64D1">
        <CreateFolder>
          <PermissionEx Id="GrafanaDataDirSddl" Sddl="D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)" />
        </CreateFolder>
        <CreateFolder Directory="GrafanaLogDir" />
      </Component>
    </DirectoryRef>
    <ComponentGroup Id="GrafanaRestrictedDirs">
      <ComponentRef Id="GrafanaConfDirAcl" />
      <ComponentRef Id="GrafanaDataDirAcl" />
    </ComponentGroup>

    <!--
      MsiLockPermissionsEx does not propagate to children that already exist, such as
      grafana.db and custom.ini kept from an earlier install. icacls sets the DACL
      through SetNamedSecurityInfo, which re-derives the inherited ACEs of existing
      children. The trailing "." keeps the directory's trailing backslash from
      escaping the closing quote.
    -->
    <SetProperty Id="GrafanaLockConfDir" Sequence="execute" Before="GrafanaLockConfDir"
      Value='"[System64Folder]icacls.exe" "[GrafanaConfDir]." /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F /C /Q' />
    <SetProperty Id="GrafanaLockDataDir" Sequence="execute" Before="GrafanaLockDataDir"
      Value='"[System64Folder]icacls.exe" "[GrafanaDataDir]." /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F /C /Q' />
    <CustomAction Id="GrafanaLockConfDir" BinaryKey="WixCA" DllEntry="WixQuietExec64" Execute="deferred" Impersonate="no" Return="check" />
    <CustomAction Id="GrafanaLockDataDir" BinaryKey="WixCA" DllEntry="WixQuietExec64" Execute="deferred" Impersonate="no" Return="check" />
    <InstallExecuteSequence>
      <Custom Action="GrafanaLockConfDir" After="CreateFolders">NOT REMOVE~="ALL"</Custom>
      <Custom Action="GrafanaLockDataDir" After="GrafanaLockConfDir">NOT REMOVE~="ALL"</Custom>
    </InstallExecuteSequence>

    <Feature Id="DefaultFeature" Title="Grafana" Display="expand" ConfigurableDirectory="INSTALLDIR">
      <Feature Id="${PRODUCT_NAME}" Title="${TITLE}" Level="1">
        <ComponentGroupRef Id="GrafanaX64" />
        <ComponentGroupRef Id="GrafanaRestrictedDirs" />
      </Feature>
      <Feature Id="GrafanaServiceFeature" Title="Run Grafana as a Service" Level="1">
        <ComponentGroupRef Id="GrafanaServiceX64" />
      </Feature>
    </Feature>

    <Property Id="WIXUI_INSTALLDIR" Value="INSTALLDIR" />
    <UIRef Id="WixUI_FeatureTree"/>
  </Product>
</Wix>
