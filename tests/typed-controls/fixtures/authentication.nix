{...}: {
  cases = [
    {
      control = ../../../controls/_authentication.nix;
      controlId = "authentication";
      config = {
        compliance.governance.level = "standard";
        compliance.governance.enforceMode = "report";
        compliance.governance.hostType = "server";
        compliance.governance.architecture = "x86_64";
        compliance.governance.primaryFramework = "anssi-bp028";
        compliance.schemaVersions."anssi-bp028" = "anssi-bp028/v1";
        compliance.controls.authentication.enable = true;
      };
    }
  ];
}
