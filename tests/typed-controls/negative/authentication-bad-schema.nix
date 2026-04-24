{evalControl, ...}:
evalControl ../../../controls/_authentication.nix {
  compliance.governance.level = "standard";
  compliance.governance.enforceMode = "report";
  compliance.governance.hostType = "server";
  compliance.governance.architecture = "x86_64";
  compliance.governance.primaryFramework = "anssi-bp028";
  compliance.schemaVersions = {};
  compliance.controls.authentication.enable = true;
}
