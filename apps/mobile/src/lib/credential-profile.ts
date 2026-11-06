import { invoke } from "@tauri-apps/api/core";
import type { CredentialProfile, CredentialProfileApi } from "../../../../src/lib/tauri";

// Only recipe metadata crosses this API; never read/reveal a credential to edit its profile.
export const credentialProfileApi: CredentialProfileApi = {
  get: (id) => invoke<CredentialProfile | null>("credential_profile_get", { id }),
  set: (id, profile) => invoke<CredentialProfile | null>("credential_profile_set", { id, profile }),
  reset: (id) => invoke<CredentialProfile | null>("credential_profile_reset", { id }),
};
