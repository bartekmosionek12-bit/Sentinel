import type { User } from "oidc-client-ts";
import { createContext, useContext } from "react";

import type { Me } from "@shared/lib/api";

export interface AuthState {
  user: User;
  me: Me | undefined;
  can: (permission: string) => boolean;
  logout: () => Promise<void>;
}

export const AuthContext = createContext<AuthState | null>(null);

export function useAuth(): AuthState {
  const value = useContext(AuthContext);
  if (!value) throw new Error("useAuth poza AuthProvider");
  return value;
}

