import { useEffect } from "react";

import { api } from "../../services/api";
import { useAuthStore } from "../../store/auth";

export function AuthBootstrap() {
  const initializeAuthentication =
    useAuthStore(
      (state) =>
        state.initializeAuthentication,
    );

  useEffect(() => {
    void initializeAuthentication(
      (token) => api.meWithToken(token),
    );
  }, [
    initializeAuthentication,
  ]);

  return null;
}