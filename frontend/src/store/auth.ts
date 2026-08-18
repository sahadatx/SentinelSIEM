import { create } from "zustand";

export interface AuthUser {
  user_id: string;
  username: string;
  roles: string[];
  permissions: string[];
  session_id: string;
}

interface AuthState {
  accessToken: string | null;
  user: AuthUser | null;
  authenticated: boolean;

  setAuthentication: (
    accessToken: string,
    user: AuthUser,
  ) => void;

  clearAuthentication: () => void;

  hasPermission: (
    permission: string,
  ) => boolean;

  hasRole: (
    role: string,
  ) => boolean;
}

const TOKEN_KEY = "sentinelsiem.access_token";
const USER_KEY = "sentinelsiem.user";

function loadInitialState(): {
  accessToken: string | null;
  user: AuthUser | null;
} {
  try {
    const accessToken = window.localStorage.getItem(
      TOKEN_KEY,
    );

    const rawUser = window.localStorage.getItem(
      USER_KEY,
    );

    const user = rawUser
      ? JSON.parse(rawUser) as AuthUser
      : null;

    if (!accessToken || !user) {
      return {
        accessToken: null,
        user: null,
      };
    }

    return {
      accessToken,
      user,
    };
  } catch {
    return {
      accessToken: null,
      user: null,
    };
  }
}

const initial = loadInitialState();

export const useAuthStore = create<AuthState>(
  (set, get) => ({
    accessToken: initial.accessToken,
    user: initial.user,
    authenticated:
      Boolean(initial.accessToken && initial.user),

    setAuthentication: (
      accessToken,
      user,
    ) => {
      window.localStorage.setItem(
        TOKEN_KEY,
        accessToken,
      );

      window.localStorage.setItem(
        USER_KEY,
        JSON.stringify(user),
      );

      set({
        accessToken,
        user,
        authenticated: true,
      });
    },

    clearAuthentication: () => {
      window.localStorage.removeItem(
        TOKEN_KEY,
      );

      window.localStorage.removeItem(
        USER_KEY,
      );

      set({
        accessToken: null,
        user: null,
        authenticated: false,
      });
    },

    hasPermission: (
      permission,
    ) => {
      return Boolean(
        get().user?.permissions.includes(
          permission,
        ),
      );
    },

    hasRole: (
      role,
    ) => {
      return Boolean(
        get().user?.roles.includes(role),
      );
    },
  }),
);