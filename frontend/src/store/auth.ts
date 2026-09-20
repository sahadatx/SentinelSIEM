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
  authReady: boolean;
  authInitializing: boolean;

  setAuthentication: (
    accessToken: string,
    user: AuthUser,
  ) => void;

  clearAuthentication: () => void;

  initializeAuthentication: (
    validateToken: (
      accessToken: string,
    ) => Promise<AuthUser>,
  ) => Promise<void>;

  hasPermission: (
    permission: string,
  ) => boolean;

  hasRole: (
    role: string,
  ) => boolean;
}

const TOKEN_KEY = "sentinelsiem.access_token";
const USER_KEY = "sentinelsiem.user";

interface StoredAuthentication {
  accessToken: string | null;
  user: AuthUser | null;
}

function loadInitialState(): StoredAuthentication {
  try {
    const accessToken =
      window.localStorage.getItem(
        TOKEN_KEY,
      );

    const rawUser =
      window.localStorage.getItem(
        USER_KEY,
      );

    const user = rawUser
      ? (JSON.parse(rawUser) as AuthUser)
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

    /*
     * Do not trust cached localStorage state as proof of a
     * valid authenticated session until /auth/me succeeds.
     */
    authenticated: false,

    /*
     * Prevent protected routes from making an authentication
     * decision before the bootstrap check has completed.
     */
    authReady: false,
    authInitializing: false,

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
        authReady: true,
        authInitializing: false,
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
        authReady: true,
        authInitializing: false,
      });
    },

    initializeAuthentication: async (
      validateToken,
    ) => {
      const current = get();

      if (current.authInitializing) {
        return;
      }

      /*
       * No stored token means there is nothing to validate.
       */
      if (!current.accessToken) {
        set({
          authReady: true,
          authenticated: false,
          authInitializing: false,
        });

        return;
      }

      set({
        authInitializing: true,
      });

      try {
        const user = await validateToken(
          current.accessToken,
        );

        /*
         * Keep the backend's current user/session data as
         * the source of truth instead of trusting cached data.
         */
        window.localStorage.setItem(
          USER_KEY,
          JSON.stringify(user),
        );

        set({
          user,
          authenticated: true,
          authReady: true,
          authInitializing: false,
        });
      } catch {
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
          authReady: true,
          authInitializing: false,
        });
      }
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