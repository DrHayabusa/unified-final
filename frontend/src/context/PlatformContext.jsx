import { createContext, useContext, useEffect, useState } from "react";

import {
  bootstrapAdministrator,
  fetchCustomers,
  getCurrentSession,
  getSetupStatus,
  login as loginRequest,
  logout as logoutRequest,
} from "../lib/platformApi.jsx";

const PlatformContext = createContext(null);

export function PlatformProvider({ children }) {
  const [state, setState] = useState({ status: "loading", user: null, csrfToken: "", customers: [], error: "" });
  const [selectedCustomerId, setSelectedCustomerId] = useState("");

  const acceptSession = (payload) => {
    const customers = payload.customers ?? [];
    setState({ status: "authenticated", user: payload.user, csrfToken: payload.csrfToken, customers, error: "" });
    setSelectedCustomerId((current) => customers.some((customer) => customer.id === current) ? current : customers[0]?.id ?? "");
  };

  const initialize = async () => {
    setState((current) => ({ ...current, status: "loading", error: "" }));
    try {
      const setup = await getSetupStatus();
      if (setup.setupRequired) {
        setState({ status: "setup", user: null, csrfToken: "", customers: [], error: "" });
        return;
      }
      try {
        acceptSession(await getCurrentSession());
      } catch (error) {
        if (error.status !== 401) throw error;
        setState({ status: "signed-out", user: null, csrfToken: "", customers: [], error: "" });
      }
    } catch (error) {
      setState({ status: "unavailable", user: null, csrfToken: "", customers: [], error: error.message });
    }
  };

  useEffect(() => {
    initialize();
  }, []);

  const bootstrap = async (payload) => acceptSession(await bootstrapAdministrator(payload));
  const login = async (payload) => acceptSession(await loginRequest(payload));

  const logout = async () => {
    try {
      await logoutRequest(state.csrfToken);
    } finally {
      setState({ status: "signed-out", user: null, csrfToken: "", customers: [], error: "" });
      setSelectedCustomerId("");
    }
  };

  const refreshCustomers = async ({ selectCustomerId } = {}) => {
    const payload = await fetchCustomers();
    const customers = payload.customers ?? [];
    setState((current) => ({ ...current, customers }));
    setSelectedCustomerId((current) => {
      const requested = selectCustomerId || current;
      return customers.some((customer) => customer.id === requested) ? requested : customers[0]?.id ?? "";
    });
    return customers;
  };

  const selectedCustomer = state.customers.find((customer) => customer.id === selectedCustomerId) ?? null;

  return (
    <PlatformContext.Provider value={{
      ...state,
      selectedCustomer,
      selectedCustomerId,
      setSelectedCustomerId,
      bootstrap,
      login,
      logout,
      initialize,
      refreshCustomers,
    }}>
      {children}
    </PlatformContext.Provider>
  );
}

export function usePlatform() {
  const context = useContext(PlatformContext);
  if (!context) throw new Error("usePlatform must be used inside PlatformProvider.");
  return context;
}
