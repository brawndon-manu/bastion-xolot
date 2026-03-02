import { createAsyncThunk, createSlice } from "@reduxjs/toolkit";
import { api } from "../../api/client";

type AuthState = {
  isAuthenticated: boolean;
  token: string | null;
  loading: boolean;
  error: string | null;
};

const initialState: AuthState = {
  isAuthenticated: false,
  token: null,
  loading: false,
  error: null
};

export const bootstrapAuth = createAsyncThunk("auth/bootstrap", async () => {
  const token = await api.getStoredToken();
  return { token };
});

export const pairWithGateway = createAsyncThunk("auth/pair", async (pin: string) => {
  const res = await api.pair(pin);
  return res;
});

export const signOut = createAsyncThunk("auth/signOut", async () => {
  await api.clearToken();
  return true;
});

const authSlice = createSlice({
  name: "auth",
  initialState,
  reducers: {},
  extraReducers: (b) => {
    b.addCase(bootstrapAuth.fulfilled, (s, a) => {
      s.token = a.payload.token;
      s.isAuthenticated = !!a.payload.token;
    });

    b.addCase(pairWithGateway.pending, (s) => {
      s.loading = true;
      s.error = null;
    });
    b.addCase(pairWithGateway.fulfilled, (s, a) => {
      s.loading = false;
      s.token = a.payload.token;
      s.isAuthenticated = true;
    });
    b.addCase(pairWithGateway.rejected, (s, a) => {
      s.loading = false;
      s.error = (a.error.message ?? "Pairing failed");
    });

    b.addCase(signOut.fulfilled, (s) => {
      s.token = null;
      s.isAuthenticated = false;
    });
  }
});

export default authSlice.reducer;
