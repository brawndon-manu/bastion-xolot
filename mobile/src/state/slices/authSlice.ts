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
  let token = await api.getStoredToken();
  return { token: token };
});

export const pairWithGateway = createAsyncThunk("auth/pair", async (pin: string) => {
  let result = await api.pair(pin);
  return result;
});

export const signOut = createAsyncThunk("auth/signOut", async () => {
  await api.clearToken();
  return true;
});

const authSlice = createSlice({
  name: "auth",
  initialState,
  reducers: {},
  extraReducers: (builder) => {
    builder.addCase(bootstrapAuth.fulfilled, (state, action) => {
      state.token = action.payload.token;
      state.isAuthenticated = !!action.payload.token;
    });
    builder.addCase(pairWithGateway.pending, (state) => {
      state.loading = true;
      state.error = null;
    });
    builder.addCase(pairWithGateway.fulfilled, (state, action) => {
      state.loading = false;
      state.token = action.payload.token;
      state.isAuthenticated = true;
    });
    builder.addCase(pairWithGateway.rejected, (state, action) => {
      state.loading = false;
      state.error = action.error.message || "Pairing failed";
    });
    builder.addCase(signOut.fulfilled, (state) => {
      state.token = null;
      state.isAuthenticated = false;
    });
  }
});

export default authSlice.reducer;
