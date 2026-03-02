import { createAsyncThunk, createSlice } from "@reduxjs/toolkit";
import { api, Device } from "../../api/client";
import type { RootState } from "../store";

type DevicesState = {
  items: Device[];
  loading: boolean;
  error: string | null;
};

const initialState: DevicesState = {
  items: [],
  loading: false,
  error: null
};

export const loadDevices = createAsyncThunk("devices/load", async () => {
  return api.getDevices();
});

const devicesSlice = createSlice({
  name: "devices",
  initialState,
  reducers: {
    deviceSeen: (s, a) => {
      const d: Device = a.payload;
      const idx = s.items.findIndex((x) => x.id === d.id);
      if (idx >= 0) s.items[idx] = d;
      else s.items.unshift(d);
    }
  },
  extraReducers: (b) => {
    b.addCase(loadDevices.pending, (s) => {
      s.loading = true;
      s.error = null;
    });
    b.addCase(loadDevices.fulfilled, (s, a) => {
      s.loading = false;
      s.items = a.payload;
    });
    b.addCase(loadDevices.rejected, (s, a) => {
      s.loading = false;
      s.error = a.error.message ?? "Failed to load devices";
    });
  }
});

export const { deviceSeen } = devicesSlice.actions;

export const selectDeviceById = (state: RootState, id: string) =>
  state.devices.items.find((d) => d.id === id);

export default devicesSlice.reducer;
