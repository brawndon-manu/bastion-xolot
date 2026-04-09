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
  let devices = await api.getDevices();
  return devices;
});

const devicesSlice = createSlice({
  name: "devices",
  initialState,
  reducers: {
    deviceSeen: (state, action) => {
      let device: Device = action.payload;
      let index = state.items.findIndex((x) => x.id === device.id);

      if (index >= 0) 
      {
        state.items[index] = device;
      }
      else
      {
        state.items.unshift(device);
      }
    }
  },
  extraReducers: (builder) => {
    builder.addCase(loadDevices.pending, (state) => {
      state.loading = true;
      state.error = null;
    });
    builder.addCase(loadDevices.fulfilled, (state, action) => {
      state.loading = false;
      state.items = action.payload;
    });
    builder.addCase(loadDevices.rejected, (state, action) => {
      state.loading = false;
      state.error = action.error.message || "Failed to load devices";
    });
  }
});

export const { deviceSeen } = devicesSlice.actions;

export const selectDeviceById = (state: RootState, id: string) =>
{
  return state.devices.items.find((d) => d.id === id);
};

export default devicesSlice.reducer;
