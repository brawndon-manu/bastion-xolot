import { createAsyncThunk, createSlice } from "@reduxjs/toolkit";
import { api, Alert } from "../../api/client";
import type { RootState } from "../store";

type AlertsState = {
  items: Alert[];
  loading: boolean;
  error: string | null;
};

const initialState: AlertsState = {
  items: [],
  loading: false,
  error: null
};

export const loadAlerts = createAsyncThunk("alerts/load", async () => {
  let alerts = await api.getAlerts();
  return alerts;
});

/**
 * alert
 */

const alertsSlice = createSlice({
  name: "alerts",
  initialState,
  reducers: {
    alertUpsert: (state, action) => {
      let incoming: Alert = action.payload;
      let index = state.items.findIndex((x) => x.id === incoming.id);

      if (index >= 0)
        {
          state.items[index] = incoming;
        } 
        else 
        {
          state.items.unshift(incoming);
        }
      },
      alertResolved: (state, action) => {
      let incoming: Alert = action.payload;
      let index = state.items.findIndex((x) => x.id === incoming.id);

      if (index >= 0) {
        state.items[index] = incoming;
      } else {
        state.items.unshift(incoming);
      }
    }
  },
  extraReducers: (builder) => {
    builder.addCase(loadAlerts.pending, (state) => {
      state.loading = true;
      state.error = null;
    });
    builder.addCase(loadAlerts.fulfilled, (state, action) => {
      state.loading = false;
      state.items = action.payload;
    });
    builder.addCase(loadAlerts.rejected, (state, action) => {
      state.loading = false;
      state.error = action.error.message || "Failed to load alerts";
    });
  }
});

export const { alertUpsert, alertResolved } = alertsSlice.actions;

export const selectAlertById = (state: RootState, id: string) =>
{
  return state.alerts.items.find((a) => a.id === id);
};

export default alertsSlice.reducer;
